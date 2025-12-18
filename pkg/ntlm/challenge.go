package ntlm

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// Challenge represents an NTLM challenge generator
type Challenge struct {
	ServerName    string
	DomainName    string
	DNSServerName string
	DNSDomainName string
}

// NewChallenge creates a new challenge generator
func NewChallenge(serverName, domainName string) *Challenge {
	return &Challenge{
		ServerName:    serverName,
		DomainName:    domainName,
		DNSServerName: serverName,
		DNSDomainName: domainName,
	}
}

// Generate creates a new NTLM Type 2 challenge message
func (c *Challenge) Generate() *ChallengeMessage {
	// Generate random 8-byte server challenge
	serverChallenge := make([]byte, 8)
	rand.Read(serverChallenge)

	// Build target info
	targetInfo := c.buildTargetInfo()

	// Target name (domain in UTF-16LE)
	targetName := EncodeUTF16LE(c.DomainName)

	// Build payload
	payload := append(targetName, targetInfo...)

	msg := &ChallengeMessage{
		MessageType: NtLmChallenge,
		NegotiateFlags: NegotiateUnicode |
			NegotiateNTLM |
			RequestTarget |
			NegotiateTargetInfo |
			NegotiateExtendedSessionSecurity |
			TargetTypeDomain |
			Negotiate128 |
			Negotiate56,
		TargetNameLen:    uint16(len(targetName)),
		TargetNameMaxLen: uint16(len(targetName)),
		TargetNameOffset: 56, // After fixed header
		TargetInfoLen:    uint16(len(targetInfo)),
		TargetInfoMaxLen: uint16(len(targetInfo)),
		TargetInfoOffset: 56 + uint32(len(targetName)),
		Payload:          payload,
	}

	copy(msg.Signature[:], ntlmSignature)
	copy(msg.ServerChallenge[:], serverChallenge)

	return msg
}

// buildTargetInfo constructs the target info AVPair list
func (c *Challenge) buildTargetInfo() []byte {
	var result []byte

	// Add NetBIOS domain name
	if c.DomainName != "" {
		result = append(result, encodeAVPair(MsvAvNbDomainName, EncodeUTF16LE(c.DomainName))...)
	}

	// Add NetBIOS computer name
	if c.ServerName != "" {
		result = append(result, encodeAVPair(MsvAvNbComputerName, EncodeUTF16LE(c.ServerName))...)
	}

	// Add DNS domain name
	if c.DNSDomainName != "" {
		result = append(result, encodeAVPair(MsvAvDnsDomainName, EncodeUTF16LE(c.DNSDomainName))...)
	}

	// Add DNS computer name
	if c.DNSServerName != "" {
		result = append(result, encodeAVPair(MsvAvDnsComputerName, EncodeUTF16LE(c.DNSServerName))...)
	}

	// Add timestamp
	timestamp := uint64(time.Now().Unix()+11644473600) * 10000000
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, timestamp)
	result = append(result, encodeAVPair(MsvAvTimestamp, timestampBytes)...)

	// Add EOL
	result = append(result, encodeAVPair(MsvAvEOL, nil)...)

	return result
}

// encodeAVPair encodes an AVPair
func encodeAVPair(avID uint16, value []byte) []byte {
	result := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint16(result[0:2], avID)
	binary.LittleEndian.PutUint16(result[2:4], uint16(len(value)))
	copy(result[4:], value)
	return result
}

// Bytes serializes the challenge message to bytes
func (c *ChallengeMessage) Bytes() []byte {
	size := 56 + len(c.Payload)
	result := make([]byte, size)

	copy(result[0:8], c.Signature[:])
	binary.LittleEndian.PutUint32(result[8:12], c.MessageType)
	binary.LittleEndian.PutUint16(result[12:14], c.TargetNameLen)
	binary.LittleEndian.PutUint16(result[14:16], c.TargetNameMaxLen)
	binary.LittleEndian.PutUint32(result[16:20], c.TargetNameOffset)
	binary.LittleEndian.PutUint32(result[20:24], c.NegotiateFlags)
	copy(result[24:32], c.ServerChallenge[:])
	copy(result[32:40], c.Reserved[:])
	binary.LittleEndian.PutUint16(result[40:42], c.TargetInfoLen)
	binary.LittleEndian.PutUint16(result[42:44], c.TargetInfoMaxLen)
	binary.LittleEndian.PutUint32(result[44:48], c.TargetInfoOffset)
	copy(result[48:56], c.Version[:])
	copy(result[56:], c.Payload)

	return result
}

// GetServerChallenge returns the server challenge bytes
func (c *ChallengeMessage) GetServerChallenge() []byte {
	result := make([]byte, 8)
	copy(result, c.ServerChallenge[:])
	return result
}
