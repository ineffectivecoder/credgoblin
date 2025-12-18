package ntlm

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// AuthParser parses NTLM Type 3 authenticate messages
type AuthMessageParser struct{}

// NewAuthParser creates a new auth message parser
func NewAuthParser() *AuthMessageParser {
	return &AuthMessageParser{}
}

// Parse parses an NTLM Type 3 authenticate message
func (p *AuthMessageParser) Parse(data []byte) (*AuthenticateMessage, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("authenticate message too short: %d bytes", len(data))
	}

	// Check signature
	if !bytes.Equal(data[0:8], ntlmSignature) {
		return nil, fmt.Errorf("invalid NTLM signature")
	}

	// Check message type
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != NtLmAuthenticate {
		return nil, fmt.Errorf("not an authenticate message: type %d", msgType)
	}

	msg := &AuthenticateMessage{
		MessageType: msgType,
	}

	copy(msg.Signature[:], data[0:8])

	// Parse security buffers
	msg.LmChallengeResponse = parseSecurityBuffer(data[12:20])
	msg.NtChallengeResponse = parseSecurityBuffer(data[20:28])
	msg.DomainName = parseSecurityBuffer(data[28:36])
	msg.UserName = parseSecurityBuffer(data[36:44])
	msg.Workstation = parseSecurityBuffer(data[44:52])
	msg.EncryptedRandomSessionKey = parseSecurityBuffer(data[52:60])

	msg.NegotiateFlags = binary.LittleEndian.Uint32(data[60:64])

	// Check for version (optional)
	if len(data) >= 72 {
		copy(msg.Version[:], data[64:72])
	}

	// Check for MIC (optional, typically at offset 72)
	if len(data) >= 88 {
		copy(msg.MIC[:], data[72:88])
	}

	// Store payload (everything after fixed header)
	if len(data) > 88 {
		msg.Payload = data[88:]
	} else if len(data) > 72 {
		msg.Payload = data[72:]
	} else if len(data) > 64 {
		msg.Payload = data[64:]
	}

	// For security buffer payload extraction, we need the full message
	// So we'll store a reference to the original data
	msg.Payload = data

	return msg, nil
}

// parseSecurityBuffer parses a security buffer from 8 bytes
func parseSecurityBuffer(data []byte) SecurityBuffer {
	return SecurityBuffer{
		Length:    binary.LittleEndian.Uint16(data[0:2]),
		MaxLength: binary.LittleEndian.Uint16(data[2:4]),
		Offset:    binary.LittleEndian.Uint32(data[4:8]),
	}
}

// GetDomain extracts the domain name from the authenticate message
func (msg *AuthenticateMessage) GetDomain() string {
	data := ReadSecurityBuffer(msg.Payload, msg.DomainName)
	if data == nil {
		return ""
	}
	return DecodeUTF16LE(data)
}

// GetUserName extracts the username from the authenticate message
func (msg *AuthenticateMessage) GetUserName() string {
	data := ReadSecurityBuffer(msg.Payload, msg.UserName)
	if data == nil {
		return ""
	}
	return DecodeUTF16LE(data)
}

// GetWorkstation extracts the workstation name from the authenticate message
func (msg *AuthenticateMessage) GetWorkstation() string {
	data := ReadSecurityBuffer(msg.Payload, msg.Workstation)
	if data == nil {
		return ""
	}
	return DecodeUTF16LE(data)
}

// GetNTResponse extracts the NT challenge response
func (msg *AuthenticateMessage) GetNTResponse() []byte {
	return ReadSecurityBuffer(msg.Payload, msg.NtChallengeResponse)
}

// GetLMResponse extracts the LM challenge response
func (msg *AuthenticateMessage) GetLMResponse() []byte {
	return ReadSecurityBuffer(msg.Payload, msg.LmChallengeResponse)
}

// GetNTProofStr extracts the NTProofStr (first 16 bytes of NT response)
func (msg *AuthenticateMessage) GetNTProofStr() []byte {
	ntResp := msg.GetNTResponse()
	if len(ntResp) < 16 {
		return nil
	}
	return ntResp[0:16]
}

// GetResponseBlob extracts the response blob (everything after NTProofStr)
func (msg *AuthenticateMessage) GetResponseBlob() []byte {
	ntResp := msg.GetNTResponse()
	if len(ntResp) <= 16 {
		return nil
	}
	return ntResp[16:]
}

// HasMIC checks if the message has a MIC
func (msg *AuthenticateMessage) HasMIC() bool {
	// Check if MIC negotiate flag is set
	if msg.NegotiateFlags&0x00000001 == 0 {
		return false
	}

	// Check if MIC is non-zero
	for _, b := range msg.MIC {
		if b != 0 {
			return true
		}
	}
	return false
}

// StripMIC removes the MIC from the message (for relay scenarios)
func (msg *AuthenticateMessage) StripMIC() {
	for i := range msg.MIC {
		msg.MIC[i] = 0
	}
}

// StripSigningFlags removes signing flags (for LDAP relay)
func (msg *AuthenticateMessage) StripSigningFlags() {
	msg.NegotiateFlags &^= NegotiateSign
	msg.NegotiateFlags &^= NegotiateSeal
	msg.NegotiateFlags &^= NegotiateAlwaysSign
	msg.NegotiateFlags &^= NegotiateKeyExchange
}
