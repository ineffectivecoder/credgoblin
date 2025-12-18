package ntlm

import (
	"encoding/binary"
)

// NTLM Message Types
const (
	NtLmNegotiate    uint32 = 0x00000001
	NtLmChallenge    uint32 = 0x00000002
	NtLmAuthenticate uint32 = 0x00000003
)

// NTLM Negotiate Flags
const (
	NegotiateUnicode                 uint32 = 0x00000001
	NegotiateOEM                     uint32 = 0x00000002
	RequestTarget                    uint32 = 0x00000004
	NegotiateSign                    uint32 = 0x00000010
	NegotiateSeal                    uint32 = 0x00000020
	NegotiateDatagram                uint32 = 0x00000040
	NegotiateLMKey                   uint32 = 0x00000080
	NegotiateNTLM                    uint32 = 0x00000200
	NegotiateAnonymous               uint32 = 0x00000800
	NegotiateDomainSupplied          uint32 = 0x00001000
	NegotiateWorkstationSupplied     uint32 = 0x00002000
	NegotiateAlwaysSign              uint32 = 0x00008000
	TargetTypeDomain                 uint32 = 0x00010000
	TargetTypeServer                 uint32 = 0x00020000
	NegotiateExtendedSessionSecurity uint32 = 0x00080000
	NegotiateIdentify                uint32 = 0x00100000
	NegotiateTargetInfo              uint32 = 0x00800000
	NegotiateVersion                 uint32 = 0x02000000
	Negotiate128                     uint32 = 0x20000000
	NegotiateKeyExchange             uint32 = 0x40000000
	Negotiate56                      uint32 = 0x80000000
)

// TargetInfo AVPair types
const (
	MsvAvEOL             uint16 = 0x0000
	MsvAvNbComputerName  uint16 = 0x0001
	MsvAvNbDomainName    uint16 = 0x0002
	MsvAvDnsComputerName uint16 = 0x0003
	MsvAvDnsDomainName   uint16 = 0x0004
	MsvAvDnsTreeName     uint16 = 0x0005
	MsvAvFlags           uint16 = 0x0006
	MsvAvTimestamp       uint16 = 0x0007
	MsvAvSingleHost      uint16 = 0x0008
	MsvAvTargetName      uint16 = 0x0009
	MsvAvChannelBindings uint16 = 0x000A
)

// NTLM message signature
var ntlmSignature = []byte("NTLMSSP\x00")

// NegotiateMessage represents an NTLM Type 1 message
type NegotiateMessage struct {
	Signature         [8]byte
	MessageType       uint32
	NegotiateFlags    uint32
	DomainNameLen     uint16
	DomainNameMaxLen  uint16
	DomainNameOffset  uint32
	WorkstationLen    uint16
	WorkstationMaxLen uint16
	WorkstationOffset uint32
	Version           [8]byte
	Payload           []byte
}

// ChallengeMessage represents an NTLM Type 2 message
type ChallengeMessage struct {
	Signature        [8]byte
	MessageType      uint32
	TargetNameLen    uint16
	TargetNameMaxLen uint16
	TargetNameOffset uint32
	NegotiateFlags   uint32
	ServerChallenge  [8]byte
	Reserved         [8]byte
	TargetInfoLen    uint16
	TargetInfoMaxLen uint16
	TargetInfoOffset uint32
	Version          [8]byte
	Payload          []byte
}

// AuthenticateMessage represents an NTLM Type 3 message
type AuthenticateMessage struct {
	Signature                 [8]byte
	MessageType               uint32
	LmChallengeResponse       SecurityBuffer
	NtChallengeResponse       SecurityBuffer
	DomainName                SecurityBuffer
	UserName                  SecurityBuffer
	Workstation               SecurityBuffer
	EncryptedRandomSessionKey SecurityBuffer
	NegotiateFlags            uint32
	Version                   [8]byte
	MIC                       [16]byte
	Payload                   []byte
}

// SecurityBuffer represents an NTLM security buffer
type SecurityBuffer struct {
	Length    uint16
	MaxLength uint16
	Offset    uint32
}

// AVPair represents a target info AVPair
type AVPair struct {
	AvID  uint16
	AvLen uint16
	Value []byte
}

// ChallengeGenerator interface for generating NTLM challenges
type ChallengeGenerator interface {
	Generate() *ChallengeMessage
}

// AuthParser interface for parsing NTLM authenticate messages
type AuthParser interface {
	Parse(data []byte) (*AuthenticateMessage, error)
}

// HashFormatter interface for formatting hashes
type HashFormatter interface {
	FormatHashcat(challenge []byte, auth *AuthenticateMessage) string
}

// ReadSecurityBuffer reads a security buffer's data from the payload
func ReadSecurityBuffer(payload []byte, buf SecurityBuffer) []byte {
	if buf.Offset >= uint32(len(payload)) {
		return nil
	}
	end := buf.Offset + uint32(buf.Length)
	if end > uint32(len(payload)) {
		return nil
	}
	return payload[buf.Offset:end]
}

// WriteSecurityBuffer writes a security buffer header
func WriteSecurityBuffer(length uint16, offset uint32) SecurityBuffer {
	return SecurityBuffer{
		Length:    length,
		MaxLength: length,
		Offset:    offset,
	}
}

// EncodeUTF16LE encodes a string to UTF-16 Little Endian
func EncodeUTF16LE(s string) []byte {
	runes := []rune(s)
	result := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(result[i*2:], uint16(r))
	}
	return result
}

// DecodeUTF16LE decodes UTF-16 Little Endian to a string
func DecodeUTF16LE(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	runes := make([]rune, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		runes[i/2] = rune(binary.LittleEndian.Uint16(data[i:]))
	}
	return string(runes)
}
