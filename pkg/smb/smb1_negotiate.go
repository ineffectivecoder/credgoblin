package smb

import (
	"bytes"
	"encoding/binary"
	"time"
)

// BuildSMB1NegotiateResponse builds an SMB1 NEGOTIATE response with Extended Security
func BuildSMB1NegotiateResponse(reqHeader *SMB1Header, dialectIndex uint16) []byte {
	// Build response header
	header := &SMB1Header{
		Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
		Command:  SMB_COM_NEGOTIATE,
		Status:   STATUS_SUCCESS,
		Flags:    SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED | SMB_FLAGS_REPLY,
		Flags2:   SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_EXTENDED_SECURITY | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE,
		PIDHigh:  reqHeader.PIDHigh,
		TID:      reqHeader.TID,
		PID:      reqHeader.PID,
		UID:      0, // No UID yet
		MID:      reqHeader.MID,
	}

	headerBytes := BuildSMB1Header(header)

	// Build negotiate response parameters
	var params bytes.Buffer

	// WordCount
	params.WriteByte(17)

	// Dialect Index - use the provided index
	binary.Write(&params, binary.LittleEndian, dialectIndex)

	// Security Mode
	params.WriteByte(SECURITY_MODE_USER_LEVEL | SECURITY_MODE_ENCRYPT_PASSWORDS)

	// MaxMpxCount
	binary.Write(&params, binary.LittleEndian, uint16(50))

	// MaxNumberVcs
	binary.Write(&params, binary.LittleEndian, uint16(1))

	// MaxBufferSize
	binary.Write(&params, binary.LittleEndian, uint32(16644))

	// MaxRawSize
	binary.Write(&params, binary.LittleEndian, uint32(65536))

	// SessionKey
	binary.Write(&params, binary.LittleEndian, uint32(0))

	// Capabilities
	capabilities := CAP_UNICODE | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_EXTENDED_SECURITY
	binary.Write(&params, binary.LittleEndian, uint32(capabilities))

	// SystemTime (FILETIME format - 100-nanosecond intervals since 1601)
	systemTime := uint64(time.Now().Unix()+11644473600) * 10000000
	binary.Write(&params, binary.LittleEndian, systemTime)

	// ServerTimeZone (minutes from UTC)
	binary.Write(&params, binary.LittleEndian, int16(0))

	// ChallengeLength (0 for Extended Security)
	params.WriteByte(0)

	// Build data section
	var data bytes.Buffer

	// GUID (16 bytes) - required for Extended Security
	guid := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	}
	data.Write(guid)

	// For Extended Security, no security blob in negotiate response
	// SPNEGO negotiation happens in SESSION_SETUP

	// ByteCount
	byteCount := uint16(data.Len())
	var byteCountBuf bytes.Buffer
	binary.Write(&byteCountBuf, binary.LittleEndian, byteCount)

	// Combine all parts
	response := append(headerBytes, params.Bytes()...)
	response = append(response, byteCountBuf.Bytes()...)
	response = append(response, data.Bytes()...)

	return response
}

// ParseSMB1NegotiateRequest parses an SMB1 negotiate request
// Returns the header and the list of dialects requested
func ParseSMB1NegotiateRequest(data []byte) (*SMB1Header, []string, error) {
	header, err := ParseSMB1Header(data)
	if err != nil {
		return nil, nil, err
	}

	if len(data) < 33 {
		return header, nil, ErrInvalidPacket
	}

	// WordCount
	wordCount := data[32]

	// Skip words (2 bytes each)
	offset := 33 + int(wordCount)*2

	if len(data) < offset+2 {
		return header, nil, ErrInvalidPacket
	}

	// ByteCount
	byteCount := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Parse dialects
	var dialects []string
	end := offset + int(byteCount)

	for offset < end && offset < len(data) {
		// Each dialect starts with 0x02
		if data[offset] != 0x02 {
			break
		}
		offset++

		// Find null terminator
		dialectEnd := offset
		for dialectEnd < end && dialectEnd < len(data) && data[dialectEnd] != 0 {
			dialectEnd++
		}

		if dialectEnd > offset {
			dialects = append(dialects, string(data[offset:dialectEnd]))
		}

		offset = dialectEnd + 1
	}

	return header, dialects, nil
}

// FindBestDialectIndex finds the best dialect index from a list
// Prefers SMB2 dialects like Responder does, falls back to SMB1
func FindBestDialectIndex(dialects []string) uint16 {
	// First, look for SMB2 dialects (Responder prefers these)
	for i, dialect := range dialects {
		if len(dialect) >= 5 && dialect[:5] == "SMB 2" {
			return uint16(i)
		}
	}

	// Fall back to NT LM 0.12
	for i, dialect := range dialects {
		if dialect == "NT LM 0.12" {
			return uint16(i)
		}
	}

	// Fall back to NT LANMAN 1.0
	for i, dialect := range dialects {
		if dialect == "NT LANMAN 1.0" {
			return uint16(i)
		}
	}

	// Return first dialect if no known one found
	if len(dialects) > 0 {
		return 0
	}
	return 0
}
