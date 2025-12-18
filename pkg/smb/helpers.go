package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// ParseSMB2Header parses an SMB2 header from packet data
func ParseSMB2Header(data []byte) (*SMB2Header, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("packet too short for SMB2 header")
	}

	header := &SMB2Header{}
	copy(header.ProtocolID[:], data[0:4])
	header.StructureSize = binary.LittleEndian.Uint16(data[4:6])
	header.CreditCharge = binary.LittleEndian.Uint16(data[6:8])
	header.Status = binary.LittleEndian.Uint32(data[8:12])
	header.Command = binary.LittleEndian.Uint16(data[12:14])
	header.CreditReqResp = binary.LittleEndian.Uint16(data[14:16])
	header.Flags = binary.LittleEndian.Uint32(data[16:20])
	header.NextCommand = binary.LittleEndian.Uint32(data[20:24])
	header.MessageID = binary.LittleEndian.Uint64(data[24:32])
	header.Reserved = binary.LittleEndian.Uint32(data[32:36])
	header.TreeID = binary.LittleEndian.Uint32(data[36:40])
	header.SessionID = binary.LittleEndian.Uint64(data[40:48])

	return header, nil
}

// BuildNegotiateResponse builds an SMB2 NEGOTIATE response
func BuildNegotiateResponse(req *SMB2Header) []byte {
	response := make([]byte, 128)

	// SMB2 Header
	copy(response[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(response[4:6], 64)
	binary.LittleEndian.PutUint16(response[6:8], 0)
	binary.LittleEndian.PutUint32(response[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(response[12:14], SMB2_NEGOTIATE)
	binary.LittleEndian.PutUint16(response[14:16], 0)
	binary.LittleEndian.PutUint32(response[16:20], 0x00000001)
	binary.LittleEndian.PutUint32(response[20:24], 0)
	binary.LittleEndian.PutUint64(response[24:32], req.MessageID)
	binary.LittleEndian.PutUint32(response[32:36], 0)
	binary.LittleEndian.PutUint32(response[36:40], 0)
	binary.LittleEndian.PutUint64(response[40:48], 0)

	// Negotiate response body
	binary.LittleEndian.PutUint16(response[64:66], 65)
	binary.LittleEndian.PutUint16(response[66:68], 0)
	binary.LittleEndian.PutUint16(response[68:70], 0x0311)
	binary.LittleEndian.PutUint16(response[70:72], 0)
	copy(response[72:88], make([]byte, 16))
	binary.LittleEndian.PutUint32(response[88:92], 0x00000001)
	binary.LittleEndian.PutUint32(response[92:96], 8192)
	binary.LittleEndian.PutUint32(response[96:100], 8192)
	binary.LittleEndian.PutUint32(response[100:104], 0)
	binary.LittleEndian.PutUint16(response[108:110], 128)
	binary.LittleEndian.PutUint16(response[110:112], 0)

	return response
}

// BuildSessionSetupResponse builds an SMB2 SESSION_SETUP response
func BuildSessionSetupResponse(req *SMB2Header, status uint32, sessionID uint64, securityBlob []byte) []byte {
	headerSize := 64
	bodySize := 9
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
	binary.LittleEndian.PutUint16(response[offset:offset+2], 9)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(headerSize+bodySize))
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(len(securityBlob)))
	offset += 2
	response[offset] = 0
	offset += 1

	copy(response[offset:], securityBlob)

	return response
}

// UnwrapSPNEGO extracts NTLM message from SPNEGO wrapper
func UnwrapSPNEGO(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty SPNEGO blob")
	}

	ntlmSig := []byte("NTLMSSP\x00")
	if len(data) >= 8 && bytes.Equal(data[0:8], ntlmSig) {
		return data, nil
	}

	idx := bytes.Index(data, ntlmSig)
	if idx != -1 {
		return data[idx:], nil
	}

	if data[0] == 0x60 || data[0] == 0xa0 || data[0] == 0xa1 {
		return nil, fmt.Errorf("SPNEGO contains non-NTLM mechanism")
	}

	return nil, fmt.Errorf("NTLM message not found in SPNEGO blob")
}

// WrapNTLMInSPNEGO wraps an NTLM message in SPNEGO
func WrapNTLMInSPNEGO(ntlmMsg []byte, isChallenge bool) []byte {
	if isChallenge {
		ntlmsspOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

		negResult := []byte{0xa0, 0x03, 0x0a, 0x01, 0x01}

		supportedMech := append([]byte{0xa1}, encodeDERLength(len(ntlmsspOID))...)
		supportedMech = append(supportedMech, ntlmsspOID...)

		octetString := append([]byte{0x04}, encodeDERLength(len(ntlmMsg))...)
		octetString = append(octetString, ntlmMsg...)
		responseToken := append([]byte{0xa2}, encodeDERLength(len(octetString))...)
		responseToken = append(responseToken, octetString...)

		sequenceContent := append(negResult, supportedMech...)
		sequenceContent = append(sequenceContent, responseToken...)
		sequence := append([]byte{0x30}, encodeDERLength(len(sequenceContent))...)
		sequence = append(sequence, sequenceContent...)

		negTokenTarg := append([]byte{0xa1}, encodeDERLength(len(sequence))...)
		negTokenTarg = append(negTokenTarg, sequence...)

		return negTokenTarg
	}

	return ntlmMsg
}

// encodeDERLength encodes a length in DER format
func encodeDERLength(length int) []byte {
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
