package relay

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
)

// LDAP GSS-API signing/sealing implementation for NTLM
// This implements RFC 2743 (GSS-API) and MS-NLMP signing

// SetSessionKey sets the NTLM session key for LDAP signing
// The session key must be extracted from the NTLM Type 3 response
func (c *LDAPClient) SetSessionKey(sessionKey []byte) {
	if len(sessionKey) == 0 {
		return
	}

	c.sessionKey = make([]byte, len(sessionKey))
	copy(c.sessionKey, sessionKey)
	c.sendSeqNum = 0
	c.recvSeqNum = 0
	c.signingActive = true

	c.logger.Debug(fmt.Sprintf("LDAP signing enabled with %d-byte session key", len(sessionKey)))
}

// gssWrap wraps an LDAP message with GSS-API signing
// This creates a GSS-API token with NTLM signature
func (c *LDAPClient) gssWrap(message []byte) ([]byte, error) {
	if !c.signingActive || len(c.sessionKey) == 0 {
		return message, nil
	}

	// GSS-API Wrap token format (MS-NLMP):
	// 0-3: Token ID (0x01, 0x00, 0x00, 0x00 for MIC/signature token)
	// 4-7: Signature algorithm (0x11, 0x00, 0x00, 0x00 for HMAC-MD5)
	// 8-11: Seal algorithm (0x00, 0x00, 0x00, 0x00 for no sealing)
	// 12-15: Filler (0xff, 0xff, 0xff, 0xff)
	// 16-23: Encrypted sequence number (8 bytes)
	// 24-31: Checksum (8 bytes)

	sig := make([]byte, 16)

	// Version (4 bytes): 0x01000000
	binary.LittleEndian.PutUint32(sig[0:4], 0x00000001)

	// Compute HMAC-MD5 checksum
	h := hmac.New(md5.New, c.sessionKey)

	// Include sequence number in MAC
	seqBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBytes, c.sendSeqNum)
	h.Write(seqBytes)
	h.Write(message)

	checksum := h.Sum(nil)

	// Take first 8 bytes of checksum
	copy(sig[4:12], checksum[:8])

	// Sequence number (4 bytes)
	binary.LittleEndian.PutUint32(sig[12:16], c.sendSeqNum)

	c.sendSeqNum++

	// Wrap in GSS-API token
	// Total: 4 (OID) + 2 (TOK_ID) + 16 (sig) + message
	result := make([]byte, 0, 22+len(message))

	// GSS-API token header
	result = append(result, 0x60, 0x84) // Application [0]

	// Length (4 bytes, big-endian for BER)
	totalLen := uint32(2 + 16 + len(message))
	result = append(result,
		byte(totalLen>>24),
		byte(totalLen>>16),
		byte(totalLen>>8),
		byte(totalLen))

	// TOK_ID for MIC token (0x0401)
	result = append(result, 0x04, 0x01)

	// Signature
	result = append(result, sig...)

	// Message
	result = append(result, message...)

	return result, nil
}

// gssUnwrap unwraps a GSS-API wrapped LDAP response
func (c *LDAPClient) gssUnwrap(wrapped []byte) ([]byte, error) {
	if !c.signingActive || len(c.sessionKey) == 0 {
		return wrapped, nil
	}

	// Check for GSS-API token header (0x60 0x84)
	if len(wrapped) < 22 || wrapped[0] != 0x60 {
		// Not a GSS-API token, return as-is
		return wrapped, nil
	}

	// Skip header (6 bytes: tag + length indicator + 4-byte length)
	offset := 6

	// Skip TOK_ID (2 bytes)
	offset += 2

	// Extract signature (16 bytes)
	if len(wrapped) < offset+16 {
		return nil, fmt.Errorf("GSS-API token too short")
	}

	sig := wrapped[offset : offset+16]
	offset += 16

	// Extract message
	message := wrapped[offset:]

	// Verify signature
	version := binary.LittleEndian.Uint32(sig[0:4])
	if version != 0x00000001 {
		return nil, fmt.Errorf("invalid GSS-API signature version: 0x%x", version)
	}

	// Extract sequence number
	seqNum := binary.LittleEndian.Uint32(sig[12:16])
	if seqNum != c.recvSeqNum {
		c.logger.Debug(fmt.Sprintf("Sequence number mismatch: expected %d, got %d", c.recvSeqNum, seqNum))
	}

	// Verify checksum
	h := hmac.New(md5.New, c.sessionKey)
	seqBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBytes, seqNum)
	h.Write(seqBytes)
	h.Write(message)
	checksum := h.Sum(nil)

	expectedChecksum := sig[4:12]
	if !hmac.Equal(expectedChecksum, checksum[:8]) {
		return nil, fmt.Errorf("GSS-API signature verification failed")
	}

	c.recvSeqNum++

	return message, nil
}

// RC4K derives a signing key using RC4
func rc4K(key, data []byte) []byte {
	cipher, _ := rc4.NewCipher(key)
	result := make([]byte, len(data))
	cipher.XORKeyStream(result, data)
	return result
}

// extractSessionKeyFromType3 extracts the NTLM session key from Type 3 message
// Note: This only works if we have the password/hash, which we don't in relay scenarios
// In ntlmrelayx, the session key is derived by the python-ldap3 library after authentication
func extractSessionKeyFromType3(type3 []byte) []byte {
	// In a relay scenario, we cannot extract the session key because:
	// 1. Session key = HMAC-MD5(NT hash, NTProofStr)
	// 2. We don't have the NT hash (password)
	// 3. The client already computed the NTLMv2 response using their key

	// For now, return nil - we'll need to handle this differently
	// ntlmrelayx works because python-ldap3 handles SASL internally
	return nil
}
