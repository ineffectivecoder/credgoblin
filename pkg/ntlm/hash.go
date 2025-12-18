package ntlm

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// HashcatFormatter formats NTLM hashes for hashcat mode 5600 (NetNTLMv2)
type HashcatFormatter struct{}

// NewHashcatFormatter creates a new hashcat formatter
func NewHashcatFormatter() *HashcatFormatter {
	return &HashcatFormatter{}
}

// FormatHashcat formats an NTLM authenticate message into hashcat -m 5600 format
// Format: username::domain:serverchallenge:NTProofStr:blob
func (f *HashcatFormatter) FormatHashcat(serverChallenge []byte, auth *AuthenticateMessage) string {
	username := auth.GetUserName()
	domain := auth.GetDomain()
	ntProofStr := auth.GetNTProofStr()
	blob := auth.GetResponseBlob()

	if len(serverChallenge) != 8 {
		return ""
	}

	if len(ntProofStr) != 16 {
		return ""
	}

	if len(blob) == 0 {
		return ""
	}

	// Clean username and domain (remove any colons)
	username = strings.ReplaceAll(username, ":", "")
	domain = strings.ReplaceAll(domain, ":", "")

	// Build hashcat format
	return fmt.Sprintf("%s::%s:%s:%s:%s",
		username,
		domain,
		hex.EncodeToString(serverChallenge),
		hex.EncodeToString(ntProofStr),
		hex.EncodeToString(blob),
	)
}

// FormatHashcatFromChallenge is a convenience method that takes a ChallengeMessage
func (f *HashcatFormatter) FormatHashcatFromChallenge(challenge *ChallengeMessage, auth *AuthenticateMessage) string {
	return f.FormatHashcat(challenge.GetServerChallenge(), auth)
}

// ValidateHash validates that a hash is in correct hashcat format
func (f *HashcatFormatter) ValidateHash(hash string) error {
	parts := strings.Split(hash, ":")
	if len(parts) != 6 {
		return fmt.Errorf("invalid hash format: expected 6 parts, got %d", len(parts))
	}

	// Validate username (part 0) - can be empty
	if parts[0] == "" {
		return fmt.Errorf("username cannot be empty")
	}

	// Part 1 should be empty (legacy field)
	if parts[1] != "" {
		return fmt.Errorf("part 2 should be empty")
	}

	// Validate domain (part 2) - can be empty

	// Validate server challenge (part 3) - should be 16 hex chars (8 bytes)
	if len(parts[3]) != 16 {
		return fmt.Errorf("server challenge should be 16 hex chars, got %d", len(parts[3]))
	}
	if _, err := hex.DecodeString(parts[3]); err != nil {
		return fmt.Errorf("server challenge is not valid hex: %v", err)
	}

	// Validate NTProofStr (part 4) - should be 32 hex chars (16 bytes)
	if len(parts[4]) != 32 {
		return fmt.Errorf("NTProofStr should be 32 hex chars, got %d", len(parts[4]))
	}
	if _, err := hex.DecodeString(parts[4]); err != nil {
		return fmt.Errorf("NTProofStr is not valid hex: %v", err)
	}

	// Validate blob (part 5) - should be valid hex and non-empty
	if len(parts[5]) == 0 {
		return fmt.Errorf("blob cannot be empty")
	}
	if len(parts[5])%2 != 0 {
		return fmt.Errorf("blob should have even number of hex chars")
	}
	if _, err := hex.DecodeString(parts[5]); err != nil {
		return fmt.Errorf("blob is not valid hex: %v", err)
	}

	return nil
}
