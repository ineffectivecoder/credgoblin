package shadowcreds

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// ExportPFX exports the private key and certificate to a PFX file
func ExportPFX(privateKey *rsa.PrivateKey, cert *x509.Certificate, password, outputPath string) error {
	// Generate random password if not provided
	if password == "" {
		password = generateRandomPassword(16)
	}

	// Encode to PFX (PKCS#12)
	pfxData, err := pkcs12.Encode(rand.Reader, privateKey, cert, nil, password)
	if err != nil {
		return fmt.Errorf("failed to encode PFX: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, pfxData, 0600); err != nil {
		return fmt.Errorf("failed to write PFX file: %w", err)
	}

	return nil
}

// FormatKeyCredentialLDAP formats the KeyCredential for LDAP
// Format: B:<hex_length>:<hex_data>:<owner_dn>
func FormatKeyCredentialLDAP(blob []byte, ownerDN string) string {
	hexData := fmt.Sprintf("%X", blob)
	hexLen := fmt.Sprintf("%X", len(blob))
	return fmt.Sprintf("B:%s:%s:%s", hexLen, hexData, ownerDN)
}

// generateRandomPassword generates a random password
func generateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp-based
		return base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", length)))[:length]
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
