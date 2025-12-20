package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ineffectivecoder/credgoblin/pkg/config"
	"github.com/ineffectivecoder/credgoblin/pkg/output"
	"github.com/ineffectivecoder/credgoblin/pkg/smb"
	"github.com/mjwhitta/cli"
)

func runCapture() {
	cfg := config.DefaultCaptureConfig()

	// Configure CLI for capture subcommand
	cli.Banner = "credgoblin capture [OPTIONS]"
	cli.Info(
		"Starts an SMB server that captures NTLM authentication attempts.",
		"Captured hashes are saved in hashcat -m 5600 format.",
	)

	cli.Flag(
		&cfg.ListenAddr,
		"i", "interface",
		cfg.ListenAddr,
		"IP address to listen on.",
	)

	cli.Flag(
		&cfg.OutputFile,
		"o", "output",
		cfg.OutputFile,
		"Output file for captured hashes.",
	)

	cli.Flag(
		&cfg.ServerName,
		"s", "server",
		cfg.ServerName,
		"Server name to advertise.",
	)

	cli.Flag(
		&cfg.DomainName,
		"d", "domain",
		cfg.DomainName,
		"Domain name to advertise.",
	)

	cli.Flag(
		&cfg.Verbose,
		"v", "verbose",
		cfg.Verbose,
		"Enable verbose output.",
	)

	cli.Flag(
		&cfg.ListenPorts,
		"p", "ports",
		cfg.ListenPorts,
		"Ports to listen on: 80 (HTTP), 443 (HTTPS), 445 (SMB), both, or comma-separated (default: both).",
	)

	// Parse flags
	cli.Parse()

	// Create logger
	logger := output.NewLogger(cfg.Verbose)

	// Print banner
	printBanner(logger)

	// Create hash writer
	hashWriter, err := output.NewHashWriter(cfg.OutputFile)
	if err != nil {
		logger.Fatal(fmt.Sprintf("Failed to create hash writer: %v", err))
	}
	defer hashWriter.Close()

	logger.Info(fmt.Sprintf("Writing hashes to: %s", cfg.OutputFile))

	// Check if we have permission to bind to port 445
	if os.Geteuid() != 0 {
		logger.Warning("Not running as root - may fail to bind to port 445")
	}

	// Create SMB server config
	smbConfig := &smb.Config{
		ListenAddr:  cfg.ListenAddr,
		ListenPorts: cfg.ListenPorts,
		ServerName:  cfg.ServerName,
		DomainName:  cfg.DomainName,
		Verbose:     cfg.Verbose,
	}

	// Create SMB server
	server := smb.NewServer(smbConfig, logger, hashWriter)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Shutting down...")
		cancel()
	}()

	// Start server
	if err := server.Start(ctx); err != nil {
		logger.Fatal(fmt.Sprintf("Failed to start server: %v", err))
	}

	logger.Info("Press Ctrl+C to stop")

	// Wait for context cancellation
	<-ctx.Done()

	// Stop server
	if err := server.Stop(); err != nil {
		logger.Error(fmt.Sprintf("Error stopping server: %v", err))
	}

	logger.Info("Server stopped")
}

func printBanner(logger *output.Logger) {
	banner := `
   _____ _____  ______ _____   _____  ____  ____  _      _____ _   _ 
  / ____|  __ \|  ____|  __ \ / ____|/ __ \|  _ \| |    |_   _| \ | |
 | |    | |__) | |__  | |  | | |  __| |  | | |_) | |      | | |  \| |
 | |    |  _  /|  __| | |  | | | |_ | |  | |  _ <| |      | | | . ` + "`" + ` |
 | |____| | \ \| |____| |__| | |__| | |__| | |_) | |____ _| |_| |\  |
  \_____|_|  \_\______|_____/ \_____|\____/|____/|______|_____|_| \_|
                                                                      
                    NTLM Hash Capture & Relay Tool
`
	logger.Print(banner)
}
