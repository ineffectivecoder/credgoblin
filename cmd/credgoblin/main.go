package main

import (
	"fmt"
	"os"
)

const (
	version = "0.1.0"
)

func main() {
	// Check for no arguments or help
	if len(os.Args) == 1 {
		printUsage()
		os.Exit(0)
	}

	// Parse subcommand
	switch os.Args[1] {
	case "capture", "--capture":
		// Remove subcommand from args and run capture
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		runCapture()
	case "relay", "--relay":
		// Remove subcommand from args and run relay
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		runRelay()
	case "-v", "--version", "version":
		fmt.Printf("credgoblin v%s\n", version)
		os.Exit(0)
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	default:
		fmt.Printf("Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("credgoblin v" + version)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  credgoblin capture [options]  # Capture NTLM hashes")
	fmt.Println("  credgoblin relay [options]    # Relay NTLM to LDAP")
	fmt.Println("  credgoblin version            # Show version")
	fmt.Println()
	fmt.Println("Run 'credgoblin capture --help' or 'credgoblin	 relay --help' for subcommand options")
}
