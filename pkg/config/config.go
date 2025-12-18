package config

// CaptureConfig holds configuration for the capture subcommand
type CaptureConfig struct {
	ListenAddr string
	OutputFile string
	ServerName string
	DomainName string
	Verbose    bool
}

// RelayConfig holds configuration for the relay subcommand
type RelayConfig struct {
	ListenAddr  string
	TargetURL   string
	TargetUser  string
	OutputPath  string
	PFXPassword string
	Verbose     bool
}

// DefaultCaptureConfig returns default capture configuration
func DefaultCaptureConfig() *CaptureConfig {
	return &CaptureConfig{
		ListenAddr: "0.0.0.0",
		OutputFile: "hashes.txt",
		ServerName: "CREDGOBLIN",
		DomainName: "WORKGROUP",
		Verbose:    false,
	}
}

// DefaultRelayConfig returns default relay configuration
func DefaultRelayConfig() *RelayConfig {
	return &RelayConfig{
		ListenAddr: "0.0.0.0",
		Verbose:    false,
	}
}
