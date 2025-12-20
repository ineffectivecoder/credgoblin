package config

// CaptureConfig holds configuration for the capture subcommand
type CaptureConfig struct {
	ListenAddr  string
	ListenPorts string // "80", "445", or "both"
	OutputFile  string
	ServerName  string
	DomainName  string
	Verbose     bool
}

// RelayConfig holds configuration for the relay subcommand
type RelayConfig struct {
	ListenAddr   string
	ListenPorts  string // "80", "445", or "both"
	TargetURL    string
	TargetUser   string
	OutputPath   string
	PFXPassword  string
	Verbose      bool
	RelayMode    string // "ldap" or "adcs"
	TemplateName string // Certificate template name for ADCS
}

// DefaultCaptureConfig returns default capture configuration
func DefaultCaptureConfig() *CaptureConfig {
	return &CaptureConfig{
		ListenAddr:  "0.0.0.0",
		ListenPorts: "both",
		OutputFile:  "hashes.txt",
		ServerName:  "CREDGOBLIN",
		DomainName:  "WORKGROUP",
		Verbose:     false,
	}
}

// DefaultRelayConfig returns default relay configuration
func DefaultRelayConfig() *RelayConfig {
	return &RelayConfig{
		ListenAddr:  "0.0.0.0",
		ListenPorts: "both",
		Verbose:     false,
		RelayMode:   "ldap",
	}
}
