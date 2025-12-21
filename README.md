<p align="center">
  <img src="assets/credgoblin-logo.png" alt="Credgoblin Logo" width="350">
</p>

<h1 align="center">Credgoblin</h1>

<p align="center">
  <strong>NTLM Credential Interception & Relay Toolkit</strong><br>
  <em>High-performance Go-based tool for Active Directory security assessments</em>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Documentation</a>
</p>

---

## Overview

Credgoblin is a security assessment tool designed for capturing and relaying NTLM authentication in Active Directory environments. Built entirely in Go for performance and portability, it provides a unified solution for:

- **Hash Capture** — Intercept NTLMv2 credentials from SMB, HTTP, and HTTPS connections
- **LDAP Relay** — Perform Shadow Credentials attacks via `msDS-KeyCredentialLink` modification  
- **ADCS Relay** — Exploit ESC8 misconfiguration through certificate enrollment abuse
- **Cross-Protocol Relay** — Chain SMB→LDAP, SMB→HTTP, and HTTP→LDAP attacks

## Features

| Capability | Description |
|------------|-------------|
| **Multi-Protocol Listeners** | SMB (445), HTTP (80), HTTPS (443) with auto-generated TLS certificates |
| **Hashcat Integration** | Export NTLMv2 hashes in `-m 5600` format |
| **Shadow Credentials** | LDAP/LDAPS relay with KeyCredential injection and PFX export |
| **ADCS ESC8** | Certificate enrollment via web interface relay |
| **CVE-2019-1040** | Drop-the-MIC implementation for cross-protocol attacks |
| **SICILY Protocol** | Native Microsoft LDAP NTLM authentication support |

## Installation

### Prerequisites

- **Go** 1.23 or later
- **Root/Administrator** privileges (required for low ports)
- **Platform** — Linux, macOS, or Windows

### Build from Source

```bash
git clone https://github.com/ineffectivecoder/credgoblin.git
cd credgoblin
go build -o credgoblin ./cmd/credgoblin
```

## Quick Start

### Capture NTLMv2 Hashes

```bash
# Listen on all protocols
sudo ./credgoblin capture -i 0.0.0.0

# HTTPS only (required for WebClient coercion)
sudo ./credgoblin capture -i 0.0.0.0 -p 443 -o hashes.txt
```

### LDAP Relay (Shadow Credentials)

```bash
# Relay to LDAP and inject Shadow Credentials
sudo ./credgoblin relay -t ldap://dc.domain.local \
    -u 'CN=DC01,CN=Computers,DC=domain,DC=local'
```

### ADCS Relay (ESC8)

```bash
# Relay to ADCS web enrollment
sudo ./credgoblin relay -m adcs \
    -t http://ca.domain.local/certsrv \
    -T User
```

## Command Reference

### Capture Mode

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --interface` | Listen address | `0.0.0.0` |
| `-p, --ports` | Ports (`80`, `443`, `445`, `both`, or comma-separated) | `both` |
| `-o, --output` | Output file for hashes | `hashes.txt` |
| `-v, --verbose` | Enable verbose logging | `false` |

### Relay Mode

| Option | Description | Required |
|--------|-------------|----------|
| `-t, --target` | Target URL (`ldap://`, `ldaps://`, `http://`, `https://`) | ✓ |
| `-m, --mode` | Attack mode (`ldap` or `adcs`) | — |
| `-u, --target-user` | Target Distinguished Name | LDAP mode |
| `-T, --template` | Certificate template name | ADCS mode |
| `-o, --output` | Output PFX path | — |
| `-P, --pfx-pass` | PFX password | — |

## Documentation

For detailed attack scenarios, technical implementation details, and protocol documentation, see the [docs](docs/) directory.

### Attack Techniques

- **Shadow Credentials** — Inject `msDS-KeyCredentialLink` for PKINIT-based authentication
- **ESC8** — Abuse misconfigured ADCS web enrollment for certificate issuance
- **WebClient Abuse** — Coerce HTTP authentication via WebDAV service
- **Cross-Protocol Relay** — Bypass signing requirements with CVE-2019-1040

### Known Limitations

| Limitation | Impact |
|------------|--------|
| SMB Signing Required | Relay attacks blocked |
| LDAP Signing Required | Domain controller relay blocked |
| EPA/Channel Binding | Server 2022+ may enforce by default |
| MIC Validation | Patched systems may validate MIC |

## Credits

Inspired by and building upon research from:

- [Impacket](https://github.com/fortra/impacket) — ntlmrelayx reference
- [Responder](https://github.com/lgandx/Responder) — Hash capture techniques
- [PKINITtools](https://github.com/dirkjanm/PKINITtools) — PKINIT authentication
- [Certipy](https://github.com/ly4k/Certipy) — ADCS attack research

## Legal

**For authorized security testing and research only.**

Usage of this tool for attacking systems without prior mutual consent is illegal. The developer assumes no liability for misuse or damages.

---

<p align="center">
  <sub>MIT License • © 2024</sub>
</p>
