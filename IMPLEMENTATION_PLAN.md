# Credgremlin Implementation Plan

A Go-based NTLM hash capture and relay tool (Responder + ntlmrelayx functionality).

## Overview

| Aspect | Decision |
|--------|----------|
| **Phase 1** | SMB hash capture (port 445 only) |
| **Phase 2** | LDAP relay for shadow credentials |
| **Architecture** | Library-first with thin CLI wrapper |
| **CLI Library** | github.com/mjwhitta/cli |
| **Module Path** | github.com/ineffectivecoder/credgremlin |
| **Hash Format** | Hashcat only (`-m 5600`) |
| **Cert Export** | PFX only |
| **Poisoning** | Not in scope (SMB server only) |

---

## Directory Structure

```
credgremlin/
├── go.mod
├── go.sum
├── README.md
├── assets/
│   └── credgremlin-logo.png
├── cmd/
│   └── credgremlin/
│       ├── main.go           # CLI entry point, subcommand routing
│       ├── capture.go        # capture subcommand
│       └── relay.go          # relay subcommand
├── pkg/
│   ├── ntlm/
│   │   ├── ntlm.go           # NTLM constants, types, message structures
│   │   ├── challenge.go      # Challenge generation/parsing
│   │   ├── hash.go           # Hash extraction (hashcat -m 5600 format)
│   │   └── auth.go           # Authenticate message parsing
│   ├── smb/
│   │   ├── server.go         # SMB2 server, TCP listener (port 445)
│   │   ├── handler.go        # SMB command handlers
│   │   ├── negotiate.go      # SMB2_NEGOTIATE handling
│   │   └── session.go        # SMB2_SESSION_SETUP with NTLM
│   ├── relay/
│   │   ├── relay.go          # Relay coordinator
│   │   ├── ldap.go           # LDAP client with NTLM bind
│   │   └── forwarder.go      # NTLM message forwarding
│   ├── shadowcreds/
│   │   ├── keycredential.go  # KeyCredential binary structure
│   │   ├── certificate.go    # RSA key + X509 cert generation
│   │   └── export.go         # PFX (PKCS#12) export
│   ├── output/
│   │   ├── logger.go         # Structured logging
│   │   └── hashwriter.go     # Hash file output
│   └── config/
│       └── config.go         # Configuration types
└── internal/
    └── version/
        └── version.go
```

---

## Dependencies

```go
// go.mod
module github.com/ineffectivecoder/credgremlin

go 1.21

require (
    github.com/go-ldap/ldap/v3 v3.4.6    // LDAP client operations
    github.com/mjwhitta/cli v1.12.5      // CLI flag parsing
    software.sslmate.com/src/go-pkcs12 v0.4.0  // PFX export
)
```

---

## Phase 1: SMB Hash Capture

### Files to Create (in order)

1. **go.mod** - Initialize module
2. **pkg/ntlm/ntlm.go** - NTLM message types, constants, flags
3. **pkg/ntlm/challenge.go** - Generate Type 2 challenge
4. **pkg/ntlm/auth.go** - Parse Type 3, extract user/domain/responses
5. **pkg/ntlm/hash.go** - Format NetNTLMv2 for hashcat
6. **pkg/smb/server.go** - TCP listener on 445, connection mgmt
7. **pkg/smb/negotiate.go** - SMB2_NEGOTIATE response with NTLM
8. **pkg/smb/session.go** - SMB2_SESSION_SETUP, SPNEGO unwrap
9. **pkg/smb/handler.go** - Route SMB commands
10. **pkg/output/logger.go** - Timestamped logging
11. **pkg/output/hashwriter.go** - Append hashes to file
12. **pkg/config/config.go** - Config structs
13. **cmd/credgremlin/main.go** - CLI with mjwhitta/cli
14. **cmd/credgremlin/capture.go** - Capture subcommand

### Hashcat Format (-m 5600)

```
username::domain:serverchallenge:NTProofStr:blob
```

Where:
- `serverchallenge` = 8 bytes hex (16 chars)
- `NTProofStr` = first 16 bytes of NTResponse (32 hex chars)
- `blob` = remaining NTResponse bytes

### NTLM Capture Flow

```
Victim                    Credgremlin (port 445)
  |-- SMB2 NEGOTIATE ------->|
  |<-- NEGOTIATE (NTLM) -----|
  |-- SESSION_SETUP (Type1)->|  Generate random 8-byte challenge
  |<-- SESSION_SETUP (Type2)-|  Return challenge in SPNEGO
  |-- SESSION_SETUP (Type3)->|  Extract hash, write to file
  |<-- ACCESS_DENIED --------|
```

---

## Phase 2: LDAP Relay + Shadow Credentials

### Files to Create (in order)

15. **pkg/relay/relay.go** - Relay coordinator
16. **pkg/relay/ldap.go** - LDAP SICILY NTLM bind
17. **pkg/relay/forwarder.go** - NTLM forwarding logic
18. **pkg/shadowcreds/certificate.go** - RSA 2048 + self-signed X509
19. **pkg/shadowcreds/keycredential.go** - msDS-KeyCredentialLink builder
20. **pkg/shadowcreds/export.go** - PFX export for Rubeus
21. **cmd/credgremlin/relay.go** - Relay subcommand

### NTLM Relay Flow

```
Victim          Credgremlin           DC (LDAP)
  |-- Type 1 ------>|                    |
  |                 |-- SICILY Type1 --->|
  |                 |<-- Type 2 ---------|
  |<-- Type 2 ------|                    |
  |-- Type 3 ------>|                    |
  |                 |-- SICILY Type3 --->|
  |                 |<-- BIND SUCCESS ---|
  |                 |-- LDAP Modify ---->|  (msDS-KeyCredentialLink)
  |                 |<-- SUCCESS --------|
  |<-- SUCCESS -----|  [Output PFX]      |
```

### KeyCredential Binary Structure

```
Version (4 bytes): 0x00000200
Properties (variable):
  [Length:2][Type:1][Value:N]

  Type 0x01: KeyID (SHA256 of public key)
  Type 0x02: KeyHash (SHA256 of properties)
  Type 0x03: RawKeyMaterial (BCRYPT_RSAKEY_BLOB)
  Type 0x04: Usage (0x01 = NGC)
  Type 0x05: Source (0x00 = AD)
  Type 0x06: DeviceId (16-byte GUID)
  Type 0x07: CustomKeyInfo
  Type 0x08: LastLogonTime (FILETIME)
  Type 0x09: CreationTime (FILETIME)

LDAP Value Format: B:<hex_length>:<hex_data>:<owner_dn>
```

---

## CLI Design

```
credgremlin capture [OPTIONS]
  -i, --interface   IP to listen on (default: 0.0.0.0)
  -o, --output      Hash output file (default: hashes.txt)
  -v, --verbose     Verbose output

credgremlin relay [OPTIONS]
  -t, --target      Target LDAP URL (ldap://dc.domain.local)
  -u, --target-user User/computer DN to modify
  -o, --output      Output path for PFX file
  -P, --pfx-pass    PFX password (random if not set)
  -v, --verbose     Verbose output
```

---

## Key Interfaces

```go
// pkg/ntlm/ntlm.go
type ChallengeGenerator interface {
    Generate() *Challenge
}

type AuthParser interface {
    Parse(data []byte) (*AuthMessage, error)
}

type HashFormatter interface {
    FormatHashcat(challenge []byte, auth *AuthMessage) string
}

// pkg/smb/server.go
type Server interface {
    Start(ctx context.Context) error
    Stop() error
    OnHashCaptured(func(hash string))
}

// pkg/relay/relay.go
type RelayClient interface {
    Connect(target string) error
    ForwardNegotiate(type1 []byte) ([]byte, error)
    ForwardAuth(type3 []byte) error
    Session() LDAPSession
}

// pkg/shadowcreds/keycredential.go
type KeyCredentialBuilder interface {
    Build() ([]byte, error)
    ExportPFX(password string) ([]byte, error)
}
```

---

## Implementation Notes

- **Port 445 requires root/sudo** - document this requirement
- **Strip MIC** from Type 3 for cross-protocol relay (SMB→LDAP)
- **Strip signing flags** from Type 1 for LDAP relay compatibility
- **LDAP SICILY bind** requires custom bind request construction
- **PFX output** compatible with Rubeus `asktgt /certificate:` and PKINITtools
