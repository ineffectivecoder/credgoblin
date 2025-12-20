# CredGoblin Architectural Design Document

## Executive Summary

CredGoblin is a high-performance NTLM credential capture and relay tool written in Go. It enables security professionals to capture NTLMv2 hashes from SMB, HTTP, and HTTPS connections, and relay NTLM authentication to LDAP/LDAPS (for Shadow Credentials attacks) or AD Certificate Services (for ESC8 certificate abuse).

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CREDGOBLIN                                  │
├─────────────────────────────────────────────────────────────────────┤
│  cmd/credgoblin/                                                    │
│  ├── main.go          → Subcommand dispatcher                       │
│  ├── capture.go       → Hash capture mode                           │
│  └── relay.go         → NTLM relay attack mode                      │
├─────────────────────────────────────────────────────────────────────┤
│  pkg/                                                               │
│  ├── config/          → Configuration structures                   │
│  ├── ntlm/            → NTLM protocol implementation               │
│  ├── output/          → Logging and hash file I/O                  │
│  ├── smb/             → SMB/HTTP server for capture                │
│  ├── relay/           → NTLM relay to LDAP/ADCS                    │
│  └── shadowcreds/     → Shadow Credentials generation              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Package Structure

### 2.1 cmd/credgoblin/ - CLI Entry Points

| File | Purpose |
|------|---------|
| `main.go` | Subcommand dispatcher (`capture`, `relay`, `version`, `help`) |
| `capture.go` | Hash capture command - starts SMB/HTTP servers |
| `relay.go` | Relay attack command - forwards auth to LDAP/ADCS |

**Command Flow:**
```
credgoblin [capture|relay]
    ├── capture → runCapture() → smb.NewServer().Start()
    └── relay   → runRelay()   → relay.NewServer().Start()
```

### 2.2 pkg/config/ - Configuration

**Key Structures:**
- `CaptureConfig`: ListenAddr, ListenPorts, OutputFile, ServerName, DomainName, Verbose
- `RelayConfig`: TargetURL, TargetDomain, TargetUser, RelayMode, TemplateName, PFXPassword

### 2.3 pkg/ntlm/ - NTLM Protocol (5 files, ~13KB)

| File | Purpose |
|------|---------|
| `ntlm.go` | Core types, constants, security buffer parsing |
| `challenge.go` | Type 2 challenge message generation |
| `auth.go` | Type 3 authenticate message parsing |
| `hash.go` | Hashcat format output (mode 5600) |

**Key Types:**
```go
// Security Buffer (offset-based data reference)
type SecurityBuffer struct {
    Length    uint16
    MaxLength uint16
    Offset    uint32
}

// NTLM Message Types
NtLmNegotiate    = 0x00000001  // Type 1
NtLmChallenge    = 0x00000002  // Type 2
NtLmAuthenticate = 0x00000003  // Type 3
```

### 2.4 pkg/output/ - Logging & I/O (2 files)

| File | Purpose |
|------|---------|
| `logger.go` | Colored console logging with timestamps |
| `hashwriter.go` | Thread-safe hash file writing (mutex-protected) |

### 2.5 pkg/smb/ - SMB Protocol Server (9 files, ~70KB)

| File | Purpose |
|------|---------|
| `server.go` | Multi-protocol server (445/80/443) |
| `handler.go` | SMB connection state machine |
| `http_handler.go` | HTTP/HTTPS NTLM auth capture |
| `negotiate.go` | SMB2 negotiate handling |
| `session.go` | Session setup and SPNEGO |
| `smb1*.go` | SMB1 backward compatibility |

### 2.6 pkg/relay/ - NTLM Relay Engine (4 files, ~110KB)

| File | Lines | Purpose |
|------|-------|---------|
| `relay.go` | 2,483 | Main relay orchestrator, SMB/HTTP handlers |
| `ldap.go` | 2,129 | LDAP client with SICILY protocol |
| `adcs.go` | 839 | ADCS HTTP certificate enrollment |
| `ldap_signing.go` | 175 | GSS-API signing/sealing |

### 2.7 pkg/shadowcreds/ - Shadow Credentials (2 files)

| File | Purpose |
|------|---------|
| `keycredential.go` | KeyCredential blob generation (RSA 2048-bit) |
| `export.go` | PFX/PKCS#12 certificate export |

---

## 3. Core Data Flows

### 3.1 Capture Mode Flow

```
Client → TCP:445/80/443
    │
    ├─ SMB/HTTP Protocol Detection
    │
    ├─ NEGOTIATE Request
    │   └─ Server: Generate NTLM Type 2 Challenge (8-byte random)
    │
    ├─ SESSION_SETUP / Authorization Header
    │   └─ Client: NTLM Type 3 with NTLMv2 response
    │
    ├─ Hash Extraction
    │   ├─ Parse Type 3 message
    │   ├─ Extract: Username, Domain, NT Response
    │   └─ Format: Hashcat mode 5600
    │
    └─ Output
        ├─ HashWriter.WriteHash() → hashes.txt
        └─ Return STATUS_ACCESS_DENIED / HTTP 401
```

### 3.2 Relay Mode Flow

```
Client → SMB/HTTP (445/80)
    │
    ├─ Receive NTLM Type 1
    │   └─ Strip signing flags (CVE-2019-1040)
    │
    ├─ Forward Type 1 → Target (LDAP/ADCS)
    │   └─ Receive Type 2 from target
    │
    ├─ Return Type 2 to client
    │   └─ Client computes Type 3
    │
    ├─ Receive NTLM Type 3
    │   └─ Remove VERSION+MIC (CVE-2019-1040)
    │
    ├─ Forward Type 3 → Target
    │   └─ Authentication complete
    │
    └─ Execute Attack
        ├─ LDAP: Modify msDS-KeyCredentialLink (Shadow Credentials)
        └─ ADCS: Request certificate (ESC8)
```

---

## 4. Protocol Implementations

### 4.1 NTLM Message Structure

**Type 1 (Negotiate):**
```
Offset  Field
0-7     Signature ("NTLMSSP\0")
8-11    MessageType (1)
12-15   NegotiateFlags
16-23   DomainName (SecurityBuffer)
24-31   Workstation (SecurityBuffer)
32+     Payload
```

**Type 2 (Challenge):**
```
Offset  Field
0-7     Signature
8-11    MessageType (2)
12-19   TargetName (SecurityBuffer)
20-23   NegotiateFlags
24-31   ServerChallenge (8 bytes)
32-39   Reserved
40-47   TargetInfo (SecurityBuffer)
48-55   Version (optional)
56+     Payload
```

**Type 3 (Authenticate):**
```
Offset  Field
0-7     Signature
8-11    MessageType (3)
12-19   LmChallengeResponse (SecurityBuffer)
20-27   NtChallengeResponse (SecurityBuffer)
28-35   DomainName (SecurityBuffer)
36-43   UserName (SecurityBuffer)
44-51   Workstation (SecurityBuffer)
52-59   EncryptedRandomSessionKey (SecurityBuffer)
60-63   NegotiateFlags
64-71   Version (optional, 8 bytes)
72-87   MIC (optional, 16 bytes)
88+     Payload
```

### 4.2 SPNEGO Wrapping

SPNEGO wraps NTLM for use in SMB2 and HTTP Negotiate auth:

**NegTokenInit (Type 1):**
```
[APPLICATION 0]
  OID: 1.3.6.1.5.5.2 (SPNEGO)
  [0] mechTypes: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
  [2] mechToken: <NTLM Type 1>
```

**NegTokenResp (Type 2/3):**
```
[1] responseToken: <NTLM Type 2 or 3>
```

### 4.3 SICILY Protocol (LDAP)

Microsoft's proprietary NTLM-over-LDAP mechanism:

```
1. sicilyDiscovery()    → Empty SASL bind (tag 9)
2. sicilyNegotiate()    → NTLM Type 1 in mechanism (tag 10)
3. sicilyAuthenticate() → NTLM Type 3 in sicilyResponse (tag 11)
```

**Critical:** Pre-SICILY queries required to "warm up" Windows DC.

### 4.4 SMB2 Session Setup

```
SMB2_NEGOTIATE → Dialect 0x0210, SPNEGO blob
SMB2_SESSION_SETUP (Type 1) → STATUS_MORE_PROCESSING_REQUIRED
SMB2_SESSION_SETUP (Type 3) → STATUS_SUCCESS/ACCESS_DENIED
```

---

## 5. Security Mechanisms

### 5.1 CVE-2019-1040 "Drop the MIC"

Enables cross-protocol NTLM relay by exploiting MIC calculation:

**Technique:**
1. Remove signing flags from Type 2 (SIGN, SEAL, KEY_EXCH)
2. Client computes Type 3 without MIC (signing not negotiated)
3. Remove VERSION+MIC (24 bytes) from Type 3
4. Adjust all payload offsets by -24
5. Server accepts because MIC is optional when signing disabled

**Implementation:** `removeVersionAndMIC()` in relay.go

### 5.2 Shadow Credentials Attack

After successful LDAP relay:
1. Generate RSA 2048-bit key pair
2. Build KeyCredential blob (binary format)
3. LDAP modify: `msDS-KeyCredentialLink` attribute
4. Generate self-signed X.509 certificate with UPN SAN
5. Export PFX for PKINIT authentication

### 5.3 ADCS ESC8 Attack

After successful HTTP relay to ADCS:
1. Prepare CSR (Certificate Signing Request)
2. POST to /certsrv/ with CSR form data
3. Retrieve issued certificate
4. Export PFX

---

## 6. Key Design Patterns

### 6.1 Dependency Injection

Components passed as constructor arguments:
```go
func NewServer(config *Config, logger *Logger, hashWriter *HashWriter) *Server
func NewHandler(conn, config, logger, challengeGen, authParser) *Handler
```

### 6.2 Context-Based Cancellation

Graceful shutdown via context:
```go
ctx, cancel := context.WithCancel(context.Background())
signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
go func() { <-sigChan; cancel() }()
server.Start(ctx)
```

### 6.3 Thread-Safe I/O

Mutex-protected hash writing:
```go
func (w *HashWriter) WriteHash(hash string) error {
    w.mutex.Lock()
    defer w.mutex.Unlock()
    // write + sync
}
```

---

## 7. Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/mjwhitta/cli` | CLI argument parsing |
| `github.com/go-ldap/ldap/v3` | LDAP protocol support |
| `github.com/go-asn1-ber/asn1-ber` | ASN.1 BER encoding |
| `github.com/google/uuid` | UUID generation |
| `software.sslmate.com/src/go-pkcs12` | PFX export |
| `github.com/Azure/go-ntlmssp` | NTLM helpers |
| `golang.org/x/crypto` | Cryptographic operations |

---

## 8. File Statistics

| Package | Files | Approximate Size |
|---------|-------|------------------|
| cmd/credgoblin | 3 | ~5KB |
| pkg/config | 1 | ~2KB |
| pkg/ntlm | 5 | ~13KB |
| pkg/output | 2 | ~3KB |
| pkg/smb | 9 | ~70KB |
| pkg/relay | 4 | ~110KB |
| pkg/shadowcreds | 2 | ~8KB |
| **Total** | **26** | **~211KB** |

---

## 9. Usage Examples

### Capture Mode
```bash
credgoblin capture -i 0.0.0.0 -o hashes.txt -v
```

### LDAP Relay
```bash
credgoblin relay -t ldap://dc.domain.local \
  -u 'CN=DC01,CN=Computers,DC=domain,DC=local' \
  -m ldap -o output.pfx
```

### ADCS Relay
```bash
credgoblin relay -t http://ca.domain.local/certsrv/ \
  -T User -m adcs -o output.pfx
```

---

## 10. Architecture Diagram

```
                    ┌─────────────────────────────────────┐
                    │           CREDGOBLIN CLI            │
                    │  main.go → capture.go / relay.go    │
                    └──────────────────┬──────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
    ┌─────────▼─────────┐    ┌────────▼────────┐    ┌─────────▼─────────┐
    │   CAPTURE MODE    │    │   RELAY MODE    │    │      SHARED       │
    │                   │    │                 │    │                   │
    │  pkg/smb/         │    │  pkg/relay/     │    │  pkg/config/      │
    │  ├─ server.go     │    │  ├─ relay.go    │    │  pkg/ntlm/        │
    │  ├─ handler.go    │    │  ├─ ldap.go     │    │  pkg/output/      │
    │  ├─ http_handler  │    │  ├─ adcs.go     │    │  pkg/shadowcreds/ │
    │  └─ smb1/2        │    │  └─ signing     │    │                   │
    └─────────┬─────────┘    └────────┬────────┘    └───────────────────┘
              │                        │
              │    NTLM Type 1/2/3     │
              │◄──────────────────────►│
              │                        │
    ┌─────────▼─────────┐    ┌────────▼────────┐
    │  HASH OUTPUT      │    │  ATTACK OUTPUT  │
    │  hashes.txt       │    │  output.pfx     │
    │  (Hashcat 5600)   │    │  (Certificate)  │
    └───────────────────┘    └─────────────────┘
```
