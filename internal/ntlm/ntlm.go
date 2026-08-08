package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// NTLM flag constants used to build and negotiate messages.
const (
	FlagUnicode            uint32 = 0x00000001
	FlagOEM                uint32 = 0x00000002
	FlagRequestTarget      uint32 = 0x00000004
	FlagNTLM               uint32 = 0x00000200
	FlagAlwaysSign         uint32 = 0x00008000
	FlagExtendedSessionSec uint32 = 0x00080000
	FlagTargetInfo         uint32 = 0x00800000
	FlagVersion            uint32 = 0x02000000
	Flag128                uint32 = 0x20000000
	FlagKeyExch            uint32 = 0x40000000
	FlagSign               uint32 = 0x00000010
	FlagSeal               uint32 = 0x00000020
)

// Magic constants used to derive signing/sealing keys.
const (
	signClientMagic = "session key to client-to-server signing key magic constant\x00"
	signServerMagic = "session key to server-to-client signing key magic constant\x00"
	sealClientMagic = "session key to client-to-server sealing key magic constant\x00"
	sealServerMagic = "session key to server-to-client sealing key magic constant\x00"
)

// NegotiateFlags returns the Type 1 flag set that the original tool validated
// as required for NTLMv2 PKT_PRIVACY authentication.
func NegotiateFlags() uint32 {
	return Flag128 |
		FlagKeyExch |
		FlagVersion |
		FlagTargetInfo | // CRITICAL: required for NTLMv2
		FlagExtendedSessionSec | // CRITICAL: required for NTLMv2
		FlagNTLM |
		FlagRequestTarget |
		FlagUnicode |
		FlagSign |
		FlagSeal
}

// AUTH: NTLM auth state for a DCERPC PKT_PRIVACY session. It holds the
// cryptographic material derived during the Bind/Auth3 handshake and the
// continuous RC4 cipher handles that must never be reinitialised between
// requests (a core correctness requirement of the original implementation).
type AUTH struct {
	User     string
	Password string
	Hash     []byte
	Domain   string

	Challenge      []byte
	Flags          uint32
	SessionBaseKey []byte
	ClientSignKey  []byte
	ClientSealKey  []byte
	ServerSignKey  []byte
	ServerSealKey  []byte
	SeqNum         uint32
	AuthContextID  uint32
	NegotiateMsg   []byte
	ChallengeMsg   []byte

	ClientSealHandle *rc4.Cipher
	ServerSealHandle *rc4.Cipher
}

// New seeds an AUTH from the user-supplied credential material. The password
// path computes the NT hash from the plaintext; a precomputed hash takes
// precedence.
func New(user, password, domain string, hash []byte) *AUTH {
	return &AUTH{
		User:     user,
		Password: password,
		Hash:     hash,
		Domain:   domain,
		SeqNum:   0,
	}
}

// Negotiate builds the NTLM Type 1 (Negotiate) message.
type Negotiate struct{}

func (Negotiate) Build() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("NTLMSSP\x00")
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Message type

	binary.Write(buf, binary.LittleEndian, NegotiateFlags())

	// Domain fields (empty).
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Workstation fields (empty).
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// VERSION structure.
	buf.WriteByte(6)
	buf.WriteByte(1)
	binary.Write(buf, binary.LittleEndian, uint16(0x1db1))
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(15)

	return buf.Bytes()
}

// BuildAuthenticate constructs the NTLM Type 3 (Authenticate) message using
// NTLMv2 and derives all session keys and RC4 cipher handles into a. It mirrors
// the original implementation's ordering and KEY_EXCH handling.
func (a *AUTH) BuildAuthenticate(challengeMsg []byte) []byte {
	targetInfo := extractTargetInfo(challengeMsg)
	hostname := extractHostname(targetInfo)
	if len(hostname) > 0 {
		targetInfo = addTargetName(targetInfo, hostname)
	}

	timestamp := time.Now().UnixNano()/100 + 116444736000000000
	clientChallenge := make([]byte, 8)
	rand.Read(clientChallenge)

	temp := buildTempBlob(timestamp, clientChallenge, targetInfo)

	var ntHashBytes []byte
	if a.Hash != nil && len(a.Hash) == 16 {
		ntHashBytes = a.Hash
	} else {
		ntHashBytes = NTMD4(a.Password)
	}

	ntlmv2Hash := NTv2Hash(ntHashBytes, a.User, a.Domain)
	ntlmv2Resp := NTv2Response(ntlmv2Hash, a.Challenge, temp)

	a.SessionBaseKey = SessionBaseKey(ntlmv2Hash, ntlmv2Resp[:16])
	a.ClientSignKey = SignKey(a.SessionBaseKey, true)
	a.ClientSealKey = SealKey(a.SessionBaseKey, true)

	buf := new(bytes.Buffer)
	buf.WriteString("NTLMSSP\x00")
	binary.Write(buf, binary.LittleEndian, uint32(3)) // Type 3

	domainUTF16 := UTF16LE(a.Domain)
	userUTF16 := UTF16LE(a.User)

	// NTLMv2 LM response: HMAC-MD5(ntlmv2Hash, challenge + clientChallenge) + clientChallenge.
	h := hmac.New(md5.New, ntlmv2Hash)
	h.Write(a.Challenge)
	h.Write(clientChallenge)
	lmResp := append(h.Sum(nil), clientChallenge...)

	// Base offset: 64-byte header + VERSION (8) + MIC (16) when negotiated.
	versionSet := a.Flags&FlagVersion != 0
	baseOffset := 64
	if versionSet {
		baseOffset += 8 + 16
	}
	offset := baseOffset

	// LM response.
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(lmResp)

	// NTLM response.
	binary.Write(buf, binary.LittleEndian, uint16(len(ntlmv2Resp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(ntlmv2Resp)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(ntlmv2Resp)

	// Domain.
	binary.Write(buf, binary.LittleEndian, uint16(len(domainUTF16)))
	binary.Write(buf, binary.LittleEndian, uint16(len(domainUTF16)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(domainUTF16)

	// User.
	binary.Write(buf, binary.LittleEndian, uint16(len(userUTF16)))
	binary.Write(buf, binary.LittleEndian, uint16(len(userUTF16)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(userUTF16)

	// Workstation (empty).
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += 0

	// Session key handling (KEY_EXCH semantics preserved from original).
	var encryptedKey, exportedKey []byte
	keyExchangeKey := a.SessionBaseKey
	if a.Flags&FlagKeyExch != 0 {
		exportedKey = make([]byte, 16)
		rand.Read(exportedKey)
		encryptedKey = make([]byte, 16)
		cipher, _ := rc4.NewCipher(keyExchangeKey)
		cipher.XORKeyStream(encryptedKey, exportedKey)
	} else {
		exportedKey = keyExchangeKey
		encryptedKey = []byte{}
	}

	// Re-derive keys from the exported session key and set up RC4 handles.
	a.SessionBaseKey = exportedKey
	a.ClientSignKey = SignKey(exportedKey, true)
	a.ClientSealKey = SealKey(exportedKey, true)
	a.ServerSignKey = SignKey(exportedKey, false)
	a.ServerSealKey = SealKey(exportedKey, false)

	a.ClientSealHandle, _ = rc4.NewCipher(a.ClientSealKey)
	a.ServerSealHandle, _ = rc4.NewCipher(a.ServerSealKey)

	// Session key field.
	binary.Write(buf, binary.LittleEndian, uint16(len(encryptedKey)))
	binary.Write(buf, binary.LittleEndian, uint16(len(encryptedKey)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(encryptedKey)

	// Response flags (force the two NTLMv2-critical bits, mask unsupported).
	responseFlags := uint32(0x62000231)
	responseFlags |= FlagExtendedSessionSec
	responseFlags |= FlagTargetInfo
	if a.Flags&Flag128 == 0 {
		responseFlags &^= Flag128
	}
	if a.Flags&FlagKeyExch == 0 {
		responseFlags &^= FlagKeyExch
	}
	if a.Flags&FlagSeal == 0 {
		responseFlags &^= FlagSeal
	}
	if a.Flags&FlagSign == 0 {
		responseFlags &^= FlagSign
	}
	if a.Flags&FlagAlwaysSign == 0 {
		responseFlags &^= FlagAlwaysSign
	}
	binary.Write(buf, binary.LittleEndian, responseFlags)

	// VERSION field.
	if versionSet {
		buf.WriteByte(6)
		buf.WriteByte(1)
		binary.Write(buf, binary.LittleEndian, uint16(7601))
		buf.Write([]byte{0, 0, 0})
		buf.WriteByte(15)
	}

	// MIC placeholder: filled in later over the whole message.
	if versionSet {
		buf.Write(make([]byte, 16))
	}

	buf.Write(lmResp)
	buf.Write(ntlmv2Resp)
	buf.Write(domainUTF16)
	buf.Write(userUTF16)
	buf.Write(encryptedKey)

	authMsg := buf.Bytes()

	// Compute the MIC over Negotiate + Challenge + Authenticate (MIC zeroed).
	if versionSet && len(exportedKey) > 0 {
		mic := hmac.New(md5.New, exportedKey)
		mic.Write(a.NegotiateMsg)
		mic.Write(a.ChallengeMsg)
		mic.Write(authMsg)
		copy(authMsg[64+8:64+8+16], mic.Sum(nil))
	}

	return authMsg
}

// extractTargetInfo pulls the AV_PAIR blob out of a Type 2 challenge message.
func extractTargetInfo(challengeMsg []byte) []byte {
	// Fallback: empty target info with terminator.
	targetInfo := []byte{0, 0, 0, 0}
	if len(challengeMsg) <= 48 {
		return targetInfo
	}
	infoLen := int(binary.LittleEndian.Uint16(challengeMsg[40:42]))
	infoOffset := int(binary.LittleEndian.Uint32(challengeMsg[44:48]))
	if infoLen > 0 && infoOffset+infoLen <= len(challengeMsg) {
		return challengeMsg[infoOffset : infoOffset+infoLen]
	}
	return targetInfo
}

// extractHostname finds the NetBIOS or DNS hostname AV_PAIR in target info.
func extractHostname(targetInfo []byte) []byte {
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
				host := make([]byte, avLen)
				copy(host, targetInfo[offset:offset+int(avLen)])
				return host
			}
		}
		offset += int(avLen)
	}
	return nil
}

// addTargetName appends a TARGET_NAME (0x0009) AV_PAIR of the form cifs/<host>.
func addTargetName(targetInfo, hostname []byte) []byte {
	filtered := new(bytes.Buffer)
	offset := 0
	for offset+4 <= len(targetInfo) {
		avID := binary.LittleEndian.Uint16(targetInfo[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(targetInfo[offset+2 : offset+4])
		if avID == 0x0000 { // EOL: stop and append later.
			break
		}
		filtered.Write(targetInfo[offset : offset+4+int(avLen)])
		offset += 4 + int(avLen)
	}

	targetName := append(UTF16LE("cifs/"), hostname...)

	buf := new(bytes.Buffer)
	buf.Write(filtered.Bytes())
	binary.Write(buf, binary.LittleEndian, uint16(0x0009))
	binary.Write(buf, binary.LittleEndian, uint16(len(targetName)))
	buf.Write(targetName)
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	return buf.Bytes()
}

func buildTempBlob(timestamp int64, clientChallenge, targetInfo []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x01)                 // RespType
	buf.WriteByte(0x01)                 // HiRespType
	buf.Write([]byte{0, 0, 0, 0, 0, 0}) // Reserved
	binary.Write(buf, binary.LittleEndian, uint64(timestamp))
	buf.Write(clientChallenge)
	buf.Write([]byte{0, 0, 0, 0}) // Reserved
	buf.Write(targetInfo)
	buf.Write([]byte{0, 0, 0, 0}) // EOL
	return buf.Bytes()
}

// NTMD4 computes the NT hash (MD4 of the UTF-16LE password), the base hash for
// NTLM. Accepts a precomputed 32-hex hash for pass-the-hash via the caller.
func NTMD4(password string) []byte {
	h := md4.New()
	h.Write(UTF16LE(password))
	return h.Sum(nil)
}

// NTv2Hash derives the NTLMv2 hash: HMAC-MD5(NT_hash, uppercase(user)+domain).
func NTv2Hash(ntHash []byte, user, domain string) []byte {
	h := hmac.New(md5.New, ntHash)
	h.Write(UTF16LE(UpperASCII(user) + domain))
	return h.Sum(nil)
}

// NTv2Response computes the NTLMv2 response (NTProofStr + temp).
func NTv2Response(ntlmv2Hash, serverChallenge, temp []byte) []byte {
	h := hmac.New(md5.New, ntlmv2Hash)
	h.Write(serverChallenge)
	h.Write(temp)
	return append(h.Sum(nil), temp...)
}

// SessionBaseKey derives HMAC-MD5(ntlmv2Hash, NTProofStr).
func SessionBaseKey(ntlmv2Hash, ntProofStr []byte) []byte {
	h := hmac.New(md5.New, ntlmv2Hash)
	h.Write(ntProofStr)
	return h.Sum(nil)
}

// SignKey derives MD5(sessionKey + signing magic).
func SignKey(sessionKey []byte, client bool) []byte {
	magic := signServerMagic
	if client {
		magic = signClientMagic
	}
	h := md5.New()
	h.Write(sessionKey)
	h.Write([]byte(magic))
	return h.Sum(nil)
}

// SealKey derives MD5(sessionKey + sealing magic).
func SealKey(sessionKey []byte, client bool) []byte {
	magic := sealServerMagic
	if client {
		magic = sealClientMagic
	}
	h := md5.New()
	h.Write(sessionKey)
	h.Write([]byte(magic))
	return h.Sum(nil)
}

// Signature builds the 16-byte NTLM verifier for a PKT_PRIVACY message using
// the continuous RC4 stream, matching impacket's GSS_GetMIC ordering.
func (a *AUTH) Signature(message []byte) []byte {
	h := hmac.New(md5.New, a.ClientSignKey)
	seqBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBytes, a.SeqNum)
	h.Write(seqBytes)
	h.Write(message)
	checksum := h.Sum(nil)[:8]

	encryptedChecksum := make([]byte, 8)
	a.ClientSealHandle.XORKeyStream(encryptedChecksum, checksum)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Version
	buf.Write(encryptedChecksum)
	binary.Write(buf, binary.LittleEndian, uint32(a.SeqNum))
	return buf.Bytes()
}

// UTF16LE encodes a string to UTF-16LE bytes.
func UTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	buf := new(bytes.Buffer)
	for _, r := range u16 {
		binary.Write(buf, binary.LittleEndian, r)
	}
	return buf.Bytes()
}

// UpperASCII uppercases ASCII letters (used only for the NTLMv2 identity user
// component, mirroring the original which explicitly does not uppercase the
// domain).
func UpperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

// DecodeHashHex returns the 16-byte NT hash for a 32-hex string, or an error.
func DecodeHashHex(s string) ([]byte, error) {
	if len(s) != 32 {
		return nil, fmt.Errorf("hash must be 32 hex characters")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("decoded hash is not 16 bytes")
	}
	return b, nil
}
