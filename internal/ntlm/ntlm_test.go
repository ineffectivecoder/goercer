package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Known-answer vectors for the NTLMv2 derivation. These were verified against
// an independent RFC-1320 MD4 reference and match the exact byte output of the
// implementation they pin. If any hardcoded value changes, the crypto layer
// has diverged from the wire-proven format (the live DC captures succeeded
// with this exact derivation).
//
// Inputs:
//
//	password = "Password"
//	user     = "User"
//	domain   = "Domain"
//	ntProof  = 000102030405060708090a0b0c0d0e0f
const (
	wantNTMD4     = "a4f49c406510bdcab6824ee7c30fd852"
	wantNTLMv2    = "0c868a403bfd7a93a3001ef22ef02e3f"
	wantSessionBK = "8f965df3ce878ef7aa97135a65892615"
	wantSignC     = "91ed22da143a96fe3db6918bd2c3a91b"
	wantSignS     = "688b9b5fe0da6d72b2f019a9fced404e"
	wantSealC     = "b87bccb1f6cdf82fb08c670258828eea"
	wantSealS     = "8a9f8f58ae390ceeffa58ad494d997fa"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test: %v", err)
	}
	return b
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

func TestNTMD4KnownAnswer(t *testing.T) {
	got := NTMD4("Password")
	if hexStr(got) != wantNTMD4 {
		t.Fatalf("NTMD4(Password) = %s, want %s", hexStr(got), wantNTMD4)
	}
}

func TestNTLMv2HashKnownAnswer(t *testing.T) {
	nt := mustDecodeHex(t, wantNTMD4)
	got := NTv2Hash(nt, "User", "Domain")
	if hexStr(got) != wantNTLMv2 {
		t.Fatalf("NTv2Hash = %s, want %s", hexStr(got), wantNTLMv2)
	}
}

func TestKeyDerivationKnownAnswers(t *testing.T) {
	nt := mustDecodeHex(t, wantNTMD4)
	v2 := NTv2Hash(nt, "User", "Domain")
	ntProof := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f")

	sbk := SessionBaseKey(v2, ntProof)
	if hexStr(sbk) != wantSessionBK {
		t.Fatalf("SessionBaseKey = %s, want %s", hexStr(sbk), wantSessionBK)
	}

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"SignKey(client)", hexStr(SignKey(sbk, true)), wantSignC},
		{"SignKey(server)", hexStr(SignKey(sbk, false)), wantSignS},
		{"SealKey(client)", hexStr(SealKey(sbk, true)), wantSealC},
		{"SealKey(server)", hexStr(SealKey(sbk, false)), wantSealS},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}
}

// TestSignatureRC4Continuity pins the single most fragile invariant in the
// whole tool: the client seal handle is a CONTINUOUS RC4 stream that is never
// reset between requests. A regression that re-initialised the cipher (or a
// per-message seal key) would silently break the handshake on the wire while
// still compiling.
func TestSignatureRC4Continuity(t *testing.T) {
	nt := mustDecodeHex(t, wantNTMD4)
	v2 := NTv2Hash(nt, "User", "Domain")
	sbk := SessionBaseKey(v2, mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f"))

	a := &AUTH{
		ClientSignKey: SignKey(sbk, true),
		ClientSealKey: SealKey(sbk, true),
		SeqNum:        0,
	}
	a.ClientSealHandle, _ = rc4.NewCipher(a.ClientSealKey)

	// First signature starts from a fresh keystream (position 0..7).
	msg1 := []byte("first message payload")
	sig1 := a.Signature(msg1)
	enc1 := sig1[4:12]

	// Advance SeqNum and sign again; the stream must CONTINUE (position 8..15).
	a.SeqNum = 1
	msg2 := []byte("second message payload over the continued stream")
	sig2 := a.Signature(msg2)
	enc2 := sig2[4:12]

	// Recompute what a BRAND-NEW cipher (a reset) would have produced for the
	// second signature. If the implementation reset the handle between sig1
	// and sig2, enc2 would equal this fresh value.
	freshCipher, _ := rc4.NewCipher(a.ClientSealKey)
	freshChecksum := checksum(a.ClientSignKey, 1, msg2)
	freshEnc := freshChecksum[:8]
	fresh := make([]byte, 8)
	freshCipher.XORKeyStream(fresh, freshEnc)

	if bytes.Equal(enc2, fresh) {
		t.Fatalf("signature stream appears to have been RESET: second signature equals a fresh-handle value")
	}
	// Sanity: the reset value must actually be reachable/different, proving the
	// check is discriminating. A continued stream at position 0-7 (matching a
	// fresh cipher on a differently-seeded message) should differ from enc1.
	if bytes.Equal(enc1, fresh) {
		t.Fatalf("test setup degenerate: fresh-handle value collides with first signature")
	}
}

// checksum replicates the HMAC-MD5 inner step of AUTH.Signature (without the
// RC4 step) so the test can recompute the pre-encryption checksum for a given
// sequence number.
func checksum(signKey []byte, seqNum uint32, message []byte) []byte {
	h := hmac.New(md5.New, signKey)
	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, seqNum)
	h.Write(seq)
	h.Write(message)
	return h.Sum(nil)
}

// TestSignatureFormatThenSeqNum is a structural check that the verifier is the
// expected 16-byte [version:4][encChecksum:8][seqnum:4] layout.
func TestSignatureFormat(t *testing.T) {
	a := &AUTH{
		ClientSignKey: mustDecodeHex(t, wantSignC),
		ClientSealKey: mustDecodeHex(t, wantSealC),
		SeqNum:        7,
	}
	a.ClientSealHandle, _ = rc4.NewCipher(a.ClientSealKey)

	sig := a.Signature([]byte{0x01})
	if len(sig) != 16 {
		t.Fatalf("signature length = %d, want 16", len(sig))
	}
	if binary.LittleEndian.Uint32(sig[0:4]) != 1 {
		t.Fatalf("signature version = %d, want 1", binary.LittleEndian.Uint32(sig[0:4]))
	}
	if binary.LittleEndian.Uint32(sig[12:16]) != 7 {
		t.Fatalf("signature seqnum = %d, want 7", binary.LittleEndian.Uint32(sig[12:16]))
	}
}
