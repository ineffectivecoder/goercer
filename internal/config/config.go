package config

import "fmt"

// Mode selects whether coerced authentication should target SMB (UNC paths)
// or HTTP/WebDAV (for relay attacks such as AD CS ESC8).
type Mode string

const (
	// ModeUNC builds \\listener\share\file UNC paths (SMB callback).
	ModeUNC Mode = "unc"
	// ModeHTTP builds \\host@80/path WebDAV paths (HTTP callback).
	ModeHTTP Mode = "http"
)

// Config is the fully-resolved runtime configuration. It is produced by the
// CLI layer after validation and consumed by the coercer engine. Keeping this
// as a single value object decouples argument parsing from execution and makes
// both unit-testable.
type Config struct {
	TargetIP string // Target server IP address.
	Listener string // Listener host / host@port / WebDAV path.
	User     string // Domain username.
	Domain   string // Domain name.
	Password string // Plaintext password (mutually exclusive with Hash).
	Hash     string // 32-char NTLM hash (pass-the-hash).

	Method string // Registered method name (e.g. "petitpotam").
	Pipe   string // Named pipe (petitpotam only).
	Opnum  int    // Specific opnum to test; -1 means "try all".

	ProxyURL string // socks5://host:port dialer.

	Mode    Mode // ModeUNC or ModeHTTP.
	Verbose bool // Emit debug output.
	FireAll bool // Continue past first success.
	JSON    bool // Emit results as JSON on stdout.

	// Transport plumbing, resolved lazily by smbxport.
	HashBytes []byte // Decoded 16-byte NT hash when Hash is set.
}

// New returns a Config populated with defaults matching the original tool's
// behaviour.
func New() *Config {
	return &Config{
		Mode:   ModeUNC,
		Pipe:   "efsrpc",
		Method: "petitpotam",
		Opnum:  -1,
	}
}

// Validate performs cross-field validation that cannot be expressed as a
// single flag check. It returns a descriptive error when the configuration is
// inconsistent.
func (c *Config) Validate() error {
	if c.TargetIP == "" || c.Listener == "" || c.User == "" || c.Domain == "" {
		return fmt.Errorf("missing required parameters: -t, -l, -u, -d")
	}
	if c.Password == "" && c.Hash == "" {
		return fmt.Errorf("authentication required: provide -p (password) or -H (hash)")
	}
	return nil
}
