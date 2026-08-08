package smbxport

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"golang.org/x/net/proxy"
)

// Pipe wraps the SMB named-pipe file handle and satisfies dcerpc.Transport.
type Pipe struct {
	*smb.File
}

// WriteFile forwards to the underlying SMB pipe.
func (p *Pipe) WriteFile(b []byte, offset uint64) (int, error) {
	return p.File.WriteFile(b, offset)
}

// ReadFile forwards to the underlying SMB pipe.
func (p *Pipe) ReadFile(b []byte, offset uint64) (int, error) {
	return p.File.ReadFile(b, offset)
}

// Session owns the authenticated SMB connection to the target and manages the
// IPC$ tree connection. It is the single place that knows how to reach the
// target, including through a SOCKS5 proxy.
type Session struct {
	conn  *smb.Connection
	share string
}

// Connect opens an authenticated SMB session to the target. When proxyURL is
// non-empty and socks5:// it is used as the transport dialer. A 32-char hash
// enables pass-the-hash via NTLMInitiator; otherwise a plaintext password is
// used.
func Connect(targetIP, user, domain, password string, hashBytes []byte, proxyURL string) (*Session, error) {
	opts := smb.Options{
		Host: targetIP,
		Port: 445,
	}

	if proxyURL != "" {
		dialer, err := socksDialer(proxyURL)
		if err != nil {
			return nil, err
		}
		opts.ProxyDialer = dialer
	}

	if hashBytes != nil {
		opts.Initiator = &spnego.NTLMInitiator{
			User:   user,
			Hash:   hashBytes,
			Domain: domain,
		}
	} else {
		opts.Initiator = &spnego.NTLMInitiator{
			User:     user,
			Password: password,
			Domain:   domain,
		}
	}

	conn, err := smb.NewConnection(opts)
	if err != nil {
		return nil, fmt.Errorf("smb connection failed: %w", err)
	}

	s := &Session{conn: conn, share: "IPC$"}
	if err := conn.TreeConnect(s.share); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tree connect to IPC$ failed: %w", err)
	}
	return s, nil
}

// OpenNamedPipe opens a named-pipe resource on the connected IPC$ share with
// read/write access, as required for DCERPC traffic.
func (s *Session) OpenNamedPipe(pipeName string) (*Pipe, error) {
	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = smb.FAccMaskFileReadData | smb.FAccMaskFileWriteData |
		smb.FAccMaskFileReadEA | smb.FAccMaskFileReadAttributes |
		smb.FAccMaskReadControl | smb.FAccMaskSynchronize

	f, err := s.conn.OpenFileExt(s.share, pipeName, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open pipe %s: %w", pipeName, err)
	}
	return &Pipe{File: f}, nil
}

// Close tears down the SMB session.
func (s *Session) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func socksDialer(proxyURL string) (proxy.Dialer, error) {
	if !strings.HasPrefix(proxyURL, "socks5://") {
		return nil, fmt.Errorf("proxy must start with socks5://")
	}
	host := strings.TrimPrefix(proxyURL, "socks5://")
	if !strings.Contains(host, ":") {
		return nil, fmt.Errorf("proxy URL must include a port")
	}
	d, err := proxy.FromURL(&url.URL{Scheme: "socks5", Host: host}, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy dialer: %w", err)
	}
	return d, nil
}
