<p align="center">
  <img alt="Aphrodite Logo" src="Payload_Type/aphrodite/agent_functions/aphrodite.svg" height="30%" width="30%">
</p>

# Aphrodite

Aphrodite is a stealth-first C2 agent written in Nim for [Mythic 3.0+](https://github.com/its-a-feature/Mythic). Every design decision prioritizes evasion: compile-time string obfuscation, W^X memory discipline, browser-grade HTTP fingerprints, ETW/AMSI patching, and zero runtime noise.

Cross-compiled to a native binary from Linux - no interpreter, no managed runtime, no dependencies on the target.

---

## Stealth Design

### Compile-time String Obfuscation

Every string literal in the agent is XOR-encrypted at compile time using the `hidstr` macro. Command names, C2 protocol keys (`checkin`, `get_tasking`), system call strings (`/bin/sh -c`, `cmd.exe /c`), registry paths, API names - none appear in plaintext in the binary.

`strings(1)` on the binary reveals nothing useful.

A second layer handles config values (C2 URL, UUID, PSK, kill date, user-agent): when `obfuscation=xor` or `obfuscation=aes` is selected at build time, these constants are XOR or AES-128 encoded with a per-build random key baked into the binary and decoded at runtime from `.rdata`.

### W^X Memory - Never RWX

All injection code respects Write XOR Execute:

| Technique | Memory flow |
|-----------|-------------|
| `earlybird` | VirtualAllocEx(RW) -> WriteProcessMemory -> VirtualProtectEx(RX) -> APC |
| `inject createremotethread` | VirtualAllocEx(RW) -> WriteProcessMemory -> VirtualProtectEx(RX) -> CRT |
| `inject ntmapview` | NtCreateSection -> NtMapViewOfSection(RW local) -> copyMem -> unmap -> NtMapViewOfSection(RX remote) |
| `inline_execute` (BOF) | VirtualAlloc(RW) per section -> copyMem -> relocations -> VirtualProtect(RX) -> call entry |

No region is simultaneously writable and executable. PAGE_EXECUTE_READWRITE (0x40) is never used.

### NtMapViewOfSection - MWTI ETW Bypass

The `ntmapview` injection technique (default for `inject`) uses `NtCreateSection` + `NtMapViewOfSection` instead of `VirtualAllocEx`. This avoids triggering the `NtAllocateVirtualMemory` event under the `Microsoft-Windows-Threat-Intelligence` ETW provider, which is the primary telemetry source for Elastic's process injection detections.

### ETW Patching

The `etwpatch` command patches `EtwEventWrite` in ntdll.dll to `xor eax,eax; ret` (3 bytes), silencing the `Microsoft-Windows-Threat-Intelligence` provider for the duration of injection. Fully reversible with `etwpatch unpatch`.

### AMSI Bypass

The `amsi` command patches `AmsiScanBuffer` in amsi.dll to always return `AMSI_RESULT_CLEAN`. Reversible with `amsi unpatch`.

### HTTP Traffic Fingerprint

Traffic profile is browser-grade - Elastic NDR, Zeek, and Suricata rule sets see a standard browser request:

```
User-Agent:      <configurable per build>
Accept:          text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type:    text/plain
Connection:      keep-alive
Cache-Control:   no-cache
```

### Zero Runtime Noise

All debug output (`stderr.writeLine`) is compiled out in production builds. The binary writes nothing to stderr unless `-d:debug` is passed at compile time. No logs, no banners, no startup messages.

### Sleep Obfuscation (Windows)

When compiled with `-d:sleepObf`, the AES session key and Mythic callback ID are XOR-encrypted with random per-sleep masks during the sleep window. Userland memory scanners (Elastic, AV) running between beacons cannot extract C2 crypto material from the process heap. Keys are restored before the next beacon cycle.

### Bidirectional Jitter

Sleep jitter applies a random variation in both directions (+/-) rather than only reducing sleep time. Beacon timing is less predictable and harder to fingerprint statistically.

### Donut / LZFSE

When generating shellcode via Donut for `execute_assembly` and similar payloads, LZFSE compression (`compress=2`) is used instead of the default aPLib (`compress=1`). The aPLib byte sequence in the Donut loader stub is a known Elastic signature (`Windows.Trojan.Donutloader`). LZFSE produces different stub bytes, avoiding this signature.

---

## Features

- Linux and Windows (cross-compiled from Linux via mingw-w64)
- C2 profiles: HTTP, WebSocket, Chess.com
- AES-256-CBC + HMAC-SHA256 encryption
- PSK mode (pre-shared key at build time)
- EKE mode - RSA-2048 staging, session key negotiated at runtime (Linux only)
- SOCKS5 proxy tunneling
- Interactive shell (`psh`) with full terminal emulation
- BOF execution (`inline_execute`) - Cobalt Strike-compatible Beacon Object Files
- 50+ built-in commands

### Commands

| Category | Commands |
|----------|----------|
| Reconnaissance | `whoami`, `hostname`, `ps`, `ifconfig`, `arp`, `nslookup`, `uptime`, `netstat` |
| Filesystem | `ls`, `cat`, `cd`, `pwd`, `mkdir`, `rm`, `mv`, `cp`, `tail`, `drives`, `chmod`, `chown`, `find`, `write` |
| Transfer | `download`, `upload`, `wget`, `curl` |
| Execution | `shell`, `psh`, `sudo`, `runas` |
| Injection (Windows) | `earlybird`, `inject` (createremotethread / queueapcthread / ntmapview) |
| EDR Bypass (Windows) | `etwpatch`, `amsi` |
| BOF (Windows) | `inline_execute`, `execute_assembly` |
| Post-exploitation (Windows) | `screenshot`, `reg`, `steal_token`, `make_token`, `rev2self` |
| Environment | `getenv`, `setenv`, `env` |
| Control | `sleep`, `exit`, `kill`, `echo`, `socks`, `jobs`, `jobkill`, `config` |

---

## Installation

```bash
# From your Mythic install directory
./mythic-cli install github https://github.com/0xbbuddha/aphrodite
```

---

## Build Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target_os` | Choice | `linux` | Target OS: `linux` or `windows` |
| `architecture` | Choice | `amd64` | Target architecture |
| `c2_profile` | Choice | `http` | C2 transport: `http` or `websocket` |
| `obfuscation` | Choice | `xor` | Config obfuscation: `xor` (per-build random key), `aes`, or `none` |
| `static_binary` | Boolean | `false` | Statically link all libraries |
| `sleep_obf` | Boolean | `false` | XOR-encrypt AES key and callback ID during sleep (Windows only) |
| `debug` | Boolean | `false` | Enable stderr output (disabled by default in all builds) |

---

## C2 Profiles

### HTTP

POST-based communication over Mythic's HTTP profile. All traffic uses the browser-grade header set described above.

Encryption modes:
- **PSK** - AES-256-CBC + HMAC-SHA256 with a pre-shared key baked at build time (uncheck "Encrypted Key Exchange" in the C2 profile)
- **EKE** - RSA-2048 staging: `staging_rsa` message sent with PSK, Mythic returns session AES key encrypted with the agent's RSA public key (Linux only)
- **Plaintext** - leave AESPSK empty, for lab/testing only

### WebSocket

Persistent WebSocket connection. Messages follow the Mythic WebSocket envelope format (`{"client":true,"data":"...","tag":""}`). Same encryption modes as HTTP.

### Chess.com

Covert channel using Chess.com library collections and FEN positions (Base5 PNBRQ encoding, CheckmateC2-compatible). Requires the [Chess.com](https://github.com/0xbbuddha/Chess.com) C2 profile.

---

## Opsec Notes

- Always use `obfuscation=xor` or `obfuscation=aes` in production builds
- Prefer `inject ntmapview` over `inject createremotethread` to avoid MWTI ETW events
- Run `etwpatch patch` before injection operations on hardened targets
- Enable `sleep_obf` on targets with active memory scanning (Elastic, Defender)
- The Chess.com profile offers the strongest network-level concealment - traffic blends with legitimate Chess.com API calls
- Never enable `debug=true` on operational builds - it produces stderr output that can be captured by EDR telemetry hooks

---

## Known Limitations

- EKE staging is Linux-only (requires OpenSSL at build time)
- `sleep_obf` is Windows-only
- Windows EDR bypass commands (`etwpatch`, `amsi`, `inject`) require appropriate privileges

---

## Credit

- [@0xbbuddha](https://github.com/0xbbuddha) - Author
