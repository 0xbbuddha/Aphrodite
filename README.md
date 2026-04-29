<p align="center">
  <img alt="Aphrodite Logo" src="Payload_Type/aphrodite/agent_functions/aphrodite.svg" height="30%" width="30%">
</p>

# Aphrodite

Aphrodite is a lightweight cross-platform agent written in Nim, designed for Mythic 3.0 and newer. Named after Aphrodite, goddess of beauty, compiled to a native binary, no runtime dependencies required.

## Features

- Linux and Windows support (cross-compiled from Linux via mingw-w64)
- HTTP, WebSocket, and Chess.com C2 profiles
- AES-256-CBC + HMAC-SHA256 encryption (PSK mode)
- EKE mode - RSA-2048 key exchange, session AES key negotiated at runtime (Linux only)
- Plaintext mode (no encryption, for testing - leave AESPSK empty)
- Configurable sleep interval and jitter
- Kill date support
- Static binary option (no shared library dependencies on target)
- SOCKS5 proxy support (tunneling through the agent)
- 42 built-in commands covering:
  - Reconnaissance (`whoami`, `ps`, `hostname`, `ifconfig`, `arp`, `nslookup`, `uptime`, `netstat`)
  - File operations (`ls`, `cat`, `cd`, `pwd`, `mkdir`, `rm`, `mv`, `cp`, `tail`, `drives`, `chmod`, `chown`, `find`, `write`)
  - File transfer (`download`, `upload`, `wget`, `curl`)
  - Execution (`shell`, `psh`, `sudo`, `runas`, `earlybird` - Windows only)
  - Environment (`getenv`, `setenv`, `env`)
  - Agent control (`sleep`, `exit`, `kill`, `echo`, `socks`, `jobs`, `jobkill`, `config`)

## Installation

1.) Install Mythic from [here](https://github.com/its-a-feature/Mythic)

2.) From the Mythic install directory, run the following command:

```bash
./mythic-cli install github https://github.com/0xbbuddha/aphrodite
```

## Supported C2 Profiles

### HTTP

Aphrodite communicates over the default HTTP profile used by Mythic. All taskings and responses are done via POST requests.

Encryption modes:
- **PSK** - pre-shared AES-256 key baked at build time (uncheck "Encrypted Key Exchange")
- **EKE** - RSA-2048 staging: the `staging_rsa` message is encrypted with the PSK, Mythic returns the session AES key encrypted with the agent's RSA public key. All subsequent messages use the negotiated session key (Linux only)
- **Plaintext** - no encryption, leave AESPSK empty in the C2 profile

### WebSocket

Persistent WebSocket connection to the Mythic server. Messages follow the Mythic WebSocket envelope format. Same encryption modes as HTTP.

### Chess.com

Covert channel using Chess.com library collections and FEN positions (Base5 PNBRQ encoding, CheckmateC2 compatible). Requires the [Chess.com](https://github.com/0xbbuddha/Chess.com) C2 profile. Same encryption modes as HTTP.

## Build Options

| Option          | Type    | Default   | Description                                              |
|-----------------|---------|-----------|----------------------------------------------------------|
| `target_os`     | Choice  | `linux`   | Target OS: `linux` or `windows`                          |
| `architecture`  | Choice  | `amd64`   | Target architecture (amd64 only)                         |
| `debug`         | Boolean | `false`   | Enable verbose debug output (larger binary)              |
| `static_binary` | Boolean | `false`   | Statically link binary (no shared library dependencies)  |
| `obfuscation`   | Choice  | `none`    | Config string obfuscation: `xor` or `aes` encode config values (C2 URL, UUID, PSK, kill date, user-agent) at build time, decoded at runtime. All other codebase strings are always obfuscated via compile-time XOR (`hidstr`) regardless of this option |

## Opsec Considerations

### Native Binary

Aphrodite compiles to a native binary with no runtime interpreter required on the target. This reduces the detection surface compared to script-based agents.

### Encryption

| Mode       | Description                                                                                      |
|------------|--------------------------------------------------------------------------------------------------|
| PSK        | AES-256-CBC + HMAC-SHA256 with a pre-shared key baked into the binary                           |
| EKE        | RSA-2048 staging - `staging_rsa` encrypted with PSK, session key negotiated via RSA (Linux only) |
| Plaintext  | No encryption - AESPSK left empty in C2 profile, for lab/testing use only                       |

### String Obfuscation

Two independent layers of string obfuscation:

| Layer | Scope | When active |
|-------|-------|-------------|
| `hidstr` compile-time XOR | All codebase strings - command names, C2 protocol keys (`checkin`, `get_tasking`, `staging_rsa`), system calls (`/bin/sh -c`, `cmd.exe /c`, `hostname`, `id -un`), env var names, OS/arch strings | Always |
| `obfuscation: xor/aes` | Config values only - C2 URL, UUID, PSK, kill date, user-agent | Build option |

`strings(1)` on the binary will not reveal command names, protocol keys, or system call strings.

### Sleep Interval

Tune the sleep interval and jitter according to your operational requirements. Higher sleep values reduce network noise at the cost of task responsiveness.

## Known Issues

### EKE - Linux Only

EKE (RSA-2048 staging) requires OpenSSL at build time and is currently only supported for Linux targets. Windows builds fall back to PSK mode automatically.

### Windows Cross-Compilation

Windows binaries are cross-compiled from Linux using mingw-w64. Some edge cases around Windows API behavior may differ from a natively compiled binary.

## TODO

### Browser Scripts

The following commands output plain text and could benefit from a structured table view in the Mythic UI. Each requires parsing the command output into JSON in the Nim agent and a matching JS browser script:

| Command    | Output to parse                        | Columns                                      |
|------------|----------------------------------------|----------------------------------------------|
| `netstat`  | `ss -tunap` / `netstat -ano`           | Proto, Local, Remote, State, PID/Process      |
| `ifconfig` | `ip addr` / `ipconfig /all`            | Interface, IP, Netmask, MAC, State            |
| `jobs`     | active interactive jobs                | Task ID, Command, Status                      |

## Credit

- [@0xbbuddha](https://github.com/0xbbuddha) - Author
