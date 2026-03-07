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
NOTE: Requires PSK mode - uncheck 'Encrypted Key Exchange' in HTTP profile.
"""
    supports_dynamic_loading = False
    c2_profiles = ["http"]
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
                build_stderr += "Select the HTTP profile when creating the payload.\n"
                return BuildResponse(
                    status=BuildStatus.Error,
                    build_stdout=build_stdout,
                    build_stderr=build_stderr,
                )

            c2 = self.c2info[0]
            profile = c2.get_c2profile()
            profile_name = profile.get("name", "")
            if profile_name != "http":
                build_stderr += f"Aphrodite supports only the http C2 profile. Got: {profile_name}\n"
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
                    "Make sure the Mythic HTTP profile also has no encryption configured.\n"
                )

            if not use_psk:
                build_stderr += (
                    "WARNING: EKE (Encrypted Key Exchange) is not yet supported in Aphrodite.\n"
                    "Please uncheck 'Encrypted Key Exchange' in the HTTP profile settings.\n"
                    "The agent will attempt to use PSK mode.\n"
                )

            # --- Build base URL ---
            if "://" not in callback_host:
                callback_host = "http://" + callback_host
            host_part = callback_host.split("://")[1]
            if ":" in host_part:
                base_url = callback_host.rstrip("/")
            else:
                base_url = f"{callback_host.rstrip('/')}:{callback_port}"

            # --- Build parameters ---
            target_os = self.get_parameter("target_os") or "linux"
            architecture = self.get_parameter("architecture") or "amd64"
            debug = self.get_parameter("debug") or False

            build_stdout += f"[+] Step 1: Gathering files...\n"
            build_stdout += f"[*] Target: {target_os}/{architecture} | debug={debug}\n"
            build_stdout += f"[*] C2: {base_url}{post_uri} | interval={interval}s jitter={jitter}%\n"

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
                    interval=interval,
                    jitter=jitter,
                    killdate=killdate,
                    user_agent=user_agent,
                    aes_psk=aes_psk_b64,
                    use_psk=use_psk,
                    debug=debug,
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
                ]

                if debug:
                    nim_flags.append("-d:debug")
                else:
                    nim_flags.append("-d:release")
                    nim_flags.append("-d:strip")

                if target_os == "windows":
                    nim_flags += ["--os:windows", "--cpu:amd64", "-d:mingw"]
                    out_binary = os.path.join(tmpdir, "output", "aphrodite.exe")
                else:
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

    def _generate_config_nim(
        self, uuid, base_url, post_uri, interval, jitter,
        killdate, user_agent, aes_psk, use_psk, debug
    ) -> str:
        # Escape backslashes and quotes for Nim string literals
        def nim_str(s):
            return s.replace("\\", "\\\\").replace('"', '\\"')

        return f'''# config.nim - Auto-generated by Aphrodite builder. DO NOT EDIT MANUALLY.
const
  AgentUUID* = "{nim_str(uuid)}"
  C2BaseUrl* = "{nim_str(base_url)}"
  C2Endpoint* = "{nim_str(post_uri)}"
  SleepInterval* = {interval}
  JitterPercent* = {jitter}
  KillDate* = "{nim_str(killdate)}"
  UserAgent* = "{nim_str(user_agent)}"
  AesPsk* = "{nim_str(aes_psk)}"
  UsePsk* = {str(use_psk).lower()}
  DebugMode* = {str(debug).lower()}
'''
