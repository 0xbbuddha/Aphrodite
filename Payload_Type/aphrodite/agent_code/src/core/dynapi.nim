## Dynamic API resolution - resolves Windows API functions at runtime via
## GetModuleHandleA + GetProcAddress so they never appear in the PE IAT.
## All function name strings are passed obfuscated via hidstr().
import crypto/strenc

when defined(windows):
  type
    HANDLE* = int

  proc GetModuleHandleA(n: cstring): HANDLE
    {.importc: "GetModuleHandleA", dynlib: "kernel32".}
  proc GetProcAddress(h: HANDLE, n: cstring): pointer
    {.importc: "GetProcAddress", dynlib: "kernel32".}

  proc resolveK32*(fnName: string): pointer =
    let modName = hidstr("kernel32.dll")
    let h = GetModuleHandleA(modName.cstring)
    if h == 0: return nil
    result = GetProcAddress(h, fnName.cstring)

  proc resolveNtdll*(fnName: string): pointer =
    let modName = hidstr("ntdll.dll")
    let h = GetModuleHandleA(modName.cstring)
    if h == 0: return nil
    result = GetProcAddress(h, fnName.cstring)
