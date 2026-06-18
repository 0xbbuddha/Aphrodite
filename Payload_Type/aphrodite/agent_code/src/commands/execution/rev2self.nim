import std/json
import core/types
import commands/registry
import crypto/strenc
import commands/execution/token_mgr

when defined(windows):
  type
    HANDLE = int
    BOOL   = int32

  proc RevertToSelf(): BOOL
    {.importc: "RevertToSelf", dynlib: "advapi32".}
  proc CloseHandle(h: HANDLE): BOOL
    {.importc: "CloseHandle", dynlib: "kernel32".}

proc rev2selfExecute(taskId: string, params: JsonNode,
                     state: AgentState, send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: hidstr("rev2self: Windows only"),
                      status: "error", completed: true)
  else:
    if RevertToSelf() == 0:
      return TaskResult(output: hidstr("Error: RevertToSelf failed"),
                        status: "error", completed: true)
    if gImpersonatedToken != 0:
      discard CloseHandle(gImpersonatedToken)
      gImpersonatedToken = 0
    return TaskResult(
      output: hidstr("Reverted to self - impersonation dropped"),
      status: "success", completed: true)

proc initRev2Self*() =
  register(hidstr("rev2self"), rev2selfExecute)
