import std/[json, osproc, strutils]
import ../types
import ./registry

proc killExecute(taskId: string, params: JsonNode, state: AgentState,
                 send: SendMsg): TaskResult =
  let pidStr = params{"pid"}.getStr("")
  if pidStr.len == 0:
    return TaskResult(output: "Error: pid required", status: "error", completed: true)

  var pid: int
  try:
    pid = parseInt(pidStr)
  except ValueError:
    return TaskResult(output: "Error: invalid pid: " & pidStr,
                      status: "error", completed: true)
  try:
    when defined(windows):
      let (output, code) = execCmdEx("taskkill /F /PID " & $pid,
                                      options = {poStdErrToStdOut})
      if code == 0:
        return TaskResult(output: "Killed PID " & $pid,
                          status: "success", completed: true)
      else:
        return TaskResult(output: output.strip(), status: "error", completed: true)
    else:
      let (output, code) = execCmdEx("kill -9 " & $pid,
                                      options = {poStdErrToStdOut})
      if code == 0:
        return TaskResult(output: "Killed PID " & $pid,
                          status: "success", completed: true)
      else:
        return TaskResult(output: output.strip(), status: "error", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initKill*() =
  register("kill", killExecute)
