import std/[json, osproc]
import ../types
import ./registry

proc uptimeExecute(taskId: string, params: JsonNode, state: AgentState,
                   send: SendMsg): TaskResult =
  try:
    var output = ""
    when defined(windows):
      let (out1, _) = execCmdEx(
        "powershell -Command \"(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime\"",
        options = {poStdErrToStdOut})
      output = out1
    else:
      let (out1, _) = execCmdEx("uptime", options = {poStdErrToStdOut})
      output = out1
    return TaskResult(output: output, status: "success", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initUptime*() =
  register("uptime", uptimeExecute)
