import std/[json, osproc]
import ../types
import ./registry

proc psExecute(taskId: string, params: JsonNode, state: AgentState,
               send: SendMsg): TaskResult =
  try:
    when defined(windows):
      let (output, _) = execCmdEx("tasklist /FO CSV /NH",
                                   options = {poStdErrToStdOut})
    else:
      let (output, _) = execCmdEx("ps aux", options = {poStdErrToStdOut})
    return TaskResult(output: output, status: "success", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initPs*() =
  register("ps", psExecute)
