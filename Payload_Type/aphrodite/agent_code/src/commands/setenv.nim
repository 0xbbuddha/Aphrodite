import std/[os, json, strutils]
import ../types
import ./registry

proc setenvExecute(taskId: string, params: JsonNode, state: AgentState,
                   send: SendMsg): TaskResult =
  let name  = params{"name"}.getStr("").strip()
  let value = params{"value"}.getStr("")
  if name.len == 0:
    return TaskResult(output: "Error: name required", status: "error", completed: true)

  try:
    putEnv(name, value)
    return TaskResult(output: "Set " & name & "=" & value,
                      status: "success", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initSetenv*() =
  register("setenv", setenvExecute)
