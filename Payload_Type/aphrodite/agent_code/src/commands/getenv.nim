import std/[os, json, strutils]
import ../types
import ./registry

proc getenvExecute(taskId: string, params: JsonNode, state: AgentState,
                   send: SendMsg): TaskResult =
  let name = params{"name"}.getStr("").strip()
  if name.len == 0:
    return TaskResult(output: "Error: name required", status: "error", completed: true)

  let val = getEnv(name, "")
  if val.len == 0:
    return TaskResult(output: name & " is not set", status: "success", completed: true)
  return TaskResult(output: name & "=" & val, status: "success", completed: true)

proc initGetenv*() =
  register("getenv", getenvExecute)
