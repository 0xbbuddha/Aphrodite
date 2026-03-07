import std/[os, json, strutils]
import ../types
import ./registry

proc cdExecute(taskId: string, params: JsonNode, state: AgentState,
               send: SendMsg): TaskResult =
  let path = params{"path"}.getStr("").strip()
  if path.len == 0:
    return TaskResult(output: "Error: path required", status: "error", completed: true)

  let target = normalizedPath(
    if isAbsolute(path): path else: state.cwd / path
  )

  if not dirExists(target):
    return TaskResult(output: "No such directory: " & target,
                      status: "error", completed: true)

  state.cwd = target
  return TaskResult(output: target, status: "success", completed: true)

proc initCd*() =
  register("cd", cdExecute)
