import std/[os, json, strutils]
import ../types
import ./registry

proc mkdirExecute(taskId: string, params: JsonNode, state: AgentState,
                  send: SendMsg): TaskResult =
  let path = params{"path"}.getStr("").strip()
  if path.len == 0:
    return TaskResult(output: "Error: path required", status: "error", completed: true)

  let fullPath = if isAbsolute(path): path else: state.cwd / path
  try:
    createDir(fullPath)
    return TaskResult(output: "Created: " & fullPath, status: "success", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initMkdir*() =
  register("mkdir", mkdirExecute)
