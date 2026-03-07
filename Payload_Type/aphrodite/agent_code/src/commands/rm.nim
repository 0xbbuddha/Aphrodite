import std/[os, json, strutils]
import ../types
import ./registry

proc rmExecute(taskId: string, params: JsonNode, state: AgentState,
               send: SendMsg): TaskResult =
  let path = params{"path"}.getStr("").strip()
  if path.len == 0:
    return TaskResult(output: "Error: path required", status: "error", completed: true)

  let fullPath = if isAbsolute(path): path else: state.cwd / path
  try:
    if fileExists(fullPath):
      removeFile(fullPath)
    elif dirExists(fullPath):
      removeDir(fullPath)
    else:
      return TaskResult(output: "No such file or directory: " & fullPath,
                        status: "error", completed: true)
    return TaskResult(output: "Removed: " & fullPath, status: "success", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initRm*() =
  register("rm", rmExecute)
