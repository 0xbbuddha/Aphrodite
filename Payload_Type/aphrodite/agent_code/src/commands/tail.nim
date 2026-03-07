import std/[os, json, strutils]
import ../types
import ./registry

proc tailExecute(taskId: string, params: JsonNode, state: AgentState,
                 send: SendMsg): TaskResult =
  let path = params{"path"}.getStr("").strip()
  if path.len == 0:
    return TaskResult(output: "Error: path required", status: "error", completed: true)

  var n = 10
  let nStr = params{"lines"}.getStr("10")
  try: n = parseInt(nStr) except: discard

  let fullPath = if isAbsolute(path): path else: state.cwd / path
  if not fileExists(fullPath):
    return TaskResult(output: "File not found: " & fullPath,
                      status: "error", completed: true)
  try:
    let lines = readFile(fullPath).splitLines()
    let start = max(0, lines.len - n)
    return TaskResult(output: lines[start .. ^1].join("\n"),
                      status: "success", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initTail*() =
  register("tail", tailExecute)
