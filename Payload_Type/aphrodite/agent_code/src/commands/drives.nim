import std/[os, json, osproc]
import ../types
import ./registry

proc drivesExecute(taskId: string, params: JsonNode, state: AgentState,
                   send: SendMsg): TaskResult =
  try:
    when defined(windows):
      var found: seq[string] = @[]
      for letter in 'A'..'Z':
        let drive = $letter & ":\\"
        if dirExists(drive):
          found.add(drive)
      return TaskResult(output: found.join("\n"), status: "success", completed: true)
    else:
      let (output, _) = execCmdEx("df -h", options = {poStdErrToStdOut})
      return TaskResult(output: output, status: "success", completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initDrives*() =
  register("drives", drivesExecute)
