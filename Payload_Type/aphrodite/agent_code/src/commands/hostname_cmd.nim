import std/json
import ../types
import ../utils
import ./registry

proc hostnameExecute(taskId: string, params: JsonNode, state: AgentState,
                     send: SendMsg): TaskResult =
  return TaskResult(output: getHostname(), status: "success", completed: true)

proc initHostname*() =
  register("hostname", hostnameExecute)
