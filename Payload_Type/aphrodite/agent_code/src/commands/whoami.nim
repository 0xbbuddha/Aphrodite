import std/json
import ../types
import ../utils
import ./registry

proc whoamiExecute(taskId: string, params: JsonNode, state: AgentState,
                   send: SendMsg): TaskResult =
  return TaskResult(
    output: getUsername() & "@" & getHostname(),
    status: "success",
    completed: true,
  )

proc initWhoami*() =
  register("whoami", whoamiExecute)
