import std/json
import ../types
import ./registry

proc exitExecute(taskId: string, params: JsonNode, state: AgentState,
                 send: SendMsg): TaskResult =
  state.running = false
  return TaskResult(output: "Agent exiting.", status: "success", completed: true)

proc initExit*() =
  register("exit", exitExecute)
