import std/json
import ../types
import ./registry

proc echoExecute(taskId: string, params: JsonNode, state: AgentState,
                 send: SendMsg): TaskResult =
  let text = params{"text"}.getStr("")
  return TaskResult(output: text, status: "success", completed: true)

proc initEcho*() =
  register("echo", echoExecute)
