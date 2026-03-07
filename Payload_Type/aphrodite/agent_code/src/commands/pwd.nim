import std/json
import ../types
import ./registry

proc pwdExecute(taskId: string, params: JsonNode, state: AgentState,
                send: SendMsg): TaskResult =
  return TaskResult(output: state.cwd, status: "success", completed: true)

proc initPwd*() =
  register("pwd", pwdExecute)
