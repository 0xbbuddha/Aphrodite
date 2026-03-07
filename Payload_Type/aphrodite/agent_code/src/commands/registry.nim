import std/[tables, json]
import ../types

var registry = initTable[string, CommandHandler]()

proc register*(name: string, handler: CommandHandler) =
  registry[name] = handler

proc dispatch*(name: string, taskId: string, params: JsonNode,
               state: AgentState, send: SendMsg): TaskResult =
  if name in registry:
    try:
      return registry[name](taskId, params, state, send)
    except Exception as e:
      return TaskResult(
        output: "Exception in '" & name & "': " & e.msg,
        status: "error",
        completed: true,
      )
  else:
    return TaskResult(
      output: "Unknown command: " & name,
      status: "error",
      completed: true,
    )
