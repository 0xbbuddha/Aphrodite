import std/json
import core/types
import commands/registry
import crypto/strenc

proc exitExecute(taskId: string, params: JsonNode, state: AgentState,
                 send: SendMsg): TaskResult =
  # Setting running=false causes the main loop in agent.nim to exit, which
  # triggers the secure memory wipe of aesKey and mythicID on the AphroditeAgent.
  state.running = false
  return TaskResult(output: "Agent exiting.", status: "success", completed: true)

proc initExit*() =
  register(hidstr("exit"), exitExecute)
