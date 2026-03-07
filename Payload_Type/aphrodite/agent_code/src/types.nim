import std/json

type
  TaskResult* = object
    output*: string
    status*: string    ## "success" | "error"
    completed*: bool

  AgentState* = ref object
    cwd*: string
    sleepInterval*: int
    jitter*: int
    running*: bool

  ## Callback to send a message directly to Mythic (for chunked transfers etc.)
  SendMsg* = proc(msg: JsonNode): JsonNode

  ## Command handler signature
  CommandHandler* = proc(taskId: string, params: JsonNode, state: AgentState,
                          send: SendMsg): TaskResult
