## SOCKS5 CONNECT request parser (RFC 1928).
##
## NOTE: Mythic handles the SOCKS5 greeting/auth exchange with the client.
## The first datagram the agent receives for a new server_id is already the
## CONNECT request (VER=5, CMD=1, RSV=0, ATYP, addr, port).
import std/[net, strutils]

type
  ConnTarget* = object
    host*: string
    port*: int

proc socks5ParseConnect*(data: string): tuple[target: ConnTarget, ok: bool] =
  ## Parse a SOCKS5 CONNECT request.
  ## Returns (target, true) on success, (_, false) on bad / incomplete data.
  if data.len < 7:
    return (ConnTarget(), false)
  if byte(data[0]) != 0x05 or byte(data[1]) != 0x01:
    return (ConnTarget(), false)

  let atyp = byte(data[3])
  case atyp

  of 0x01:  ## IPv4 (4 bytes addr + 2 bytes port)
    if data.len < 10: return (ConnTarget(), false)
    let ip = $byte(data[4]) & "." & $byte(data[5]) & "." &
             $byte(data[6]) & "." & $byte(data[7])
    let port = (uint16(byte(data[8])) shl 8) or uint16(byte(data[9]))
    return (ConnTarget(host: ip, port: int(port)), true)

  of 0x03:  ## Domain name (1 byte length + N bytes + 2 bytes port)
    let nameLen = int(byte(data[4]))
    if data.len < 5 + nameLen + 2: return (ConnTarget(), false)
    let host = data[5 ..< 5 + nameLen]
    ## Leave host as-is; Socket.connect() resolves names via getAddrInfo internally
    let port = (uint16(byte(data[5 + nameLen])) shl 8) or
               uint16(byte(data[6 + nameLen]))
    return (ConnTarget(host: host, port: int(port)), true)

  of 0x04:  ## IPv6 (16 bytes addr + 2 bytes port)
    if data.len < 22: return (ConnTarget(), false)
    var parts: seq[string]
    for i in 0 .. 7:
      let val = (uint16(byte(data[4 + i * 2])) shl 8) or
                uint16(byte(data[5 + i * 2]))
      parts.add(toHex(int(val), 4))
    let ip = parts.join(":")
    let port = (uint16(byte(data[20])) shl 8) or uint16(byte(data[21]))
    return (ConnTarget(host: "[" & ip & "]", port: int(port)), true)

  else:
    return (ConnTarget(), false)

proc socks5ConnectReply*(success: bool): string =
  ## SOCKS5 server reply to CONNECT request.
  ## BND.ADDR = 0.0.0.0, BND.PORT = 0 (we don't expose our bind address).
  if success:
    "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
  else:
    "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"  ## host unreachable
