## reg — Windows registry query / add / delete / enum (Windows only).
import std/[json, strutils, base64]
import core/types
import commands/registry
import crypto/strenc

when defined(windows):
  type
    HANDLE = int
    HKEY   = HANDLE
    DWORD  = uint32
    LONG   = int32
    REGSAM = DWORD
    LPVOID = pointer

  const
    HKEY_CLASSES_ROOT   = HKEY(cast[int32](0x80000000'u32))
    HKEY_CURRENT_USER   = HKEY(cast[int32](0x80000001'u32))
    HKEY_LOCAL_MACHINE  = HKEY(cast[int32](0x80000002'u32))
    HKEY_USERS          = HKEY(cast[int32](0x80000003'u32))
    HKEY_CURRENT_CONFIG = HKEY(cast[int32](0x80000005'u32))

    KEY_READ       = REGSAM(0x00020019)
    KEY_WRITE      = REGSAM(0x00020006)

    REG_SZ         = DWORD(1)
    REG_EXPAND_SZ  = DWORD(2)
    REG_BINARY     = DWORD(3)
    REG_DWORD      = DWORD(4)
    REG_MULTI_SZ   = DWORD(7)
    REG_QWORD      = DWORD(11)

    ERROR_SUCCESS       = LONG(0)
    ERROR_NO_MORE_ITEMS = LONG(259)

  proc RegOpenKeyExA(hKey: HKEY, lpSubKey: cstring, ulOptions: DWORD,
                     samDesired: REGSAM, phkResult: ptr HKEY): LONG
    {.importc: "RegOpenKeyExA", dynlib: "advapi32".}

  proc RegCreateKeyExA(hKey: HKEY, lpSubKey: cstring, Reserved: DWORD,
                       lpClass: cstring, dwOptions: DWORD, samDesired: REGSAM,
                       lpSecurityAttr: pointer, phkResult: ptr HKEY,
                       lpdwDisposition: ptr DWORD): LONG
    {.importc: "RegCreateKeyExA", dynlib: "advapi32".}

  proc RegQueryValueExA(hKey: HKEY, lpValueName: cstring, lpReserved: ptr DWORD,
                        lpType: ptr DWORD, lpData: pointer,
                        lpcbData: ptr DWORD): LONG
    {.importc: "RegQueryValueExA", dynlib: "advapi32".}

  proc RegSetValueExA(hKey: HKEY, lpValueName: cstring, Reserved: DWORD,
                      dwType: DWORD, lpData: pointer, cbData: DWORD): LONG
    {.importc: "RegSetValueExA", dynlib: "advapi32".}

  proc RegDeleteValueA(hKey: HKEY, lpValueName: cstring): LONG
    {.importc: "RegDeleteValueA", dynlib: "advapi32".}

  proc RegDeleteKeyA(hKey: HKEY, lpSubKey: cstring): LONG
    {.importc: "RegDeleteKeyA", dynlib: "advapi32".}

  proc RegEnumKeyExA(hKey: HKEY, dwIndex: DWORD, lpName: cstring,
                     lpcchName: ptr DWORD, lpReserved: ptr DWORD,
                     lpClass: cstring, lpcchClass: ptr DWORD,
                     lpftLastWriteTime: pointer): LONG
    {.importc: "RegEnumKeyExA", dynlib: "advapi32".}

  proc RegEnumValueA(hKey: HKEY, dwIndex: DWORD, lpValueName: cstring,
                     lpcchValueName: ptr DWORD, lpReserved: ptr DWORD,
                     lpType: ptr DWORD, lpData: pointer,
                     lpcbData: ptr DWORD): LONG
    {.importc: "RegEnumValueA", dynlib: "advapi32".}

  proc RegCloseKey(hKey: HKEY): LONG
    {.importc: "RegCloseKey", dynlib: "advapi32".}

  # ---------------------------------------------------------------------------

  proc typeStr(t: DWORD): string =
    case t
    of REG_SZ:        "REG_SZ"
    of REG_EXPAND_SZ: "REG_EXPAND_SZ"
    of REG_BINARY:    "REG_BINARY"
    of REG_DWORD:     "REG_DWORD"
    of REG_MULTI_SZ:  "REG_MULTI_SZ"
    of REG_QWORD:     "REG_QWORD"
    else:             "REG_TYPE_" & $t

  proc parseHive(name: string): HKEY =
    case name.toUpper()
    of "HKLM", "HKEY_LOCAL_MACHINE":   HKEY_LOCAL_MACHINE
    of "HKCU", "HKEY_CURRENT_USER":    HKEY_CURRENT_USER
    of "HKCR", "HKEY_CLASSES_ROOT":    HKEY_CLASSES_ROOT
    of "HKU",  "HKEY_USERS":           HKEY_USERS
    of "HKCC", "HKEY_CURRENT_CONFIG":  HKEY_CURRENT_CONFIG
    else: HKEY(0)

  proc splitPath(fullPath: string): tuple[hive: HKEY, subKey: string] =
    let sep = fullPath.find('\\')
    if sep < 0: return (parseHive(fullPath), "")
    return (parseHive(fullPath[0 ..< sep]), fullPath[sep+1 .. ^1])

  proc dataToStr(data: seq[byte], dataSize: DWORD, t: DWORD): string =
    case t
    of REG_SZ, REG_EXPAND_SZ:
      for i in 0 ..< int(dataSize):
        if data[i] == 0: break
        result.add(char(data[i]))
    of REG_DWORD:
      if int(dataSize) >= 4:
        let v = uint32(data[0]) or (uint32(data[1]) shl 8) or
                (uint32(data[2]) shl 16) or (uint32(data[3]) shl 24)
        result = $v
      else: result = "0"
    of REG_QWORD:
      if int(dataSize) >= 8:
        var v: uint64 = 0
        for i in 0 ..< 8: v = v or (uint64(data[i]) shl (i * 8))
        result = $v
      else: result = "0"
    of REG_MULTI_SZ:
      var parts: seq[string] = @[]
      var cur = ""
      for i in 0 ..< int(dataSize):
        if data[i] == 0:
          if cur.len > 0: parts.add(cur); cur = ""
        else: cur.add(char(data[i]))
      result = parts.join("\\0")
    else:
      var s = newString(int(dataSize))
      if dataSize > 0: copyMem(addr s[0], unsafeAddr data[0], int(dataSize))
      result = encode(s)

  # ---------------------------------------------------------------------------

  proc regDoQuery(hive: HKEY, subKey: string, valueName: string): JsonNode =
    var hKey: HKEY
    if RegOpenKeyExA(hive, subKey.cstring, 0, KEY_READ, addr hKey) != ERROR_SUCCESS:
      return %*{"error": "Failed to open key"}
    var dataType, dataSize: DWORD
    if RegQueryValueExA(hKey, valueName.cstring, nil, addr dataType, nil, addr dataSize) != ERROR_SUCCESS:
      discard RegCloseKey(hKey)
      return %*{"error": "Value not found: " & valueName}
    var data = newSeq[byte](int(dataSize) + 1)
    let r = RegQueryValueExA(hKey, valueName.cstring, nil, addr dataType,
                             addr data[0], addr dataSize)
    discard RegCloseKey(hKey)
    if r != ERROR_SUCCESS:
      return %*{"error": "Failed to read value"}
    return %*{"action": "query", "value": valueName,
              "type": typeStr(dataType), "data": dataToStr(data, dataSize, dataType)}

  proc regDoAdd(hive: HKEY, subKey: string, valueName: string,
                valueType: string, valueData: string): JsonNode =
    var hKey: HKEY
    var disp: DWORD = 0
    if RegCreateKeyExA(hive, subKey.cstring, 0, nil, 0, KEY_WRITE, nil,
                       addr hKey, addr disp) != ERROR_SUCCESS:
      return %*{"error": "Failed to open/create key"}
    var ret: LONG
    let vt = valueType.toUpper()
    case vt
    of "REG_DWORD":
      var v: uint32
      try: v = uint32(parseUInt(valueData)) except: v = 0
      ret = RegSetValueExA(hKey, valueName.cstring, 0, REG_DWORD, addr v, DWORD(4))
    of "REG_BINARY":
      let dec = decode(valueData)
      var data = newSeq[byte](dec.len)
      for i, c in dec: data[i] = byte(ord(c))
      let p = if data.len > 0: addr data[0] else: nil
      ret = RegSetValueExA(hKey, valueName.cstring, 0, REG_BINARY, p, DWORD(data.len))
    of "REG_EXPAND_SZ":
      let s = valueData & "\x00"
      ret = RegSetValueExA(hKey, valueName.cstring, 0, REG_EXPAND_SZ,
                           unsafeAddr s[0], DWORD(s.len))
    else: # REG_SZ default
      let s = valueData & "\x00"
      ret = RegSetValueExA(hKey, valueName.cstring, 0, REG_SZ,
                           unsafeAddr s[0], DWORD(s.len))
    discard RegCloseKey(hKey)
    if ret != ERROR_SUCCESS:
      return %*{"error": "Failed to write value (error " & $ret & ")"}
    return %*{"action": "add", "status": "success", "value": valueName,
              "type": (if vt.len > 0: vt else: "REG_SZ")}

  proc regDoDelete(hive: HKEY, subKey: string, valueName: string): JsonNode =
    if valueName.len > 0:
      var hKey: HKEY
      if RegOpenKeyExA(hive, subKey.cstring, 0, KEY_WRITE, addr hKey) != ERROR_SUCCESS:
        return %*{"error": "Failed to open key"}
      let r = RegDeleteValueA(hKey, valueName.cstring)
      discard RegCloseKey(hKey)
      if r != ERROR_SUCCESS:
        return %*{"error": "Failed to delete value (error " & $r & ")"}
    else:
      let sep = subKey.rfind('\\')
      let parentPath = if sep < 0: "" else: subKey[0 ..< sep]
      let keyName    = if sep < 0: subKey else: subKey[sep+1 .. ^1]
      var hParent: HKEY
      var opened: bool
      if parentPath.len > 0:
        opened = RegOpenKeyExA(hive, parentPath.cstring, 0, KEY_WRITE, addr hParent) == ERROR_SUCCESS
      else:
        hParent = hive
        opened  = true
      if not opened:
        return %*{"error": "Failed to open parent key"}
      let r = RegDeleteKeyA(hParent, keyName.cstring)
      if parentPath.len > 0: discard RegCloseKey(hParent)
      if r != ERROR_SUCCESS:
        return %*{"error": "Failed to delete key (error " & $r & ")"}
    return %*{"action": "delete", "status": "success"}

  proc regDoEnum(hive: HKEY, subKey: string): JsonNode =
    var hKey: HKEY
    if RegOpenKeyExA(hive, subKey.cstring, 0, KEY_READ, addr hKey) != ERROR_SUCCESS:
      return %*{"error": "Failed to open key"}
    var subkeys = newJArray()
    var values  = newJArray()
    # Subkeys
    var idx: DWORD = 0
    while true:
      var nameBuf = newString(256)
      var nameLen = DWORD(256)
      if RegEnumKeyExA(hKey, idx, nameBuf.cstring, addr nameLen,
                       nil, nil, nil, nil) != ERROR_SUCCESS: break
      subkeys.add(%($(nameBuf.cstring)))
      inc idx
    # Values
    idx = 0
    while true:
      var valName    = newString(512)
      var valNameLen = DWORD(512)
      var dataType, dataSize: DWORD
      let r = RegEnumValueA(hKey, idx, valName.cstring, addr valNameLen,
                            nil, addr dataType, nil, addr dataSize)
      if r == ERROR_NO_MORE_ITEMS: break
      if r != ERROR_SUCCESS: break
      var data = newSeq[byte](int(dataSize) + 1)
      var vn2  = newString(512)
      var vl2  = DWORD(512)
      discard RegEnumValueA(hKey, idx, vn2.cstring, addr vl2,
                            nil, addr dataType, addr data[0], addr dataSize)
      let name = $(valName.cstring)
      values.add(%*{
        "name": (if name.len == 0: "(Default)" else: name),
        "type": typeStr(dataType),
        "data": dataToStr(data, dataSize, dataType),
      })
      inc idx
    discard RegCloseKey(hKey)
    return %*{"action": "enum", "subkeys": subkeys, "values": values}

# ---------------------------------------------------------------------------

proc regExecute(taskId: string, params: JsonNode, state: AgentState,
                send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: "reg is Windows-only", status: "error", completed: true)
  else:
    let action    = params{"action"}.getStr("query").toLower()
    let keyPath   = params{"key"}.getStr("").strip()
    let valueName = params{"value"}.getStr("")
    let valueData = params{"data"}.getStr("")
    let valueType = params{"type"}.getStr("REG_SZ")

    if keyPath.len == 0:
      return TaskResult(output: "{\"error\":\"key parameter required\"}",
                        status: "error", completed: true)

    let (hive, subKey) = splitPath(keyPath)
    if hive == HKEY(0):
      return TaskResult(output: "{\"error\":\"unknown hive in: " & keyPath & "\"}",
                        status: "error", completed: true)

    let jResult =
      case action
      of "query":  regDoQuery(hive, subKey, valueName)
      of "add":    regDoAdd(hive, subKey, valueName, valueType, valueData)
      of "delete": regDoDelete(hive, subKey, valueName)
      of "enum":   regDoEnum(hive, subKey)
      else: %*{"error": "unknown action: " & action}

    return TaskResult(
      output:    $jResult,
      status:    if jResult.hasKey("error"): "error" else: "success",
      completed: true,
    )

proc initReg*() =
  register(hidstr("reg"), regExecute)
