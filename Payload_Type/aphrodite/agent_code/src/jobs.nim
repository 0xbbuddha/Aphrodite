## Background job manager for interactive shell sessions.
## Each job runs a shell process; a reader thread drains stdout into a channel.
import std/[osproc, locks, streams]

const MaxJobs* = 16

## Parallel arrays — avoids GC issues when sharing data with threads.
var jTaskId:  array[MaxJobs, string]
var jProcess: array[MaxJobs, Process]
var jAlive:   array[MaxJobs, bool]
var jOutChan: array[MaxJobs, Channel[string]]
var jThread:  array[MaxJobs, Thread[int]]
var jCount:   int = 0
var jLock:    Lock
initLock(jLock)

for i in 0 ..< MaxJobs:
  jOutChan[i].open()

# ---------------------------------------------------------------------------

proc readerProc(idx: int) {.thread.} =
  ## Reads stdout of the process at slot [idx] and pushes chunks to jOutChan.
  var buf: array[4096, uint8]
  while jAlive[idx]:
    {.cast(gcsafe).}:
      try:
        let n = jProcess[idx].outputStream.readData(addr buf[0], buf.len)
        if n <= 0:
          jAlive[idx] = false
          break
        var chunk = newString(n)
        copyMem(addr chunk[0], addr buf[0], n)
        jOutChan[idx].send(chunk)
      except:
        jAlive[idx] = false
        break

# ---------------------------------------------------------------------------

proc jobStart*(taskId: string, process: Process): bool =
  ## Register a new job. Returns false if the table is full.
  withLock(jLock):
    if jCount >= MaxJobs:
      return false
    let i = jCount
    inc jCount
    jTaskId[i]  = taskId
    jProcess[i] = process
    jAlive[i]   = true
    createThread(jThread[i], readerProc, i)
    return true

proc jobFindIdx(taskId: string): int {.inline.} =
  for i in 0 ..< jCount:
    if jAlive[i] and jTaskId[i] == taskId:
      return i
  return -1

proc jobIsAlive*(taskId: string): bool =
  jobFindIdx(taskId) >= 0

proc jobDrainOutput*(taskId: string): string =
  ## Returns all buffered output for the job, clearing the buffer.
  let i = jobFindIdx(taskId)
  if i < 0: return ""
  result = ""
  while true:
    let r = jOutChan[i].tryRecv()
    if not r.dataAvailable: break
    result.add(r.msg)

proc jobWriteInput*(taskId: string, data: string) =
  ## Writes data to the shell's stdin.
  let i = jobFindIdx(taskId)
  if i < 0: return
  {.cast(gcsafe).}:
    try:
      jProcess[i].inputStream.write(data)
      jProcess[i].inputStream.flush()
    except: discard

proc jobKill*(taskId: string) =
  ## Terminate the shell process.
  withLock(jLock):
    let i = jobFindIdx(taskId)
    if i < 0: return
    jAlive[i] = false
    try: jProcess[i].terminate() except: discard

proc jobActiveList*(): seq[string] =
  ## Returns task IDs of all currently alive jobs.
  for i in 0 ..< jCount:
    if jAlive[i]:
      result.add(jTaskId[i])

proc jobPid*(taskId: string): int =
  let i = jobFindIdx(taskId)
  if i < 0: return -1
  {.cast(gcsafe).}:
    return jProcess[i].processID
