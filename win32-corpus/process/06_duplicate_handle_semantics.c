/*
 * Test: 06_duplicate_handle_semantics
 *
 * Purpose: verify DuplicateHandle semantics that curl's Windows code depends
 *   on: a duplicated pipe write end keeps the pipe alive after the original
 *   is closed (EOF only after the last writer closes); DUPLICATE_CLOSE_SOURCE
 *   moves ownership of an event handle; a reduced-access duplicate still
 *   refers to the same kernel object; and GetCurrentProcess() pseudo-handles
 *   duplicate into real process handles that report our pid.
 *
 * APIs: CreatePipe, DuplicateHandle (DUPLICATE_SAME_ACCESS, DUPLICATE_CLOSE_SOURCE,
 *   reduced access), GetCurrentProcess, CloseHandle, WriteFile, ReadFile,
 *   CreateEventW, SetEvent, ResetEvent, WaitForSingleObject, GetProcessId,
 *   GetCurrentProcessId.
 *
 * Success means: data written through the duplicate arrives at the reader;
 *   ReadFile fails with ERROR_BROKEN_PIPE only after the last writer handle is
 *   closed; after DUPLICATE_CLOSE_SOURCE the source value fails SetEvent with
 *   ERROR_INVALID_HANDLE whenever the reused value differs from the duplicate
 *   (the check is skipped when the two values coincide, see the code); signalling through the reduced-access
 *   duplicate is observed by the full-access handle; the process pseudo-handle
 *   duplicate reports our own pid.
 *
 * Source reference: src/tool_doswin.c:922 (DuplicateHandle(GetCurrentProcess(),
 *   GetStdHandle(STD_INPUT_HANDLE), GetCurrentProcess(), &h, 0, FALSE,
 *   DUPLICATE_SAME_ACCESS)) which duplicates a stdin handle and relies on the
 *   original pipe staying readable.
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define NAME "duplicate_handle_semantics"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

static int run(void)
{
  HANDLE rd = NULL, wr = NULL, wr2 = NULL;
  HANDLE ev = NULL, ev2 = NULL, ev3 = NULL, ph = NULL;
  char buf[16];
  DWORD got = 0, n = 0;

  /* 1. Duplicate a pipe write end, close the original: pipe stays open. */
  if(!CreatePipe(&rd, &wr, NULL, 0))
    FAILF("CreatePipe");
  if(!DuplicateHandle(GetCurrentProcess(), wr, GetCurrentProcess(), &wr2,
                      0, FALSE, DUPLICATE_SAME_ACCESS))
    FAILF("DuplicateHandle(pipe write end)");
  CloseHandle(wr);
  wr = NULL;

  if(!WriteFile(wr2, "dup", 3, &n, NULL) || n != 3)
    FAILF("WriteFile through duplicate");
  if(!ReadFile(rd, buf, 3, &got, NULL) || got != 3 || memcmp(buf, "dup", 3) != 0)
    FAILF("read through pipe after original closed (got %lu bytes)",
          (unsigned long)got);

  /* Only the duplicate is left as a writer; closing it yields EOF. */
  CloseHandle(wr2);
  wr2 = NULL;
  if(ReadFile(rd, buf, 3, &got, NULL))
    FAILF("ReadFile succeeded after the last writer closed (got %lu)", (unsigned long)got);
  if(GetLastError() != ERROR_BROKEN_PIPE)
    FAILF("ReadFile after last writer closed: expected ERROR_BROKEN_PIPE");
  CloseHandle(rd);
  rd = NULL;

  /* 2. DUPLICATE_CLOSE_SOURCE transfers ownership of an event. */
  ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!ev)
    FAILF("CreateEventW");
  if(!DuplicateHandle(GetCurrentProcess(), ev, GetCurrentProcess(), &ev2,
                      0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE))
    FAILF("DuplicateHandle(DUPLICATE_CLOSE_SOURCE)");
  /*
   * The closed source slot may be reused for the new duplicate (Wine does this),
   * so the stale value can alias ev2. Two distinct open handles never share a
   * value, so ev == ev2 can only happen if the source was really closed. When the
   * values differ, the source must now be invalid; if CLOSE_SOURCE were ignored,
   * the values would differ and the SetEvent check below would fail.
   */
  if(ev != ev2) {
    SetLastError(0);
    if(SetEvent(ev))
      FAILF("source event handle still valid after DUPLICATE_CLOSE_SOURCE");
    if(GetLastError() != ERROR_INVALID_HANDLE)
      FAILF("SetEvent on closed source: expected ERROR_INVALID_HANDLE");
  }
  if(!SetEvent(ev2))
    FAILF("SetEvent(ev2)");
  if(WaitForSingleObject(ev2, 1000) != WAIT_OBJECT_0)
    FAILF("ev2 not signalled");
  ResetEvent(ev2);

  /* 3. Reduced-access duplicate refers to the same kernel object. */
  if(!DuplicateHandle(GetCurrentProcess(), ev2, GetCurrentProcess(), &ev3,
                      EVENT_MODIFY_STATE, FALSE, 0))
    FAILF("DuplicateHandle(EVENT_MODIFY_STATE)");
  if(WaitForSingleObject(ev2, 0) != WAIT_TIMEOUT)
    FAILF("event unexpectedly signalled before SetEvent(ev3)");
  if(!SetEvent(ev3))
    FAILF("SetEvent(ev3)");
  if(WaitForSingleObject(ev2, 1000) != WAIT_OBJECT_0)
    FAILF("SetEvent via reduced duplicate not visible through ev2");

  /* 4. Duplicate of the current-process pseudo handle is a real handle to us. */
  if(!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(),
                      &ph, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0))
    FAILF("DuplicateHandle(GetCurrentProcess pseudo handle)");
  if(GetProcessId(ph) != GetCurrentProcessId())
    FAILF("GetProcessId(dup of self)=%lu, GetCurrentProcessId=%lu",
          (unsigned long)GetProcessId(ph), (unsigned long)GetCurrentProcessId());

  CloseHandle(ph);
  CloseHandle(ev3);
  CloseHandle(ev2);
  return 0;
}

int main(void)
{
  int rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
