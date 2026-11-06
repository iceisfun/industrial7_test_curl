/*
 * Test: 14_pipe_eof_broken_pipe
 *
 * Purpose: check the EOF and error paths of anonymous pipes, which curl's
 *   child-process and wakeup code depend on. PeekNamedPipe must report the
 *   number of buffered bytes without consuming them; a partial ReadFile must
 *   return exactly the requested bytes; after the writer closes and the buffer
 *   drains, ReadFile fails with ERROR_BROKEN_PIPE (EOF); writing after the
 *   reader closed must fail with ERROR_NO_DATA (232; probed on Win10 22H2).
 *
 * APIs: CreatePipe, PeekNamedPipe, WriteFile, ReadFile, CloseHandle,
 *   GetLastError.
 *
 * Success means: PeekNamedPipe on an empty pipe reports 0 bytes available and
 *   after writing "xyz" reports 3 without consuming; ReadFile(2) yields "xy",
 *   ReadFile(10) yields "z"; the next ReadFile fails with ERROR_BROKEN_PIPE;
 *   WriteFile to a pipe whose read end is closed fails with ERROR_NO_DATA
 *   (232).
 *
 * Source reference: no direct pipe-EOF call site was found in lib/, src/ or
 *   tests/. The stdin pipe that src/tool_doswin.c:922 duplicates is the
 *   reader side this EOF behaviour applies to.
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

#define NAME "pipe_eof_broken_pipe"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

static int run(void)
{
  HANDLE rd = NULL, wr = NULL;
  DWORD avail = 0xFFFFFFFF, got = 0, n = 0, err;
  char buf[16];

  /* 1. Empty pipe: PeekNamedPipe reports zero available bytes. */
  if(!CreatePipe(&rd, &wr, NULL, 0))
    FAILF("CreatePipe");
  if(!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL))
    FAILF("PeekNamedPipe(empty)");
  if(avail != 0)
    FAILF("PeekNamedPipe(empty) reports %lu bytes", (unsigned long)avail);

  /* 2. PeekNamedPipe sees data without consuming it. */
  if(!WriteFile(wr, "xyz", 3, &n, NULL) || n != 3)
    FAILF("WriteFile(xyz)");
  avail = 0;
  if(!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL))
    FAILF("PeekNamedPipe(3 bytes)");
  if(avail != 3)
    FAILF("PeekNamedPipe reports %lu bytes, expected 3", (unsigned long)avail);

  /* 3. Partial reads return exactly what was asked for, then what remains. */
  if(!ReadFile(rd, buf, 2, &got, NULL) || got != 2 || memcmp(buf, "xy", 2) != 0)
    FAILF("ReadFile(2) did not return \"xy\" (got %lu)", (unsigned long)got);
  if(!ReadFile(rd, buf, 10, &got, NULL) || got != 1 || buf[0] != 'z')
    FAILF("ReadFile(10) did not return the remaining \"z\" (got %lu)", (unsigned long)got);

  /* 4. Writer closed and buffer empty: EOF is ERROR_BROKEN_PIPE. */
  CloseHandle(wr);
  wr = NULL;
  SetLastError(0);
  if(ReadFile(rd, buf, sizeof(buf), &got, NULL))
    FAILF("ReadFile succeeded at EOF (got %lu bytes)", (unsigned long)got);
  err = GetLastError();
  if(err != ERROR_BROKEN_PIPE)
    FAILF("ReadFile at EOF: error %lu, expected ERROR_BROKEN_PIPE (109)", (unsigned long)err);
  CloseHandle(rd);
  rd = NULL;

  /* 5. Reader closed: writing must fail. */
  if(!CreatePipe(&rd, &wr, NULL, 0))
    FAILF("CreatePipe(second)");
  CloseHandle(rd);
  rd = NULL;
  SetLastError(0);
  if(WriteFile(wr, "a", 1, &n, NULL))
    FAILF("WriteFile succeeded with no reader");
  err = GetLastError();
  if(err != ERROR_NO_DATA)
    FAILF("WriteFile with no reader: error %lu, expected ERROR_NO_DATA (232)",
          (unsigned long)err);
  CloseHandle(wr);

  return 0;
}

int main(void)
{
  int rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
