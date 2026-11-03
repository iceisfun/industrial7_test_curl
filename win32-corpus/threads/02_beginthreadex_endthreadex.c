/*
 * Test: beginthreadex_endthreadex
 *
 * Purpose: the CRT thread API (_beginthreadex/_endthreadex) starts a
 *   __stdcall routine, returns a waitable handle, reports the exit code
 *   returned both by a normal return and by an explicit _endthreadex, and keeps
 *   errno per-thread so the worker's errno does not leak into the caller.
 *
 * APIs: _beginthreadex, _endthreadex, WaitForSingleObject, GetExitCodeThread,
 *   GetCurrentThreadId, CloseHandle, errno.
 *
 * Success: both threads exit with the expected codes (1234 via return, 55 via
 *   _endthreadex), _beginthreadex gives a non-zero handle and thread id, and the
 *   main thread's errno is still 0 after the worker set its own errno.
 *
 * curl reference: none for the CRT path. curl does not call _beginthreadex or
 *   _endthreadex anywhere (grep of lib/ and src/ is empty); its Windows
 *   threads use CreateThread directly (lib/curl_threads.c:35). This test covers
 *   the CRT alternative so the corpus exercises both thread-creation APIs. The
 *   errno-from-creator behaviour that curl does depend on is at
 *   lib/curl_threads.c:38-40 and is covered by test 14.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <process.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#define TEST_NAME "beginthreadex_endthreadex"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static unsigned __stdcall ret_worker(void *arg)
{
  unsigned v = *(unsigned *)arg;
  errno = ERANGE; /* per-thread CRT errno, must not reach the main thread */
  if(v == 0)
    _endthreadex(55);
  return v;
}

int main(void)
{
  unsigned value = 1234;
  unsigned zero = 0;
  unsigned tid1 = 0, tid2 = 0;
  uintptr_t raw1, raw2;
  HANDLE h1, h2;
  DWORD code = 0;

  errno = 0;
  raw1 = _beginthreadex(NULL, 0, ret_worker, &value, 0, &tid1);
  if(raw1 == 0)
    FAILF("_beginthreadex failed (errno=%d GLE=%lu)", errno, GetLastError());
  h1 = (HANDLE)raw1;
  if(tid1 == 0 || tid1 == GetCurrentThreadId())
    FAILF("_beginthreadex reported bogus thread id %u", tid1);

  if(WaitForSingleObject(h1, 5000) != WAIT_OBJECT_0)
    FAILF("worker 1 did not finish (GLE=%lu)", GetLastError());
  if(!GetExitCodeThread(h1, &code))
    FAILF("GetExitCodeThread(1) failed (GLE=%lu)", GetLastError());
  if(code != 1234)
    FAILF("worker 1 exit code %lu, expected 1234 (return path)", code);

  if(errno != 0)
    FAILF("main thread errno leaked from worker: %d (expected 0)", errno);
  CloseHandle(h1);

  raw2 = _beginthreadex(NULL, 0, ret_worker, &zero, 0, &tid2);
  if(raw2 == 0)
    FAILF("second _beginthreadex failed (errno=%d GLE=%lu)", errno, GetLastError());
  h2 = (HANDLE)raw2;
  if(WaitForSingleObject(h2, 5000) != WAIT_OBJECT_0)
    FAILF("worker 2 did not finish (GLE=%lu)", GetLastError());
  code = 0;
  if(!GetExitCodeThread(h2, &code))
    FAILF("GetExitCodeThread(2) failed (GLE=%lu)", GetLastError());
  if(code != 55)
    FAILF("worker 2 exit code %lu, expected 55 (_endthreadex path)", code);
  CloseHandle(h2);

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
