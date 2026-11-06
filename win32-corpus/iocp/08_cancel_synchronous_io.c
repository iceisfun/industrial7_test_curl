/*
 * 08_cancel_synchronous_io
 *
 * Purpose: abort a thread that is blocked in a synchronous (non-overlapped)
 *   ReadFile, using CancelSynchronousIo on the thread handle. This is how a
 *   blocking reader is woken for shutdown without closing the handle.
 * APIs: CreatePipe (non-overlapped), CreateThread, ReadFile (synchronous),
 *   CancelSynchronousIo, WaitForSingleObject, GetExitCodeThread, CloseHandle.
 * Success: CancelSynchronousIo returns TRUE while the reader is blocked
 *   (retried until the reader has entered ReadFile; ERROR_NOT_FOUND is the
 *   expected answer before that). The reader's ReadFile then fails with
 *   ERROR_OPERATION_ABORTED and transfers 0 bytes, and the thread exits.
 *   The API exists on every supported Windows; any error other than ERROR_NOT_FOUND is a FAIL.
 * Source: none. Generic Win32 contract. curl does not call this API.
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
#include <stdlib.h>
#include <string.h>

#define TEST_NAME "08_cancel_synchronous_io"

static volatile LONG g_started = 0;
static volatile LONG g_read_err = -1;
static volatile LONG g_read_bytes = -1;
static HANDLE g_rd;

static void fail_exit(const char *why, DWORD gle)
{
  printf("FAIL %s: %s (gle=%lu)\n", TEST_NAME, why, (unsigned long)gle);
  exit(1);
}

static DWORD WINAPI reader_thread(LPVOID arg)
{
  char buf[16];
  DWORD n = 0;
  BOOL ok;
  (void)arg;

  InterlockedExchange(&g_started, 1);
  ok = ReadFile(g_rd, buf, sizeof buf, &n, NULL);
  InterlockedExchange(&g_read_bytes, (LONG)n);
  InterlockedExchange(&g_read_err, ok ? 0 : (LONG)GetLastError());
  return 0;
}

int main(void)
{
  HANDLE rd = NULL, wr = NULL, th;
  DWORD waited = 0, tid = 0;
  int attempts = 0;
  BOOL cancelled = FALSE;

  if(!CreatePipe(&rd, &wr, NULL, 0))
    fail_exit("CreatePipe", GetLastError());
  g_rd = rd;

  th = CreateThread(NULL, 0, reader_thread, NULL, 0, &tid);
  if(!th)
    fail_exit("CreateThread", GetLastError());

  /* Wait until the reader has started, then give it time to block. */
  while(!g_started && waited < 5000) {
    Sleep(1);
    waited++;
  }
  if(!g_started)
    fail_exit("reader thread never started", 0);
  Sleep(100);

  /* ERROR_NOT_FOUND means "no synchronous I/O pending on that thread yet". */
  for(attempts = 0; attempts < 500 && !cancelled; attempts++) {
    SetLastError(0);
    if(CancelSynchronousIo(th)) {
      cancelled = TRUE;
      break;
    }
    if(GetLastError() != ERROR_NOT_FOUND)
      fail_exit("CancelSynchronousIo", GetLastError());
    Sleep(10);
  }
  if(!cancelled)
    fail_exit("CancelSynchronousIo never found the blocked read", 0);

  if(WaitForSingleObject(th, 5000) != WAIT_OBJECT_0)
    fail_exit("reader thread did not exit after cancel", GetLastError());

  if(g_read_err != ERROR_OPERATION_ABORTED) {
    printf("FAIL %s: reader ReadFile error=%ld expected ERROR_OPERATION_ABORTED (%ld)\n",
           TEST_NAME, (long)g_read_err, (long)ERROR_OPERATION_ABORTED);
    return 1;
  }
  if(g_read_bytes != 0) {
    printf("FAIL %s: cancelled read transferred %ld bytes\n", TEST_NAME,
           (long)g_read_bytes);
    return 1;
  }

  CloseHandle(th);
  CloseHandle(rd);
  CloseHandle(wr);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
