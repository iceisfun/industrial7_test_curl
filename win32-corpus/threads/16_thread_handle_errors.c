/*
 * Test: thread_handle_errors
 *
 * Purpose: error behaviour of thread handles that curl's join/destroy helpers
 * depend on (lib/curl_threads.c: Curl_thread_join waits on the handle and
 * closes it; Curl_thread_destroy closes it; a cleared handle must not be
 * waited on or closed again). Pins the exact last-error values for NULL,
 * bogus and already-closed handles, and the exit-code rules of
 * GetExitCodeThread / TerminateThread.
 *
 * APIs: CreateThread, WaitForSingleObject, CloseHandle, GetExitCodeThread,
 *   TerminateThread, GetLastError.
 *
 * Success (probed on Windows 10 22H2): WaitForSingleObject on NULL or on the
 * bogus handle value 0x1234 returns WAIT_FAILED with ERROR_INVALID_HANDLE
 * (6); CloseHandle(NULL), CloseHandle(0x1234) and a second CloseHandle on an
 * already closed thread handle return FALSE with 6; GetExitCodeThread on a
 * closed handle or NULL returns FALSE with 6. A thread that returned 7 reports
 * exit code 7 after a wait. A CREATE_SUSPENDED thread reports STILL_ACTIVE
 * (259) and, after TerminateThread(h, 99), exit code 99 once its handle is
 * signalled. CreateThread with a 2^62-byte stack reservation fails with
 * ERROR_INVALID_PARAMETER (87).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "thread_handle_errors"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static DWORD WINAPI worker(LPVOID p)
{
  (void)p;
  return 7;
}

int main(void)
{
  HANDLE h;
  DWORD ec = 0, w;
  BOOL b;

  SetLastError(0);
  w = WaitForSingleObject(NULL, 0);
  if(w != WAIT_FAILED || GetLastError() != ERROR_INVALID_HANDLE)
    FAILF("Wait(NULL) = 0x%lx GLE=%lu, expected WAIT_FAILED / 6", (unsigned long)w, (unsigned long)GetLastError());
  SetLastError(0);
  w = WaitForSingleObject((HANDLE)(ULONG_PTR)0x1234, 0);
  if(w != WAIT_FAILED || GetLastError() != ERROR_INVALID_HANDLE)
    FAILF("Wait(0x1234) = 0x%lx GLE=%lu, expected WAIT_FAILED / 6", (unsigned long)w, (unsigned long)GetLastError());
  SetLastError(0);
  if(CloseHandle(NULL) || GetLastError() != ERROR_INVALID_HANDLE)
    FAILF("CloseHandle(NULL) should fail with 6 (GLE=%lu)", (unsigned long)GetLastError());
  SetLastError(0);
  if(CloseHandle((HANDLE)(ULONG_PTR)0x1234) || GetLastError() != ERROR_INVALID_HANDLE)
    FAILF("CloseHandle(0x1234) should fail with 6 (GLE=%lu)", (unsigned long)GetLastError());

  h = CreateThread(NULL, 0, worker, NULL, 0, NULL);
  if(!h)
    FAILF("CreateThread failed (GLE=%lu)", (unsigned long)GetLastError());
  if(WaitForSingleObject(h, 10000) != WAIT_OBJECT_0)
    FAILF("worker did not finish");
  b = GetExitCodeThread(h, &ec);
  if(!b || ec != 7)
    FAILF("exit code %lu (ok=%d), expected 7", (unsigned long)ec, b);
  if(!CloseHandle(h))
    FAILF("CloseHandle on a finished thread failed");
  SetLastError(0);
  if(CloseHandle(h) || GetLastError() != ERROR_INVALID_HANDLE)
    FAILF("second CloseHandle should fail with 6 (GLE=%lu)", (unsigned long)GetLastError());
  SetLastError(0);
  if(GetExitCodeThread(h, &ec) || GetLastError() != ERROR_INVALID_HANDLE)
    FAILF("GetExitCodeThread on a closed handle should fail with 6 (GLE=%lu)", (unsigned long)GetLastError());
  SetLastError(0);
  if(GetExitCodeThread(NULL, &ec) || GetLastError() != ERROR_INVALID_HANDLE)
    FAILF("GetExitCodeThread(NULL) should fail with 6 (GLE=%lu)", (unsigned long)GetLastError());

  h = CreateThread(NULL, 0, worker, NULL, CREATE_SUSPENDED, NULL);
  if(!h)
    FAILF("CreateThread(CREATE_SUSPENDED) failed");
  ec = 0;
  if(!GetExitCodeThread(h, &ec) || ec != STILL_ACTIVE)
    FAILF("suspended thread exit code %lu, expected STILL_ACTIVE", (unsigned long)ec);
  if(!TerminateThread(h, 99))
    FAILF("TerminateThread failed (GLE=%lu)", (unsigned long)GetLastError());
  if(WaitForSingleObject(h, 10000) != WAIT_OBJECT_0)
    FAILF("terminated thread handle did not signal");
  if(!GetExitCodeThread(h, &ec) || ec != 99)
    FAILF("terminated thread exit code %lu, expected 99", (unsigned long)ec);
  CloseHandle(h);

  SetLastError(0);
  h = CreateThread(NULL, (SIZE_T)1 << 62, worker, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
  if(h || GetLastError() != ERROR_INVALID_PARAMETER) {
    if(h)
      CloseHandle(h);
    FAILF("huge stack reservation: handle=%p GLE=%lu, expected NULL / 87", (void *)h, (unsigned long)GetLastError());
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
