/*
 * Test: create_thread_exit_code
 *
 * Purpose: CreateThread start routine receives its argument, the returned
 *   thread handle is waitable, GetExitCodeThread reports STILL_ACTIVE while the
 *   thread is blocked and the start routine's return value after it exits.
 *
 * APIs: CreateThread, WaitForSingleObject, GetExitCodeThread, CreateEventW,
 *   SetEvent, InterlockedExchange, CloseHandle.
 *
 * Success: thread is still active while gated (GetExitCodeThread == 259),
 *   WaitForSingleObject times out before the gate opens, after the gate opens
 *   the wait returns WAIT_OBJECT_0, the exit code is 42 and the side effect
 *   written through the argument is visible.
 *
 * curl reference: lib/curl_threads.c:35 (CreateThread(NULL, 0, func, arg, 0,
 *   NULL)) and lib/curl_threads.c:57 (join via WaitForSingleObjectEx INFINITE).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "create_thread_exit_code"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

typedef struct {
  HANDLE gate;
  LONG *value;
} ctx_t;

static DWORD WINAPI worker(LPVOID arg)
{
  ctx_t *c = (ctx_t *)arg;
  if(WaitForSingleObject(c->gate, 5000) != WAIT_OBJECT_0)
    return 1;
  InterlockedExchange(c->value, 7);
  return 42;
}

int main(void)
{
  ctx_t c;
  HANDLE th;
  DWORD code = 0, tid = 0;
  LONG value = 0;

  c.gate = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!c.gate)
    FAILF("CreateEventW failed (GLE=%lu)", GetLastError());
  c.value = &value;

  th = CreateThread(NULL, 0, worker, &c, 0, &tid);
  if(!th)
    FAILF("CreateThread failed (GLE=%lu)", GetLastError());
  if(tid == 0)
    FAILF("CreateThread returned thread id 0");

  if(WaitForSingleObject(th, 100) != WAIT_TIMEOUT)
    FAILF("thread exited before gate was opened (GLE=%lu)", GetLastError());

  if(!GetExitCodeThread(th, &code))
    FAILF("GetExitCodeThread failed while running (GLE=%lu)", GetLastError());
  if(code != STILL_ACTIVE)
    FAILF("GetExitCodeThread while blocked returned %lu, expected STILL_ACTIVE (259)", code);

  if(!SetEvent(c.gate))
    FAILF("SetEvent failed (GLE=%lu)", GetLastError());

  if(WaitForSingleObject(th, 5000) != WAIT_OBJECT_0)
    FAILF("WaitForSingleObject after gate did not return WAIT_OBJECT_0 (GLE=%lu)", GetLastError());

  code = 0;
  if(!GetExitCodeThread(th, &code))
    FAILF("GetExitCodeThread failed after exit (GLE=%lu)", GetLastError());
  if(code != 42)
    FAILF("exit code was %lu, expected 42", code);

  if(InterlockedCompareExchange(&value, 0, 0) != 7)
    FAILF("thread did not write through its argument (value=%ld)", (long)value);

  CloseHandle(th);
  CloseHandle(c.gate);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
