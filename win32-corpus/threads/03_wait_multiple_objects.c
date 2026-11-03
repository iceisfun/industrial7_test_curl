/*
 * Test: wait_multiple_objects
 *
 * Purpose: WaitForMultipleObjects semantics that curl's multi/poll code and
 *   thread-join helpers depend on: timeout, index of the signaled object,
 *   lowest-index tie break, wait-all semantics, mixed event and thread
 *   handles, and rejection of more than MAXIMUM_WAIT_OBJECTS handles.
 *
 * APIs: WaitForMultipleObjects, WaitForSingleObject, CreateEventW, SetEvent,
 *   CreateThread, GetExitCodeThread, CloseHandle.
 *
 * Success: any-wait returns WAIT_TIMEOUT with nothing signaled, the index of the
 *   signaled event, lowest index on a tie; wait-all returns WAIT_TIMEOUT until
 *   every event is signaled and then WAIT_OBJECT_0; a thread handle in the set
 *   wakes the wait after roughly its runtime; 65 handles fail with
 *   ERROR_INVALID_PARAMETER.
 *
 * curl reference: lib/curl_threads.c:57 joins a worker by waiting on its
 *   thread handle (WaitForSingleObjectEx with INFINITE). This test covers the
 *   multi-handle form of the same wait; curl itself only waits on one handle.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#define TEST_NAME "wait_multiple_objects"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static double now_ms(void)
{
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
}

static DWORD WINAPI sleeper(LPVOID p)
{
  Sleep((DWORD)(uintptr_t)p);
  return 0;
}

int main(void)
{
  HANDLE ev[3];
  HANDLE many[65];
  HANDLE all2[2];
  HANDLE th;
  DWORD r, i;
  double t0;

  for(i = 0; i < 3; i++) {
    /* auto-reset events, not signaled */
    ev[i] = CreateEventW(NULL, FALSE, FALSE, NULL);
    if(!ev[i])
      FAILF("CreateEventW(%lu) failed (GLE=%lu)", i, GetLastError());
  }

  /* 1. nothing signaled: zero timeout returns WAIT_TIMEOUT */
  r = WaitForMultipleObjects(3, ev, FALSE, 0);
  if(r != WAIT_TIMEOUT)
    FAILF("wait-any on unsignaled set returned %lu, expected WAIT_TIMEOUT (GLE=%lu)", r, GetLastError());

  /* 2. one signaled: index is reported */
  if(!SetEvent(ev[1]))
    FAILF("SetEvent(ev[1]) failed (GLE=%lu)", GetLastError());
  r = WaitForMultipleObjects(3, ev, FALSE, 1000);
  if(r != WAIT_OBJECT_0 + 1)
    FAILF("wait-any returned %lu, expected WAIT_OBJECT_0+1", r);

  /* auto-reset was consumed by the successful wait */
  r = WaitForMultipleObjects(3, ev, FALSE, 0);
  if(r != WAIT_TIMEOUT)
    FAILF("auto-reset event still signaled after consumption (r=%lu)", r);

  /* 3. two signaled: lowest index wins, the other stays signaled */
  if(!SetEvent(ev[2]) || !SetEvent(ev[0]))
    FAILF("SetEvent for tie-break setup failed (GLE=%lu)", GetLastError());
  r = WaitForMultipleObjects(3, ev, FALSE, 1000);
  if(r != WAIT_OBJECT_0 + 0)
    FAILF("tie-break returned %lu, expected index 0", r);
  r = WaitForMultipleObjects(3, ev, FALSE, 1000);
  if(r != WAIT_OBJECT_0 + 2)
    FAILF("second wait returned %lu, expected index 2 (still signaled)", r);

  /* 4. wait-all with manual-reset events */
  all2[0] = CreateEventW(NULL, TRUE, FALSE, NULL);
  all2[1] = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!all2[0] || !all2[1])
    FAILF("CreateEventW for wait-all failed (GLE=%lu)", GetLastError());
  SetEvent(all2[0]);
  r = WaitForMultipleObjects(2, all2, TRUE, 50);
  if(r != WAIT_TIMEOUT)
    FAILF("wait-all with one of two signaled returned %lu, expected WAIT_TIMEOUT", r);
  SetEvent(all2[1]);
  r = WaitForMultipleObjects(2, all2, TRUE, 1000);
  if(r != WAIT_OBJECT_0)
    FAILF("wait-all with both signaled returned %lu, expected WAIT_OBJECT_0", r);

  /* 5. mixed thread handle and event: thread finishes after ~120ms */
  th = CreateThread(NULL, 0, sleeper, (LPVOID)(uintptr_t)120, 0, NULL);
  if(!th)
    FAILF("CreateThread failed (GLE=%lu)", GetLastError());
  {
    HANDLE mix[2];
    mix[0] = ev[1]; /* not signaled now: auto reset consumed above */
    mix[1] = th;
    t0 = now_ms();
    r = WaitForMultipleObjects(2, mix, FALSE, 3000);
    if(r != WAIT_OBJECT_0 + 1)
      FAILF("mixed wait returned %lu, expected WAIT_OBJECT_0+1 (thread)", r);
    if(now_ms() - t0 < 90.0)
      FAILF("mixed wait returned after %.1f ms, thread sleeps 120 ms", now_ms() - t0);
  }
  CloseHandle(th);

  /* 6. more than MAXIMUM_WAIT_OBJECTS (64) must fail */
  for(i = 0; i < 65; i++)
    many[i] = ev[0];
  r = WaitForMultipleObjects(65, many, FALSE, 0);
  if(r != WAIT_FAILED)
    FAILF("65-handle wait returned %lu, expected WAIT_FAILED", r);
  if(GetLastError() != ERROR_INVALID_PARAMETER)
    FAILF("65-handle wait GLE=%lu, expected ERROR_INVALID_PARAMETER (87)", GetLastError());

  for(i = 0; i < 3; i++)
    CloseHandle(ev[i]);
  CloseHandle(all2[0]);
  CloseHandle(all2[1]);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
