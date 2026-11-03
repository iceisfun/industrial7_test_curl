/*
 * Test: timed_wait_timeout
 *
 * Purpose: WaitForSingleObject / WaitForSingleObjectEx with finite timeouts on
 *   events and on running threads, the timing bounds of a timeout, and
 *   alertable waits woken by a user APC (WAIT_IO_COMPLETION).
 *
 * APIs: WaitForSingleObject, WaitForSingleObjectEx, CreateEventW, SetEvent,
 *   CreateThread, GetExitCodeThread, QueueUserAPC, QueryPerformanceCounter,
 *   InterlockedExchange, CloseHandle.
 *
 * Success: a 200 ms wait on an unsignaled event returns WAIT_TIMEOUT after
 *   180..3000 ms, a 0 ms wait returns immediately, a 100 ms wait on a 400 ms
 *   thread returns WAIT_TIMEOUT and the later 5 s wait returns WAIT_OBJECT_0
 *   with exit code 9, a finite wait on an auto-reset event is satisfied by a
 *   SetEvent issued 100 ms later,
 *   an alertable wait on the helper is interrupted by a queued APC and returns
 *   WAIT_IO_COMPLETION (0xC0) with the APC argument delivered.
 *
 * curl reference: lib/curl_threads.c:57 (Curl_thread_join uses
 *   WaitForSingleObjectEx(*hnd, INFINITE, FALSE)); this test uses the finite
 *   and alertable variants of the same call.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "timed_wait_timeout"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static double now_ms(void)
{
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
}

static volatile LONG apc_arg = 0;

static VOID CALLBACK user_apc(ULONG_PTR arg)
{
  InterlockedExchange(&apc_arg, (LONG)arg);
}

static DWORD WINAPI slow_thread(LPVOID p)
{
  (void)p;
  Sleep(400);
  return 9;
}

static DWORD WINAPI alertable_waiter(LPVOID p)
{
  HANDLE ev = (HANDLE)p;
  DWORD r = WaitForSingleObjectEx(ev, 5000, TRUE);
  return r;
}

static DWORD WINAPI delayed_setter(LPVOID p)
{
  Sleep(100);
  SetEvent((HANDLE)p);
  return 0;
}

int main(void)
{
  HANDLE never, th, alert_ev, waiter;
  double t0, elapsed;
  DWORD code = 0;

  /* 1. timed wait on an unsignaled event */
  never = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!never)
    FAILF("CreateEventW failed (GLE=%lu)", GetLastError());
  t0 = now_ms();
  if(WaitForSingleObject(never, 200) != WAIT_TIMEOUT)
    FAILF("200 ms wait on unsignaled event did not return WAIT_TIMEOUT (GLE=%lu)", GetLastError());
  elapsed = now_ms() - t0;
  if(elapsed < 180.0 || elapsed > 3000.0)
    FAILF("200 ms timed wait took %.1f ms", elapsed);

  /* 2. zero timeout returns at once */
  t0 = now_ms();
  if(WaitForSingleObject(never, 0) != WAIT_TIMEOUT)
    FAILF("zero-timeout wait did not return WAIT_TIMEOUT");
  if(now_ms() - t0 > 100.0)
    FAILF("zero-timeout wait blocked for %.1f ms", now_ms() - t0);

  /* 3. timeout on a running thread, then completion */
  th = CreateThread(NULL, 0, slow_thread, NULL, 0, NULL);
  if(!th)
    FAILF("CreateThread(slow) failed (GLE=%lu)", GetLastError());
  t0 = now_ms();
  if(WaitForSingleObject(th, 100) != WAIT_TIMEOUT)
    FAILF("100 ms wait on 400 ms thread did not time out");
  elapsed = now_ms() - t0;
  if(elapsed < 80.0)
    FAILF("thread wait returned after only %.1f ms", elapsed);
  if(WaitForSingleObject(th, 5000) != WAIT_OBJECT_0)
    FAILF("thread did not complete within 5 s (GLE=%lu)", GetLastError());
  if(!GetExitCodeThread(th, &code) || code != 9)
    FAILF("slow thread exit code %lu, expected 9", code);
  CloseHandle(th);
  CloseHandle(never);

  /* 4. infinite-style wait satisfied by a delayed SetEvent */
  alert_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
  if(!alert_ev)
    FAILF("CreateEventW(delayed) failed (GLE=%lu)", GetLastError());
  th = CreateThread(NULL, 0, delayed_setter, alert_ev, 0, NULL);
  if(!th)
    FAILF("CreateThread(setter) failed (GLE=%lu)", GetLastError());
  if(WaitForSingleObject(alert_ev, 5000) != WAIT_OBJECT_0)
    FAILF("delayed SetEvent did not satisfy wait (GLE=%lu)", GetLastError());
  WaitForSingleObject(th, 5000);
  CloseHandle(th);
  CloseHandle(alert_ev);

  /* 5. alertable wait interrupted by a queued user APC */
  alert_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
  if(!alert_ev)
    FAILF("CreateEventW(alert) failed (GLE=%lu)", GetLastError());
  waiter = CreateThread(NULL, 0, alertable_waiter, alert_ev, 0, NULL);
  if(!waiter)
    FAILF("CreateThread(alertable) failed (GLE=%lu)", GetLastError());
  Sleep(50);
  if(!QueueUserAPC(user_apc, waiter, 0x1234))
    FAILF("QueueUserAPC failed (GLE=%lu)", GetLastError());
  if(WaitForSingleObject(waiter, 5000) != WAIT_OBJECT_0)
    FAILF("alertable waiter did not finish (GLE=%lu)", GetLastError());
  if(!GetExitCodeThread(waiter, &code))
    FAILF("GetExitCodeThread(alertable) failed (GLE=%lu)", GetLastError());
  if(code != WAIT_IO_COMPLETION)
    FAILF("alertable wait returned %lu, expected WAIT_IO_COMPLETION (192)", code);
  if(InterlockedCompareExchange(&apc_arg, 0, 0) != 0x1234)
    FAILF("APC argument not delivered (got 0x%lx)", (unsigned long)apc_arg);
  CloseHandle(waiter);
  CloseHandle(alert_ev);

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
