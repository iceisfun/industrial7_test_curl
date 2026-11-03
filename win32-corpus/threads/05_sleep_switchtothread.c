/*
 * Test: sleep_switchtothread
 *
 * Purpose: Sleep blocks for at least the requested time, Sleep(0) returns
 *   promptly, and SwitchToThread lets a cooperative spin loop make progress
 *   while another thread that it depends on is runnable. This is the yielding
 *   pattern used by curl's Windows code when it spins briefly on a lock or a
 *   socket-state flag.
 *
 * APIs: Sleep, SwitchToThread, CreateThread, WaitForSingleObject,
 *   QueryPerformanceCounter, InterlockedExchange, InterlockedCompareExchange.
 *
 * Success: Sleep(100) elapses >= 90 ms, Sleep(0) returns within 50 ms, and
 *   the SwitchToThread spin loop observes the flag set by the helper thread
 *   within 5 s. SwitchToThread must return a BOOL (nonzero or zero, never
 *   crash), and the helper flag must actually be set by the helper.
 *
 * curl reference: lib/cf-socket.c:950-965 explains that on Windows a
 *   zero-length yield (SleepEx(0, FALSE), at line 965) lets other threads run
 *   after a connect-failure path. This test checks the same class of yield
 *   primitives (Sleep(0), SwitchToThread) on their own; it does not model
 *   curl's connect path.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "sleep_switchtothread"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static double now_ms(void)
{
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
}

static volatile LONG helper_flag = 0;

static DWORD WINAPI helper(LPVOID p)
{
  (void)p;
  Sleep(20);
  InterlockedExchange(&helper_flag, 1);
  return 0;
}

int main(void)
{
  double t0, elapsed;
  HANDLE th;
  BOOL sw;

  /* 1. Sleep(100) must not return early */
  t0 = now_ms();
  Sleep(100);
  elapsed = now_ms() - t0;
  if(elapsed < 90.0)
    FAILF("Sleep(100) returned after only %.1f ms", elapsed);

  /* 2. Sleep(0) yields and returns quickly */
  t0 = now_ms();
  Sleep(0);
  elapsed = now_ms() - t0;
  if(elapsed > 50.0)
    FAILF("Sleep(0) took %.1f ms", elapsed);

  /* 3. SwitchToThread spin until the helper thread sets the flag */
  th = CreateThread(NULL, 0, helper, NULL, 0, NULL);
  if(!th)
    FAILF("CreateThread failed (GLE=%lu)", GetLastError());

  t0 = now_ms();
  while(InterlockedCompareExchange(&helper_flag, 0, 0) == 0) {
    sw = SwitchToThread();
    (void)sw; /* result depends on scheduler state; only progress matters */
    if(now_ms() - t0 > 5000.0) {
      CloseHandle(th);
      FAILF("SwitchToThread spin never observed helper flag (GLE=%lu)", GetLastError());
    }
  }
  elapsed = now_ms() - t0;
  if(elapsed < 10.0)
    FAILF("helper flag observed after %.1f ms, helper sleeps 20 ms", elapsed);

  if(WaitForSingleObject(th, 5000) != WAIT_OBJECT_0)
    FAILF("helper thread did not exit (GLE=%lu)", GetLastError());
  CloseHandle(th);

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
