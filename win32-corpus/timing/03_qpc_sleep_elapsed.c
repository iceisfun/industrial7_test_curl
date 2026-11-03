/*
 * Test: timing_qpc_sleep_elapsed
 * Purpose: Measure real elapsed time across Sleep() with the high
 *          resolution counter, the way curl measures elapsed time between
 *          its own wait cycles.
 * APIs: QueryPerformanceFrequency, QueryPerformanceCounter, Sleep
 * Success: Sleep(50) elapses between 40 ms and 5 s by QPC; ten Sleep(5)
 *          calls together elapse at least 40 ms. A counter that does not
 *          advance, or a Sleep that returns immediately, is a FAIL.
 * Source: curl lib/curlx/wait.c:54-73 (curlx_wait_ms uses Sleep() when no
 *         sockets are involved) and lib/curlx/timeval.c:38-48 (elapsed time
 *         is computed from QPC).
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

static double elapsed_us(LARGE_INTEGER a, LARGE_INTEGER b, LONGLONG freq)
{
  return ((double)(b.QuadPart - a.QuadPart) * 1000000.0) / (double)freq;
}

int main(void)
{
  LARGE_INTEGER f, t0, t1;
  double us;
  int i;

  if(!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) {
    printf("FAIL timing_qpc_sleep_elapsed: QueryPerformanceFrequency error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }

  if(!QueryPerformanceCounter(&t0)) {
    printf("FAIL timing_qpc_sleep_elapsed: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  Sleep(50);
  if(!QueryPerformanceCounter(&t1)) {
    printf("FAIL timing_qpc_sleep_elapsed: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  us = elapsed_us(t0, t1, f.QuadPart);
  if(us < 40000.0) {
    printf("FAIL timing_qpc_sleep_elapsed: Sleep(50) returned after only %.0f us\n", us);
    return 1;
  }
  if(us > 5000000.0) {
    printf("FAIL timing_qpc_sleep_elapsed: Sleep(50) took %.0f us (over 5 s)\n", us);
    return 1;
  }

  if(!QueryPerformanceCounter(&t0)) {
    printf("FAIL timing_qpc_sleep_elapsed: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  for(i = 0; i < 10; i++)
    Sleep(5);
  if(!QueryPerformanceCounter(&t1)) {
    printf("FAIL timing_qpc_sleep_elapsed: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  us = elapsed_us(t0, t1, f.QuadPart);
  if(us < 40000.0) {
    printf("FAIL timing_qpc_sleep_elapsed: 10 x Sleep(5) returned after only %.0f us\n", us);
    return 1;
  }

  printf("PASS timing_qpc_sleep_elapsed\n");
  return 0;
}
