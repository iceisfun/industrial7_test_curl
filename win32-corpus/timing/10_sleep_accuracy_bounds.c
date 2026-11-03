/*
 * Test: timing_sleep_accuracy_bounds
 * Purpose: Bounds on Sleep(): Sleep(0) yields without blocking for long,
 *          each Sleep(10) never returns meaningfully early, and a batch of
 *          Sleep(10) calls accumulates the expected total.
 * APIs: Sleep, QueryPerformanceFrequency, QueryPerformanceCounter
 * Success: Sleep(0) returns in under 100 ms; each of 10 x Sleep(10) takes at
 *          least 8 ms and under 5 s (so the batch totals at least 80 ms);
 *          10 x Sleep(1) takes at least 5 ms (it does not return instantly).
 * Source: curl lib/curlx/wait.c:66-73 (Sleep((DWORD)timeout_ms) is the
 *         Windows implementation of curlx_wait_ms, so early returns would
 *         make curl spin on its timeouts).
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

static double us_between(LARGE_INTEGER a, LARGE_INTEGER b, LONGLONG freq)
{
  return ((double)(b.QuadPart - a.QuadPart) * 1000000.0) / (double)freq;
}

int main(void)
{
  LARGE_INTEGER f, a, b;
  double us;
  int i;

  if(!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) {
    printf("FAIL timing_sleep_accuracy_bounds: QueryPerformanceFrequency error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }

  if(!QueryPerformanceCounter(&a)) {
    printf("FAIL timing_sleep_accuracy_bounds: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  Sleep(0);
  if(!QueryPerformanceCounter(&b)) {
    printf("FAIL timing_sleep_accuracy_bounds: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  us = us_between(a, b, f.QuadPart);
  if(us > 100000.0) {
    printf("FAIL timing_sleep_accuracy_bounds: Sleep(0) took %.0f us\n", us);
    return 1;
  }

  for(i = 0; i < 10; i++) {
    if(!QueryPerformanceCounter(&a)) {
      printf("FAIL timing_sleep_accuracy_bounds: QueryPerformanceCounter error %lu\n",
             (unsigned long)GetLastError());
      return 1;
    }
    Sleep(10);
    if(!QueryPerformanceCounter(&b)) {
      printf("FAIL timing_sleep_accuracy_bounds: QueryPerformanceCounter error %lu\n",
             (unsigned long)GetLastError());
      return 1;
    }
    us = us_between(a, b, f.QuadPart);
    if(us < 8000.0) {
      printf("FAIL timing_sleep_accuracy_bounds: Sleep(10) #%d returned after %.0f us\n",
             i, us);
      return 1;
    }
    if(us > 5000000.0) {
      printf("FAIL timing_sleep_accuracy_bounds: Sleep(10) #%d took %.0f us\n", i, us);
      return 1;
    }
  }

  if(!QueryPerformanceCounter(&a)) {
    printf("FAIL timing_sleep_accuracy_bounds: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  for(i = 0; i < 10; i++)
    Sleep(1);
  if(!QueryPerformanceCounter(&b)) {
    printf("FAIL timing_sleep_accuracy_bounds: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  us = us_between(a, b, f.QuadPart);
  if(us < 5000.0) {
    printf("FAIL timing_sleep_accuracy_bounds: 10 x Sleep(1) returned in only %.0f us\n", us);
    return 1;
  }

  printf("PASS timing_sleep_accuracy_bounds\n");
  return 0;
}
