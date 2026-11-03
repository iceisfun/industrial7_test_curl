/*
 * Test: timing_qpc_frequency
 * Purpose: QueryPerformanceFrequency returns a positive, stable tick rate.
 * APIs: QueryPerformanceFrequency
 * Success: every call returns TRUE, the frequency is > 0 and plausible
 *          (<= 1e12 ticks/s), and it is identical across 1000 calls.
 * Source: curl lib/curlx/timeval.c:32-35 (curlx_now_init stores the
 *         frequency) and lib/curlx/timeval.c:38-48 (curlx_pnow divides
 *         the counter by it; a zero frequency is a division by zero).
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

int main(void)
{
  LARGE_INTEGER f0, f;
  int i;

  if(!QueryPerformanceFrequency(&f0)) {
    printf("FAIL timing_qpc_frequency: QueryPerformanceFrequency error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  if(f0.QuadPart <= 0 || f0.QuadPart > 1000000000000LL) {
    printf("FAIL timing_qpc_frequency: implausible frequency %lld\n",
           (long long)f0.QuadPart);
    return 1;
  }

  for(i = 0; i < 1000; i++) {
    if(!QueryPerformanceFrequency(&f)) {
      printf("FAIL timing_qpc_frequency: call %d error %lu\n", i,
             (unsigned long)GetLastError());
      return 1;
    }
    if(f.QuadPart != f0.QuadPart) {
      printf("FAIL timing_qpc_frequency: frequency changed on call %d: %lld -> %lld\n",
             i, (long long)f0.QuadPart, (long long)f.QuadPart);
      return 1;
    }
  }

  printf("PASS timing_qpc_frequency\n");
  return 0;
}
