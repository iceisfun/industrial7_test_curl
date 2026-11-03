/*
 * Test: timing_gettickcount64_monotonic
 * Purpose: GetTickCount64 is monotonic, advances by about the slept
 *          duration, agrees with QPC within timer granularity, and its low
 *          32 bits agree with the legacy GetTickCount (wrap-safe compare).
 * APIs: GetTickCount64, GetTickCount, QueryPerformanceFrequency,
 *       QueryPerformanceCounter, Sleep
 * Success: 1000 consecutive GetTickCount64 reads never decrease; a
 *          Sleep(200) advances GetTickCount64 by at least 180 ms and at
 *          most 5 s, and within 50 ms of the QPC measurement; low-32-bit
 *          GetTickCount differs from GetTickCount64 by at most 50 ms.
 * Source: curl does not call GetTickCount64 or GetTickCount; its Windows
 *         monotonic clock is QPC (lib/curlx/timeval.c:38-48). This test
 *         checks the tick-count family as an independent monotonic source.
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

static long long absll(long long v)
{
  return v < 0 ? -v : v;
}

int main(void)
{
  ULONGLONG a, b, t0, t1;
  DWORD g0, g1;
  LARGE_INTEGER f, q0, q1;
  long long tick_ms, qpc_ms;
  int i;

  if(!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) {
    printf("FAIL timing_gettickcount64_monotonic: QueryPerformanceFrequency error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }

  a = GetTickCount64();
  if(a == 0) {
    printf("FAIL timing_gettickcount64_monotonic: GetTickCount64 returned 0 (error %lu)\n",
           (unsigned long)GetLastError());
    return 1;
  }
  for(i = 0; i < 1000; i++) {
    b = GetTickCount64();
    if(b < a) {
      printf("FAIL timing_gettickcount64_monotonic: decreased on read %d (%llu < %llu)\n",
             i, (unsigned long long)b, (unsigned long long)a);
      return 1;
    }
    a = b;
  }

  t0 = GetTickCount64();
  g0 = GetTickCount();
  if(!QueryPerformanceCounter(&q0)) {
    printf("FAIL timing_gettickcount64_monotonic: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  Sleep(200);
  t1 = GetTickCount64();
  g1 = GetTickCount();
  if(!QueryPerformanceCounter(&q1)) {
    printf("FAIL timing_gettickcount64_monotonic: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }

  tick_ms = (long long)(t1 - t0);
  qpc_ms = (long long)((q1.QuadPart - q0.QuadPart) * 1000 / f.QuadPart);
  if(tick_ms < 180 || tick_ms > 5000) {
    printf("FAIL timing_gettickcount64_monotonic: Sleep(200) advanced GetTickCount64 by %lld ms\n",
           tick_ms);
    return 1;
  }
  if(absll(tick_ms - qpc_ms) > 50) {
    printf("FAIL timing_gettickcount64_monotonic: GetTickCount64 delta %lld ms disagrees with QPC %lld ms\n",
           tick_ms, qpc_ms);
    return 1;
  }

  /* Wrap-safe comparison of the legacy 32-bit counter. */
  {
    DWORD legacy_delta = g1 - g0;
    if(absll((long long)legacy_delta - tick_ms) > 50) {
      printf("FAIL timing_gettickcount64_monotonic: GetTickCount delta %lu ms disagrees with GetTickCount64 delta %lld ms\n",
             (unsigned long)legacy_delta, tick_ms);
      return 1;
    }
  }

  printf("PASS timing_gettickcount64_monotonic\n");
  return 0;
}
