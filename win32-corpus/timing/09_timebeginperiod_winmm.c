/*
 * Test: timing_timebeginperiod_winmm
 * Purpose: Multimedia timer resolution: query the device capabilities,
 *          raise the timer resolution with timeBeginPeriod, and verify that
 *          timeGetTime and Sleep observe the finer granularity; then restore
 *          it with timeEndPeriod.
 * APIs: timeGetDevCaps, timeBeginPeriod, timeEndPeriod, timeGetTime (winmm),
 *       Sleep, QueryPerformanceCounter
 * Success: timeGetDevCaps returns MMSYSERR_NOERROR with 0 < wPeriodMin <=
 *          wPeriodMax; timeBeginPeriod(wPeriodMin) returns TIMERR_NOERROR
 *          (or the test SKIPs on TIMERR_NOCANDO); timeGetTime advances by at
 *          least 25 ms across Sleep(30); 20 x Sleep(1) completes in under
 *          250 ms in at least one of up to three batches (a stuck 15.6 ms
 *          tick would take about 312 ms in every batch); timeEndPeriod
 *          returns TIMERR_NOERROR.
 * Source: curl lib/curlx/wait.c:73 (Sleep() is the wait primitive used for
 *         curl's timeouts; its granularity follows timeBeginPeriod). Winmm
 *         is linked directly since it is in the mingw import library set.
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
#include <mmsystem.h>
#include <stdio.h>

int main(void)
{
  TIMECAPS tc;
  MMRESULT r;
  DWORD t0, t1, dt;
  LARGE_INTEGER f, q0, q1;
  double ms, best_ms;
  int i, attempt;

  r = timeGetDevCaps(&tc, sizeof(tc));
  if(r != MMSYSERR_NOERROR) {
    printf("FAIL timing_timebeginperiod_winmm: timeGetDevCaps returned %u\n", (unsigned)r);
    return 1;
  }
  if(tc.wPeriodMin == 0 || tc.wPeriodMin > tc.wPeriodMax) {
    printf("FAIL timing_timebeginperiod_winmm: bad timer range %u..%u ms\n",
           (unsigned)tc.wPeriodMin, (unsigned)tc.wPeriodMax);
    return 1;
  }

  r = timeBeginPeriod(tc.wPeriodMin);
  if(r == TIMERR_NOCANDO) {
    printf("SKIP timing_timebeginperiod_winmm: timer resolution %u ms not supported\n",
           (unsigned)tc.wPeriodMin);
    return 77;
  }
  if(r != TIMERR_NOERROR) {
    printf("FAIL timing_timebeginperiod_winmm: timeBeginPeriod returned %u\n", (unsigned)r);
    return 1;
  }

  if(!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) {
    timeEndPeriod(tc.wPeriodMin);
    printf("FAIL timing_timebeginperiod_winmm: QueryPerformanceFrequency error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }

  t0 = timeGetTime();
  Sleep(30);
  t1 = timeGetTime();
  dt = t1 - t0;
  if(dt < 25 || dt > 5000) {
    timeEndPeriod(tc.wPeriodMin);
    printf("FAIL timing_timebeginperiod_winmm: timeGetTime advanced %lu ms across Sleep(30)\n",
           (unsigned long)dt);
    return 1;
  }

  /* Up to three batches: a stuck 15.6 ms tick makes every batch take about
     312 ms, so it still fails, while one stall from a loaded host does not. */
  best_ms = -1.0;
  for(attempt = 0; attempt < 3; attempt++) {
    if(!QueryPerformanceCounter(&q0)) {
      timeEndPeriod(tc.wPeriodMin);
      printf("FAIL timing_timebeginperiod_winmm: QueryPerformanceCounter error %lu\n",
             (unsigned long)GetLastError());
      return 1;
    }
    for(i = 0; i < 20; i++)
      Sleep(1);
    if(!QueryPerformanceCounter(&q1)) {
      timeEndPeriod(tc.wPeriodMin);
      printf("FAIL timing_timebeginperiod_winmm: QueryPerformanceCounter error %lu\n",
             (unsigned long)GetLastError());
      return 1;
    }
    ms = ((double)(q1.QuadPart - q0.QuadPart) * 1000.0) / (double)f.QuadPart;
    if(best_ms < 0.0 || ms < best_ms)
      best_ms = ms;
    if(best_ms <= 250.0)
      break;
  }
  if(best_ms > 250.0) {
    timeEndPeriod(tc.wPeriodMin);
    printf("FAIL timing_timebeginperiod_winmm: 20 x Sleep(1) took %.1f ms (best of 3) under %u ms resolution\n",
           best_ms, (unsigned)tc.wPeriodMin);
    return 1;
  }

  r = timeEndPeriod(tc.wPeriodMin);
  if(r != TIMERR_NOERROR) {
    printf("FAIL timing_timebeginperiod_winmm: timeEndPeriod returned %u\n", (unsigned)r);
    return 1;
  }

  printf("PASS timing_timebeginperiod_winmm\n");
  return 0;
}
