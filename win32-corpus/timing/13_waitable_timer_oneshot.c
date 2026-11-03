/*
 * Test: timing_waitable_timer_oneshot
 * Purpose: CreateWaitableTimerW/SetWaitableTimer one-shot behaviour with
 *          both relative and absolute due times, for manual-reset and
 *          auto-reset timers, plus CancelWaitableTimer.
 * APIs: CreateWaitableTimerW, SetWaitableTimer, CancelWaitableTimer,
 *       WaitForSingleObject, GetSystemTimeAsFileTime, QueryPerformanceCounter,
 *       CloseHandle
 * Success: a manual-reset timer due in 20 ms (relative, negative value)
 *          signals within 2 s after at least 15 ms and stays signaled on a
 *          later poll; an auto-reset timer due in 10 ms signals once and the
 *          next zero-timeout wait returns WAIT_TIMEOUT; an absolute timer due
 *          30 ms in the future signals, and the wall clock at the signal is
 *          at or after the due time (2 ms tolerance); CancelWaitableTimer
 *          returns TRUE.
 * Source: curl does not create waitable timers (grep finds none in lib/).
 *         Its Windows timed waits are Sleep() (lib/curlx/wait.c:66-73) and
 *         timed condition variables (lib/curl_threads.c:154); this test
 *         covers the separate timer primitive.
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

static ULONGLONG ft_u64(FILETIME f)
{
  return ((ULONGLONG)f.dwHighDateTime << 32) | (ULONGLONG)f.dwLowDateTime;
}

static double ms_between(LARGE_INTEGER a, LARGE_INTEGER b, LONGLONG freq)
{
  return ((double)(b.QuadPart - a.QuadPart) * 1000.0) / (double)freq;
}

int main(void)
{
  HANDLE manual, autot;
  LARGE_INTEGER f, due, a, b;
  FILETIME now_ft;
  ULONGLONG due_abs, now_u;
  DWORD r;
  double ms;

  if(!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) {
    printf("FAIL timing_waitable_timer_oneshot: QueryPerformanceFrequency error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }

  /* Manual-reset timer, relative due time of 20 ms (negative, 100 ns units). */
  manual = CreateWaitableTimerW(NULL, TRUE, NULL);
  if(!manual) {
    printf("FAIL timing_waitable_timer_oneshot: CreateWaitableTimerW(manual) error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  due.QuadPart = -200000LL;
  if(!SetWaitableTimer(manual, &due, 0, NULL, NULL, FALSE)) {
    printf("FAIL timing_waitable_timer_oneshot: SetWaitableTimer(relative) error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  if(!QueryPerformanceCounter(&a)) {
    printf("FAIL timing_waitable_timer_oneshot: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  r = WaitForSingleObject(manual, 2000);
  if(!QueryPerformanceCounter(&b)) {
    printf("FAIL timing_waitable_timer_oneshot: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  ms = ms_between(a, b, f.QuadPart);
  if(r != WAIT_OBJECT_0) {
    printf("FAIL timing_waitable_timer_oneshot: relative timer wait returned %lu (error %lu)\n",
           (unsigned long)r, (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  if(ms < 15.0) {
    printf("FAIL timing_waitable_timer_oneshot: 20 ms timer fired after only %.1f ms\n", ms);
    CloseHandle(manual);
    return 1;
  }
  if(WaitForSingleObject(manual, 0) != WAIT_OBJECT_0) {
    printf("FAIL timing_waitable_timer_oneshot: manual-reset timer lost its signal\n");
    CloseHandle(manual);
    return 1;
  }
  if(!CancelWaitableTimer(manual)) {
    printf("FAIL timing_waitable_timer_oneshot: CancelWaitableTimer error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  CloseHandle(manual);

  /* Auto-reset timer: one signal, consumed by the first wait. */
  autot = CreateWaitableTimerW(NULL, FALSE, NULL);
  if(!autot) {
    printf("FAIL timing_waitable_timer_oneshot: CreateWaitableTimerW(auto) error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  due.QuadPart = -100000LL;
  if(!SetWaitableTimer(autot, &due, 0, NULL, NULL, FALSE)) {
    printf("FAIL timing_waitable_timer_oneshot: SetWaitableTimer(auto) error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(autot);
    return 1;
  }
  if(WaitForSingleObject(autot, 2000) != WAIT_OBJECT_0) {
    printf("FAIL timing_waitable_timer_oneshot: auto-reset timer did not fire (error %lu)\n",
           (unsigned long)GetLastError());
    CloseHandle(autot);
    return 1;
  }
  if(WaitForSingleObject(autot, 0) != WAIT_TIMEOUT) {
    printf("FAIL timing_waitable_timer_oneshot: auto-reset timer fired twice\n");
    CloseHandle(autot);
    return 1;
  }

  /* Absolute due time: 30 ms after the current wall clock (FILETIME, UTC). */
  GetSystemTimeAsFileTime(&now_ft);
  due_abs = ft_u64(now_ft) + 300000ULL;
  due.QuadPart = (LONGLONG)due_abs;
  if(!SetWaitableTimer(autot, &due, 0, NULL, NULL, FALSE)) {
    printf("FAIL timing_waitable_timer_oneshot: SetWaitableTimer(absolute) error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(autot);
    return 1;
  }
  if(WaitForSingleObject(autot, 2000) != WAIT_OBJECT_0) {
    printf("FAIL timing_waitable_timer_oneshot: absolute timer did not fire (error %lu)\n",
           (unsigned long)GetLastError());
    CloseHandle(autot);
    return 1;
  }
  GetSystemTimeAsFileTime(&now_ft);
  now_u = ft_u64(now_ft);
  if(now_u + 20000ULL < due_abs) {
    printf("FAIL timing_waitable_timer_oneshot: absolute timer signaled before its due time\n");
    CloseHandle(autot);
    return 1;
  }

  /* Cancel on an idle timer must still report success. */
  if(!CancelWaitableTimer(autot)) {
    printf("FAIL timing_waitable_timer_oneshot: CancelWaitableTimer(idle) error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(autot);
    return 1;
  }
  CloseHandle(autot);

  printf("PASS timing_waitable_timer_oneshot\n");
  return 0;
}
