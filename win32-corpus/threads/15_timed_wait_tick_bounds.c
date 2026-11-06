/*
 * Test: timed_wait_tick_bounds
 *
 * Purpose: how far a finite timeout can deviate from its nominal value on
 * Windows. Timed waits are driven by the system timer tick (15.625 ms by
 * default): Sleep(1) lasts a whole tick, a wait of N ms rounds to tick
 * boundaries, and a wait can end up to one tick EARLY. curl's multi code
 * (lib/multi.c, lib/select.c Curl_wait_ms -> Sleep / WSAPoll timeouts) and its
 * condition-variable timeouts (lib/curl_threads.c Curl_cond_timedwait ->
 * SleepConditionVariableCS) are subject to the same rounding, so a test or
 * caller must never assert a lower bound tighter than one tick.
 *
 * APIs: Sleep, SleepEx, WaitForSingleObject, SleepConditionVariableCS,
 *   SleepConditionVariableSRW, QueryPerformanceCounter, InitializeCriticalSectionEx.
 *
 * Success (probed on Windows 10 22H2, 20 samples per case, std and adm):
 *   a 0 ms wait has a median under 1 ms (about 0.001 ms) and a maximum under
 *   one tick for every API (a preemption can add a few ms). For N in {1, 2, 10, 16,
 *   30, 50, 100} every sample lies in [N - 16, N + 100] ms (observed minimum
 *   early return 1.9 ms at N=30; the neighbouring timing test has seen 12 ms
 *   early). With the default 15.625 ms tick the median of Sleep(1) and
 *   WaitForSingleObject(h, 1) is between 9 and 20 ms; with a finer timer (some
 *   other process called timeBeginPeriod) it is between 0.9 and 20 ms, so the
 *   check allows both and only requires "at least 0.9 ms, at most 20 ms".
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define TEST_NAME "timed_wait_tick_bounds"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

#define SAMPLES 20

static LARGE_INTEGER fq;
static HANDLE ev;
static CRITICAL_SECTION cs;
static SRWLOCK srw = SRWLOCK_INIT;
static CONDITION_VARIABLE cv_cs = CONDITION_VARIABLE_INIT;
static CONDITION_VARIABLE cv_srw = CONDITION_VARIABLE_INIT;

static void one(int api, DWORD ms)
{
  switch(api) {
  case 0: WaitForSingleObject(ev, ms); break;
  case 1: Sleep(ms); break;
  case 2: SleepEx(ms, FALSE); break;
  case 3:
    EnterCriticalSection(&cs);
    SleepConditionVariableCS(&cv_cs, &cs, ms);
    LeaveCriticalSection(&cs);
    break;
  default:
    AcquireSRWLockExclusive(&srw);
    SleepConditionVariableSRW(&cv_srw, &srw, ms, 0);
    ReleaseSRWLockExclusive(&srw);
    break;
  }
}

static int cmp(const void *a, const void *b)
{
  double x = *(const double *)a, y = *(const double *)b;
  return x < y ? -1 : x > y;
}

int main(void)
{
  static const char *const names[] = { "WaitForSingleObject", "Sleep", "SleepEx",
                                       "SleepConditionVariableCS", "SleepConditionVariableSRW" };
  static const DWORD tests[] = { 0, 1, 2, 10, 16, 30, 50, 100 };
  int api, t, i;

  QueryPerformanceFrequency(&fq);
  ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  InitializeCriticalSectionEx(&cs, 0, CRITICAL_SECTION_NO_DEBUG_INFO);
  if(!ev)
    FAILF("CreateEventW failed");

  for(api = 0; api < 5; api++) {
    for(t = 0; t < (int)(sizeof(tests) / sizeof(tests[0])); t++) {
      double s[SAMPLES];
      DWORD n = tests[t];
      for(i = 0; i < SAMPLES; i++) {
        LARGE_INTEGER a, b;
        QueryPerformanceCounter(&a);
        one(api, n);
        QueryPerformanceCounter(&b);
        s[i] = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)fq.QuadPart;
      }
      qsort(s, SAMPLES, sizeof(s[0]), cmp);
      if(n == 0) {
        /* typically ~0.001 ms; a preemption can add up to a tick */
        if(s[SAMPLES / 2] >= 1.0 || s[SAMPLES - 1] >= 16.0)
          FAILF("%s(0): median %.3f ms, max %.2f ms, expected < 1 ms and < 16 ms", names[api],
                s[SAMPLES / 2], s[SAMPLES - 1]);
        continue;
      }
      if(s[0] < (double)n - 16.0 || s[SAMPLES - 1] > (double)n + 100.0)
        FAILF("%s(%lu): samples %.2f..%.2f ms outside [%lu, %lu]", names[api], (unsigned long)n,
              s[0], s[SAMPLES - 1], (unsigned long)(n > 16 ? n - 16 : 0), (unsigned long)n + 100);
      if(n == 1 && (api == 0 || api == 1)) {
        double med = s[SAMPLES / 2];
        if(med < 0.9 || med > 20.0)
          FAILF("%s(1) median %.2f ms outside [0.9, 20]", names[api], med);
      }
    }
  }

  DeleteCriticalSection(&cs);
  CloseHandle(ev);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
