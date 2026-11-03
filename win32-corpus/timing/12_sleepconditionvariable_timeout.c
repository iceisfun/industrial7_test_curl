/*
 * Test: timing_sleepconditionvariable_timeout
 * Purpose: SleepConditionVariableCS with a finite timeout returns FALSE
 *          with ERROR_TIMEOUT when nobody signals, and wakes a thread that
 *          is waiting for a condition set by another thread. This is the
 *          timed-wait sequence curl's thread helper uses.
 * APIs: InitializeCriticalSection, EnterCriticalSection, LeaveCriticalSection,
 *       DeleteCriticalSection, InitializeConditionVariable,
 *       SleepConditionVariableCS, WakeConditionVariable, CreateThread,
 *       WaitForSingleObject, GetExitCodeThread, QueryPerformanceCounter
 * Success: a 30 ms timed wait returns FALSE, GetLastError()==ERROR_TIMEOUT,
 *          and takes at least 20 ms; a waiter thread blocked on a flag
 *          observes the flag after the main thread sets it and calls
 *          WakeConditionVariable, and exits with code 0 (condition met)
 *          within 10 s.
 * Source: curl lib/curl_threads.c:148 (SleepConditionVariableCS(c, m,
 *         INFINITE)) and lib/curl_threads.c:154-158 (the timed form, which
 *         treats a FALSE return as a timeout).
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

struct shared {
  CRITICAL_SECTION cs;
  CONDITION_VARIABLE cv;
  volatile LONG flag;
};

static DWORD WINAPI waiter(LPVOID arg)
{
  struct shared *s = (struct shared *)arg;
  DWORD rc = 0;

  EnterCriticalSection(&s->cs);
  while(!s->flag) {
    if(!SleepConditionVariableCS(&s->cv, &s->cs, 5000)) {
      if(GetLastError() == ERROR_TIMEOUT)
        break;
      rc = 2; /* unexpected error */
      break;
    }
  }
  if(!s->flag && rc == 0)
    rc = 3; /* flag never set */
  LeaveCriticalSection(&s->cs);
  return rc;
}

int main(void)
{
  struct shared s;
  LARGE_INTEGER f, a, b;
  BOOL ok, qpc_ok;
  DWORD err, code = 0xFFFFFFFF;
  HANDLE th;
  double ms;

  if(!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) {
    printf("FAIL timing_sleepconditionvariable_timeout: QueryPerformanceFrequency error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }

  InitializeCriticalSection(&s.cs);
  InitializeConditionVariable(&s.cv);
  s.flag = 0;

  /* Part 1: timed wait with nobody signaling must time out. */
  EnterCriticalSection(&s.cs);
  if(!QueryPerformanceCounter(&a)) {
    LeaveCriticalSection(&s.cs);
    DeleteCriticalSection(&s.cs);
    printf("FAIL timing_sleepconditionvariable_timeout: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  ok = SleepConditionVariableCS(&s.cv, &s.cs, 30);
  err = GetLastError();
  qpc_ok = QueryPerformanceCounter(&b);
  LeaveCriticalSection(&s.cs);
  if(!qpc_ok) {
    DeleteCriticalSection(&s.cs);
    printf("FAIL timing_sleepconditionvariable_timeout: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  ms = ((double)(b.QuadPart - a.QuadPart) * 1000.0) / (double)f.QuadPart;
  if(ok) {
    printf("FAIL timing_sleepconditionvariable_timeout: timed wait returned TRUE with no signal\n");
    DeleteCriticalSection(&s.cs);
    return 1;
  }
  if(err != ERROR_TIMEOUT) {
    printf("FAIL timing_sleepconditionvariable_timeout: timed wait error is %lu, expected ERROR_TIMEOUT (%lu)\n",
           (unsigned long)err, (unsigned long)ERROR_TIMEOUT);
    DeleteCriticalSection(&s.cs);
    return 1;
  }
  if(ms < 20.0) {
    printf("FAIL timing_sleepconditionvariable_timeout: 30 ms timed wait returned after %.1f ms\n", ms);
    DeleteCriticalSection(&s.cs);
    return 1;
  }

  /* Part 2: a waiter thread is woken by a signal that sets the condition. */
  th = CreateThread(NULL, 0, waiter, &s, 0, NULL);
  if(!th) {
    printf("FAIL timing_sleepconditionvariable_timeout: CreateThread error %lu\n",
           (unsigned long)GetLastError());
    DeleteCriticalSection(&s.cs);
    return 1;
  }
  Sleep(50);
  EnterCriticalSection(&s.cs);
  s.flag = 1;
  WakeConditionVariable(&s.cv);
  LeaveCriticalSection(&s.cs);

  if(WaitForSingleObject(th, 10000) != WAIT_OBJECT_0) {
    printf("FAIL timing_sleepconditionvariable_timeout: waiter thread did not finish (error %lu)\n",
           (unsigned long)GetLastError());
    DeleteCriticalSection(&s.cs);
    return 1;
  }
  if(!GetExitCodeThread(th, &code) || code != 0) {
    printf("FAIL timing_sleepconditionvariable_timeout: waiter exit code %lu (0 expected)\n",
           (unsigned long)code);
    CloseHandle(th);
    DeleteCriticalSection(&s.cs);
    return 1;
  }
  CloseHandle(th);
  DeleteCriticalSection(&s.cs);

  printf("PASS timing_sleepconditionvariable_timeout\n");
  return 0;
}
