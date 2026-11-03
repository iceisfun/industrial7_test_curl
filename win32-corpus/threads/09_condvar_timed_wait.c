/*
 * Test: condvar_timed_wait
 *
 * Purpose: timed waits on CONDITION_VARIABLE with both lock types. A wait that
 *   times out returns FALSE with ERROR_TIMEOUT (what curl's
 *   Curl_cond_timedwait maps to CURLE_OPERATION_TIMEDOUT), the lock is
 *   reacquired in its original mode, and a signal before the deadline returns
 *   TRUE without a timeout.
 *
 * APIs: InitializeConditionVariable, SleepConditionVariableCS,
 *   SleepConditionVariableSRW, WakeConditionVariable, InitializeCriticalSection,
 *   AcquireSRWLockExclusive, AcquireSRWLockShared, TryAcquireSRWLockExclusive,
 *   TryAcquireSRWLockShared, CreateThread, WaitForSingleObject, GetLastError.
 *
 * Success: CS timed wait of 50 ms returns FALSE / ERROR_TIMEOUT after >= 40 ms
 *   with the CS still owned (RecursionCount == 1); SRW shared and exclusive
 *   timed waits time out with ERROR_TIMEOUT and keep the lock held (try-lock
 *   from the owner fails); a 0 ms wait times out immediately; a signal from a
 *   helper at ~100 ms wakes a 5 s wait with TRUE.
 *
 * curl reference: lib/curl_threads.c:151-158 (Curl_cond_timedwait calls
 *   SleepConditionVariableCS(c, m, timeout_ms) and maps ERROR_TIMEOUT to
 *   CURLE_OPERATION_TIMEDOUT).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "condvar_timed_wait"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static double now_ms(void)
{
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
}

static CRITICAL_SECTION cs;
static SRWLOCK srw = SRWLOCK_INIT;
static CONDITION_VARIABLE cv;
static volatile LONG signaled_flag = 0;

static DWORD WINAPI signaller(LPVOID p)
{
  (void)p;
  Sleep(100);
  EnterCriticalSection(&cs);
  signaled_flag = 1;
  LeaveCriticalSection(&cs);
  WakeConditionVariable(&cv);
  return 0;
}

int main(void)
{
  BOOL ok;
  DWORD err;
  double t0, elapsed;
  HANDLE th;

  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);

  /* 1. zero timeout returns immediately with ERROR_TIMEOUT */
  EnterCriticalSection(&cs);
  t0 = now_ms();
  ok = SleepConditionVariableCS(&cv, &cs, 0);
  err = GetLastError();
  elapsed = now_ms() - t0;
  if(ok)
    FAILF("zero-timeout SleepConditionVariableCS returned TRUE");
  if(err != ERROR_TIMEOUT)
    FAILF("zero-timeout GLE=%lu, expected ERROR_TIMEOUT (1460)", err);
  if(elapsed > 200.0)
    FAILF("zero-timeout wait took %.1f ms", elapsed);
  LeaveCriticalSection(&cs);

  /* 2. CS 50 ms timeout: FALSE + ERROR_TIMEOUT, lock reacquired */
  EnterCriticalSection(&cs);
  t0 = now_ms();
  ok = SleepConditionVariableCS(&cv, &cs, 50);
  err = GetLastError();
  elapsed = now_ms() - t0;
  if(ok)
    FAILF("CS timed wait returned TRUE with no signal");
  if(err != ERROR_TIMEOUT)
    FAILF("CS timed wait GLE=%lu, expected ERROR_TIMEOUT (1460)", err);
  if(elapsed < 40.0)
    FAILF("CS timed wait returned after %.1f ms, requested 50 ms", elapsed);
  if(cs.RecursionCount != 1)
    FAILF("CS not reacquired after timeout (RecursionCount=%ld)", (long)cs.RecursionCount);
  LeaveCriticalSection(&cs);

  /* 3. SRW shared timeout keeps the lock held shared */
  AcquireSRWLockShared(&srw);
  ok = SleepConditionVariableSRW(&cv, &srw, 50, CONDITION_VARIABLE_LOCKMODE_SHARED);
  err = GetLastError();
  if(ok)
    FAILF("SRW shared timed wait returned TRUE with no signal");
  if(err != ERROR_TIMEOUT)
    FAILF("SRW shared timed wait GLE=%lu, expected ERROR_TIMEOUT", err);
  if(TryAcquireSRWLockExclusive(&srw))
    FAILF("SRW lock not held shared after timed wait timeout");
  ReleaseSRWLockShared(&srw);

  /* 4. SRW exclusive timeout keeps the lock held exclusively */
  AcquireSRWLockExclusive(&srw);
  ok = SleepConditionVariableSRW(&cv, &srw, 30, 0);
  err = GetLastError();
  if(ok)
    FAILF("SRW exclusive timed wait returned TRUE with no signal");
  if(err != ERROR_TIMEOUT)
    FAILF("SRW exclusive timed wait GLE=%lu, expected ERROR_TIMEOUT", err);
  if(TryAcquireSRWLockShared(&srw))
    FAILF("SRW lock not held exclusively after timed wait timeout");
  ReleaseSRWLockExclusive(&srw);

  /* 5. signal before deadline wakes the waiter with TRUE */
  th = CreateThread(NULL, 0, signaller, NULL, 0, NULL);
  if(!th)
    FAILF("CreateThread failed (GLE=%lu)", GetLastError());
  EnterCriticalSection(&cs);
  t0 = now_ms();
  while(!signaled_flag) {
    ok = SleepConditionVariableCS(&cv, &cs, 5000);
    if(!ok) {
      err = GetLastError();
      LeaveCriticalSection(&cs);
      CloseHandle(th);
      FAILF("signal never delivered, wait GLE=%lu", err);
    }
  }
  elapsed = now_ms() - t0;
  LeaveCriticalSection(&cs);
  WaitForSingleObject(th, 5000);
  CloseHandle(th);
  if(elapsed < 60.0)
    FAILF("waiter woke after %.1f ms, signaller waits 100 ms", elapsed);
  if(elapsed > 4000.0)
    FAILF("waiter woke after %.1f ms, far beyond the signal", elapsed);

  DeleteCriticalSection(&cs);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
