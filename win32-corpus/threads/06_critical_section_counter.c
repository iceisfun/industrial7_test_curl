/*
 * Test: critical_section_counter
 *
 * Purpose: CRITICAL_SECTION initialised with the exact call curl uses
 *   (InitializeCriticalSectionEx(m, 0, 1)), recursive ownership,
 *   TryEnterCriticalSection from the owner and from another thread, and a
 *   multi-threaded counter stress test that must not lose updates.
 *
 * APIs: InitializeCriticalSectionEx, EnterCriticalSection,
 *   TryEnterCriticalSection, LeaveCriticalSection, DeleteCriticalSection,
 *   CreateThread, WaitForMultipleObjects, GetExitCodeThread, CloseHandle.
 *
 * Success: the counter ends at exactly THREADS * ITERS, TryEnter from another
 *   thread fails while held and succeeds when free, TryEnter from the owner is
 *   recursive (RecursionCount reaches 2), and the lock is released after the
 *   matching number of Leave calls.
 *
 * curl reference: lib/curl_threads.h:36-39 (Curl_mutex_init/acquire/release/
 *   destroy mapped to InitializeCriticalSectionEx(m, 0, 1), EnterCriticalSection,
 *   LeaveCriticalSection, DeleteCriticalSection).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "critical_section_counter"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

#define THREADS 8
#define ITERS 100000

static CRITICAL_SECTION cs;
static long long counter = 0;

static DWORD WINAPI inc_worker(LPVOID p)
{
  long i;
  (void)p;
  for(i = 0; i < ITERS; i++) {
    EnterCriticalSection(&cs);
    counter++;
    LeaveCriticalSection(&cs);
  }
  return 0;
}

static DWORD WINAPI try_from_other(LPVOID p)
{
  BOOL got = TryEnterCriticalSection(&cs);
  *(BOOL *)p = got;
  if(got)
    LeaveCriticalSection(&cs);
  return 0;
}

static int run_try_from_other(BOOL *out)
{
  HANDLE th = CreateThread(NULL, 0, try_from_other, out, 0, NULL);
  if(!th)
    return -1;
  WaitForSingleObject(th, 5000);
  CloseHandle(th);
  return 0;
}

int main(void)
{
  HANDLE th[THREADS];
  DWORD i;
  BOOL other = TRUE, ok;

  /* exact curl initialisation sequence */
  if(!InitializeCriticalSectionEx(&cs, 0, 1))
    FAILF("InitializeCriticalSectionEx(&cs, 0, 1) failed (GLE=%lu)", GetLastError());

  /* 1. ownership by main thread blocks TryEnter from another thread */
  EnterCriticalSection(&cs);
  if(run_try_from_other(&other) != 0)
    FAILF("CreateThread for try helper failed (GLE=%lu)", GetLastError());
  if(other)
    FAILF("TryEnterCriticalSection succeeded from another thread while held");

  /* 2. recursive TryEnter from owner succeeds and bumps RecursionCount */
  ok = TryEnterCriticalSection(&cs);
  if(!ok)
    FAILF("TryEnterCriticalSection from owner returned FALSE (GLE=%lu)", GetLastError());
  if(cs.RecursionCount != 2)
    FAILF("RecursionCount after recursive enter is %ld, expected 2", (long)cs.RecursionCount);
  LeaveCriticalSection(&cs);
  LeaveCriticalSection(&cs);

  /* 3. free lock: TryEnter from another thread succeeds */
  other = FALSE;
  if(run_try_from_other(&other) != 0)
    FAILF("CreateThread for try helper failed (GLE=%lu)", GetLastError());
  if(!other)
    FAILF("TryEnterCriticalSection failed from another thread on a free lock");

  /* 4. counter stress: THREADS workers, each ITERS guarded increments */
  for(i = 0; i < THREADS; i++) {
    th[i] = CreateThread(NULL, 0, inc_worker, NULL, 0, NULL);
    if(!th[i])
      FAILF("CreateThread(%lu) failed (GLE=%lu)", i, GetLastError());
  }
  if(WaitForMultipleObjects(THREADS, th, TRUE, 60000) != WAIT_OBJECT_0)
    FAILF("stress workers did not finish (GLE=%lu)", GetLastError());
  for(i = 0; i < THREADS; i++)
    CloseHandle(th[i]);

  if(counter != (long long)THREADS * ITERS)
    FAILF("lost updates: counter=%lld expected %lld", counter, (long long)THREADS * ITERS);

  /* lock must be free again */
  other = FALSE;
  if(run_try_from_other(&other) != 0 || !other)
    FAILF("lock still held after stress run");

  DeleteCriticalSection(&cs);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
