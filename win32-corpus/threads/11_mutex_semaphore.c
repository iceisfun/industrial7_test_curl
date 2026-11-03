/*
 * Test: mutex_semaphore
 *
 * Purpose: unnamed kernel mutex and semaphore objects. Covers recursive
 *   acquisition, ReleaseMutex from a non-owner (ERROR_NOT_OWNER), abandoned
 *   mutex detection when an owner thread exits, semaphore counting limits,
 *   ReleaseSemaphore previous count and ERROR_TOO_MANY_POSTS, and a
 *   concurrency cap enforced by a semaphore.
 *
 * APIs: CreateMutexW, WaitForSingleObject, ReleaseMutex, CreateSemaphoreW,
 *   ReleaseSemaphore, CreateThread, WaitForMultipleObjects, InterlockedIncrement,
 *   InterlockedDecrement, GetLastError.
 *
 * Success: mutex is recursive for its owner; a non-owner release returns FALSE
 *   with ERROR_NOT_OWNER (288); abandoned ownership is reported as
 *   WAIT_ABANDONED_0; semaphore(initial 2, max 3) gives exactly two immediate
 *   acquisitions, ReleaseSemaphore returns the previous count, an over-max
 *   release fails with ERROR_TOO_MANY_POSTS (298) and leaves the count unchanged;
 *   three workers gated by a semaphore(2) never exceed two concurrent holders.
 *
 * curl reference: curl's Windows build uses CRITICAL_SECTION rather than a
 *   kernel mutex (lib/curl_threads.h:36-39). Kernel mutex/semaphore coverage is
 *   required for the wait-on-handle paths used by the Windows worker helpers.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "mutex_semaphore"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static HANDLE mtx_abandon;
static HANDLE mtx_counter;
static HANDLE sem_cap;
static volatile LONG counter_val = 0;
static volatile LONG inside_now = 0;
static volatile LONG inside_max = 0;

static DWORD WINAPI abandon_owner(LPVOID p)
{
  (void)p;
  if(WaitForSingleObject(mtx_abandon, 2000) != WAIT_OBJECT_0)
    return 1;
  return 0; /* exits without ReleaseMutex: mutex becomes abandoned */
}

static DWORD WINAPI try_release(LPVOID p)
{
  BOOL *out = (BOOL *)p;
  *out = ReleaseMutex(mtx_abandon);
  return *out ? 0 : GetLastError();
}

static DWORD WINAPI counter_worker(LPVOID p)
{
  int i;
  (void)p;
  for(i = 0; i < 2000; i++) {
    if(WaitForSingleObject(mtx_counter, INFINITE) != WAIT_OBJECT_0)
      return 1;
    InterlockedIncrement(&counter_val);
    if(!ReleaseMutex(mtx_counter))
      return 2;
  }
  return 0;
}

static DWORD WINAPI cap_worker(LPVOID p)
{
  LONG now;
  (void)p;
  if(WaitForSingleObject(sem_cap, 5000) != WAIT_OBJECT_0)
    return 1;
  now = InterlockedIncrement(&inside_now);
  for(;;) {
    LONG m = InterlockedCompareExchange(&inside_max, now, now);
    if(now <= m)
      break;
    if(InterlockedCompareExchange(&inside_max, now, m) == m)
      break;
  }
  Sleep(40);
  InterlockedDecrement(&inside_now);
  ReleaseSemaphore(sem_cap, 1, NULL);
  return 0;
}

int main(void)
{
  HANDLE th;
  BOOL rel_ok = TRUE;
  DWORD r;
  LONG prev = -1;
  HANDLE workers[4];
  int i;

  /* 1. recursive mutex ownership and release counting */
  mtx_counter = CreateMutexW(NULL, FALSE, NULL);
  if(!mtx_counter)
    FAILF("CreateMutexW failed (GLE=%lu)", GetLastError());
  if(WaitForSingleObject(mtx_counter, 0) != WAIT_OBJECT_0)
    FAILF("first acquire of unowned mutex failed (GLE=%lu)", GetLastError());
  if(WaitForSingleObject(mtx_counter, 0) != WAIT_OBJECT_0)
    FAILF("recursive acquire by owner failed (GLE=%lu)", GetLastError());
  if(!ReleaseMutex(mtx_counter) || !ReleaseMutex(mtx_counter))
    FAILF("ReleaseMutex for the two owned levels failed (GLE=%lu)", GetLastError());
  if(ReleaseMutex(mtx_counter))
    FAILF("ReleaseMutex on fully released mutex returned TRUE");
  if(GetLastError() != ERROR_NOT_OWNER)
    FAILF("ReleaseMutex on unowned mutex GLE=%lu, expected ERROR_NOT_OWNER (288)", GetLastError());

  /* 2. mutex protects a shared counter across threads */
  for(i = 0; i < 4; i++) {
    workers[i] = CreateThread(NULL, 0, counter_worker, NULL, 0, NULL);
    if(!workers[i])
      FAILF("CreateThread(counter %d) failed (GLE=%lu)", i, GetLastError());
  }
  if(WaitForMultipleObjects(4, workers, TRUE, 30000) != WAIT_OBJECT_0)
    FAILF("counter workers did not finish (GLE=%lu)", GetLastError());
  for(i = 0; i < 4; i++) {
    if(!GetExitCodeThread(workers[i], &r) || r != 0)
      FAILF("counter worker %d exit code %lu, expected 0 (wait or ReleaseMutex failed)", i, r);
  }
  for(i = 0; i < 4; i++)
    CloseHandle(workers[i]);
  if(counter_val != 4 * 2000)
    FAILF("counter=%ld, expected %d", (long)counter_val, 4 * 2000);
  CloseHandle(mtx_counter);

  /* 3. non-owner release fails with ERROR_NOT_OWNER */
  mtx_abandon = CreateMutexW(NULL, TRUE, NULL); /* main owns it */
  if(!mtx_abandon)
    FAILF("CreateMutexW(initial owner) failed (GLE=%lu)", GetLastError());
  th = CreateThread(NULL, 0, try_release, &rel_ok, 0, NULL);
  if(!th)
    FAILF("CreateThread(try_release) failed (GLE=%lu)", GetLastError());
  WaitForSingleObject(th, 5000);
  CloseHandle(th);
  if(rel_ok)
    FAILF("ReleaseMutex from non-owner thread returned TRUE");
  if(!ReleaseMutex(mtx_abandon))
    FAILF("owner ReleaseMutex failed (GLE=%lu)", GetLastError());
  CloseHandle(mtx_abandon);

  /* 4. abandoned mutex: owner thread exits without release */
  mtx_abandon = CreateMutexW(NULL, FALSE, NULL);
  if(!mtx_abandon)
    FAILF("CreateMutexW(abandon) failed (GLE=%lu)", GetLastError());
  th = CreateThread(NULL, 0, abandon_owner, NULL, 0, NULL);
  if(!th)
    FAILF("CreateThread(abandon_owner) failed (GLE=%lu)", GetLastError());
  WaitForSingleObject(th, 5000);
  CloseHandle(th);
  r = WaitForSingleObject(mtx_abandon, 2000);
  if(r != WAIT_ABANDONED_0)
    FAILF("wait on abandoned mutex returned %lu, expected WAIT_ABANDONED_0 (GLE=%lu)", r, GetLastError());
  if(!ReleaseMutex(mtx_abandon))
    FAILF("ReleaseMutex after abandonment failed (GLE=%lu)", GetLastError());
  CloseHandle(mtx_abandon);

  /* 5. semaphore counting: initial 2, max 3 */
  sem_cap = CreateSemaphoreW(NULL, 2, 3, NULL);
  if(!sem_cap)
    FAILF("CreateSemaphoreW failed (GLE=%lu)", GetLastError());
  if(WaitForSingleObject(sem_cap, 0) != WAIT_OBJECT_0 ||
     WaitForSingleObject(sem_cap, 0) != WAIT_OBJECT_0)
    FAILF("semaphore with initial count 2 did not admit two waiters");
  if(WaitForSingleObject(sem_cap, 0) != WAIT_TIMEOUT)
    FAILF("third acquire on drained semaphore did not time out");

  if(!ReleaseSemaphore(sem_cap, 2, &prev))
    FAILF("ReleaseSemaphore(+2) failed (GLE=%lu)", GetLastError());
  if(prev != 0)
    FAILF("ReleaseSemaphore previous count %ld, expected 0", (long)prev);

  if(ReleaseSemaphore(sem_cap, 2, NULL))
    FAILF("ReleaseSemaphore beyond max (count 2+2 > 3) succeeded");
  if(GetLastError() != ERROR_TOO_MANY_POSTS)
    FAILF("over-max release GLE=%lu, expected ERROR_TOO_MANY_POSTS (298)", GetLastError());

  if(WaitForSingleObject(sem_cap, 0) != WAIT_OBJECT_0 ||
     WaitForSingleObject(sem_cap, 0) != WAIT_OBJECT_0)
    FAILF("count 2 not preserved after failed over-max release");
  if(WaitForSingleObject(sem_cap, 0) != WAIT_TIMEOUT)
    FAILF("semaphore count larger than 2 after failed release");

  /* 6. semaphore(2) caps concurrency of 4 workers */
  if(!ReleaseSemaphore(sem_cap, 2, NULL))
    FAILF("ReleaseSemaphore for worker tokens failed (GLE=%lu)", GetLastError());
  for(i = 0; i < 4; i++) {
    workers[i] = CreateThread(NULL, 0, cap_worker, NULL, 0, NULL);
    if(!workers[i])
      FAILF("CreateThread(cap %d) failed (GLE=%lu)", i, GetLastError());
  }
  if(WaitForMultipleObjects(4, workers, TRUE, 20000) != WAIT_OBJECT_0)
    FAILF("capped workers did not finish (GLE=%lu)", GetLastError());
  for(i = 0; i < 4; i++)
    CloseHandle(workers[i]);
  if(inside_max > 2)
    FAILF("semaphore(2) admitted %ld concurrent holders", (long)inside_max);
  if(inside_max != 2)
    FAILF("concurrency reached only %ld; expected the cap of 2 to be hit", (long)inside_max);
  CloseHandle(sem_cap);

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
