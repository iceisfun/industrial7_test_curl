/*
 * Test: srwlock_readers_writers
 *
 * Purpose: SRWLOCK shared/exclusive semantics that curl relies on through
 *   easy_lock.h (SRWLOCK with AcquireSRWLockExclusive/ReleaseSRWLockExclusive
 *   as curl_simple_lock_lock/unlock), plus shared-reader concurrency and
 *   writer exclusion under stress.
 *
 * APIs: SRWLOCK_INIT, InitializeSRWLock, AcquireSRWLockShared,
 *   ReleaseSRWLockShared, AcquireSRWLockExclusive, ReleaseSRWLockExclusive,
 *   TryAcquireSRWLockShared, TryAcquireSRWLockExclusive, CreateThread,
 *   WaitForMultipleObjects.
 *
 * Success: four readers hold the shared lock at the same time (they all see
 *   each other inside the critical section), try-exclusive fails while shared
 *   is held, try-shared fails while exclusive is held, and under mixed
 *   writer/reader stress the readers never observe a torn pair and the final
 *   writer count is exact.
 *
 * curl reference: lib/easy_lock.h:32-33 (curl_simple_lock = SRWLOCK,
 *   CURL_SIMPLE_LOCK_INIT = SRWLOCK_INIT) and lines 35-36
 *   (curl_simple_lock_lock/unlock via AcquireSRWLockExclusive /
 *   ReleaseSRWLockExclusive).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "srwlock_readers_writers"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

#define READERS 4
#define WRITERS 3
#define ROUNDS 20000

static SRWLOCK lock = SRWLOCK_INIT;
static volatile LONG inside_shared = 0;
static volatile LONG max_inside = 0;
static volatile LONG arrived = 0;

static long long pair_a = 0, pair_b = 0;
static volatile LONG torn_reads = 0;

static DWORD WINAPI shared_holder(LPVOID p)
{
  LONG now;
  (void)p;
  AcquireSRWLockShared(&lock);
  now = InterlockedIncrement(&inside_shared);
  for(;;) {
    LONG m = InterlockedCompareExchange(&max_inside, now, now);
    if(now > m) {
      if(InterlockedCompareExchange(&max_inside, now, m) == m)
        break;
    }
    else
      break;
  }
  /* barrier: every reader is inside at once, bounded. The arrival counter is
     never decremented (a counter that is decremented on leaving lets a late
     holder miss the "all inside" instant). Sleep(1) lasts ~15.6 ms on
     Windows (default timer tick), so yield instead of sleeping. */
  InterlockedIncrement(&arrived);
  {
    ULONGLONG t0 = GetTickCount64();
    while(InterlockedCompareExchange(&arrived, 0, 0) < READERS &&
          GetTickCount64() - t0 < 5000)
      Sleep(0);
  }
  InterlockedDecrement(&inside_shared);
  ReleaseSRWLockShared(&lock);
  return 0;
}

static DWORD WINAPI writer(LPVOID p)
{
  int i;
  (void)p;
  for(i = 0; i < ROUNDS; i++) {
    AcquireSRWLockExclusive(&lock);
    pair_a++;
    pair_b++;
    ReleaseSRWLockExclusive(&lock);
  }
  return 0;
}

static DWORD WINAPI reader(LPVOID p)
{
  int i;
  (void)p;
  for(i = 0; i < ROUNDS; i++) {
    long long a, b;
    AcquireSRWLockShared(&lock);
    a = pair_a;
    b = pair_b;
    ReleaseSRWLockShared(&lock);
    if(a != b)
      InterlockedIncrement(&torn_reads);
  }
  return 0;
}

int main(void)
{
  HANDLE th[READERS + WRITERS + READERS];
  int n = 0, i;
  BOOL ok;

  /* 1. concurrent shared holders */
  for(i = 0; i < READERS; i++) {
    th[n] = CreateThread(NULL, 0, shared_holder, NULL, 0, NULL);
    if(!th[n])
      FAILF("CreateThread(shared %d) failed (GLE=%lu)", i, GetLastError());
    n++;
  }
  if(WaitForMultipleObjects((DWORD)n, th, TRUE, 20000) != WAIT_OBJECT_0)
    FAILF("shared holders did not finish (GLE=%lu)", GetLastError());
  for(i = 0; i < n; i++)
    CloseHandle(th[i]);
  if(InterlockedCompareExchange(&max_inside, 0, 0) != READERS)
    FAILF("max concurrent shared holders was %ld, expected %d", (long)max_inside, READERS);
  n = 0;

  /* 2. try-lock rules on the main thread */
  AcquireSRWLockShared(&lock);
  ok = TryAcquireSRWLockExclusive(&lock);
  if(ok)
    FAILF("TryAcquireSRWLockExclusive succeeded while shared was held");
  ok = TryAcquireSRWLockShared(&lock);
  if(!ok)
    FAILF("TryAcquireSRWLockShared failed while another shared holder exists (GLE=%lu)", GetLastError());
  ReleaseSRWLockShared(&lock);
  ReleaseSRWLockShared(&lock);

  ok = TryAcquireSRWLockExclusive(&lock);
  if(!ok)
    FAILF("TryAcquireSRWLockExclusive failed on free lock (GLE=%lu)", GetLastError());
  if(TryAcquireSRWLockShared(&lock))
    FAILF("TryAcquireSRWLockShared succeeded while exclusive was held");
  ReleaseSRWLockExclusive(&lock);

  /* 3. writer exclusion under reader stress */
  for(i = 0; i < WRITERS; i++) {
    th[n] = CreateThread(NULL, 0, writer, NULL, 0, NULL);
    if(!th[n])
      FAILF("CreateThread(writer %d) failed (GLE=%lu)", i, GetLastError());
    n++;
  }
  for(i = 0; i < READERS; i++) {
    th[n] = CreateThread(NULL, 0, reader, NULL, 0, NULL);
    if(!th[n])
      FAILF("CreateThread(reader %d) failed (GLE=%lu)", i, GetLastError());
    n++;
  }
  if(WaitForMultipleObjects((DWORD)n, th, TRUE, 60000) != WAIT_OBJECT_0)
    FAILF("writer/reader stress did not finish (GLE=%lu)", GetLastError());
  for(i = 0; i < n; i++)
    CloseHandle(th[i]);

  if(torn_reads != 0)
    FAILF("readers observed %ld torn pairs under shared lock", (long)torn_reads);
  if(pair_a != (long long)WRITERS * ROUNDS || pair_b != pair_a)
    FAILF("writer count mismatch a=%lld b=%lld expected %lld",
          pair_a, pair_b, (long long)WRITERS * ROUNDS);

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
