/*
 * Test: condvar_producer_consumer
 *
 * Purpose: bounded-buffer producer/consumer built on CONDITION_VARIABLE, run
 *   twice: once with a CRITICAL_SECTION and SleepConditionVariableCS (curl's
 *   Windows configuration, lib/curl_threads.h:36-40) and once with an SRWLOCK
 *   and SleepConditionVariableSRW. Predicates are re-checked after every wake.
 *
 * APIs: InitializeCriticalSection, InitializeSRWLock, InitializeConditionVariable,
 *   EnterCriticalSection, LeaveCriticalSection, AcquireSRWLockExclusive,
 *   ReleaseSRWLockExclusive, SleepConditionVariableCS, SleepConditionVariableSRW,
 *   WakeConditionVariable, WakeAllConditionVariable, CreateThread,
 *   WaitForMultipleObjects.
 *
 * Success: all PRODUCERS*PER_PRODUCER items are consumed exactly once (sum of
 *   consumed values equals the sum of produced values, item count exact), no
 *   deadlock within 30 s, and the buffer never exceeds its capacity.
 *
 * curl reference: lib/curl_threads.c:146-149 (Curl_cond_wait =
 *   SleepConditionVariableCS(c, m, INFINITE)) and lib/curl_threads.h:40-42
 *   (curl_cond_t = CONDITION_VARIABLE, InitializeConditionVariable).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "condvar_producer_consumer"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

#define CAP 4
#define PRODUCERS 2
#define CONSUMERS 3
#define PER_PRODUCER 5000
#define TOTAL (PRODUCERS * PER_PRODUCER)

static int use_srw = 0;
static CRITICAL_SECTION cs;
static SRWLOCK srw = SRWLOCK_INIT;
static CONDITION_VARIABLE not_full, not_empty;

static int buf[CAP];
static int head, tail, count;
static int consumed_items;
static long long produced_sum, consumed_sum;
static int max_count;
static int bad_state;

static void buf_lock(void)
{
  if(use_srw) AcquireSRWLockExclusive(&srw);
  else EnterCriticalSection(&cs);
}

static void buf_unlock(void)
{
  if(use_srw) ReleaseSRWLockExclusive(&srw);
  else LeaveCriticalSection(&cs);
}

static void buf_wait(CONDITION_VARIABLE *cv)
{
  if(use_srw)
    (void)SleepConditionVariableSRW(cv, &srw, INFINITE, 0);
  else
    (void)SleepConditionVariableCS(cv, &cs, INFINITE);
}

static DWORD WINAPI producer(LPVOID p)
{
  int id = *(int *)p;
  int i;
  for(i = 0; i < PER_PRODUCER; i++) {
    int value = id * PER_PRODUCER + i + 1;
    buf_lock();
    while(count == CAP)
      buf_wait(&not_full);
    buf[tail] = value;
    tail = (tail + 1) % CAP;
    count++;
    if(count > CAP)
      bad_state = 1;
    if(count > max_count)
      max_count = count;
    produced_sum += value;
    WakeAllConditionVariable(&not_empty);
    buf_unlock();
  }
  return 0;
}

static DWORD WINAPI consumer(LPVOID p)
{
  (void)p;
  for(;;) {
    int v;
    buf_lock();
    while(count == 0 && consumed_items < TOTAL)
      buf_wait(&not_empty);
    if(count == 0 && consumed_items >= TOTAL) {
      buf_unlock();
      break;
    }
    v = buf[head];
    head = (head + 1) % CAP;
    count--;
    consumed_items++;
    consumed_sum += v;
    if(consumed_items == TOTAL)
      WakeAllConditionVariable(&not_empty);
    WakeConditionVariable(&not_full);
    buf_unlock();
  }
  return 0;
}

static int run_pipeline(int srw_mode)
{
  HANDLE th[PRODUCERS + CONSUMERS];
  int ids[PRODUCERS];
  int n = 0, i;
  long long expect = 0;

  use_srw = srw_mode;
  head = tail = count = 0;
  consumed_items = 0;
  produced_sum = consumed_sum = 0;
  max_count = 0;
  bad_state = 0;
  memset(buf, 0, sizeof(buf));
  if(!srw_mode) {
    if(!InitializeCriticalSectionAndSpinCount(&cs, 0))
      return 1;
  }
  InitializeConditionVariable(&not_full);
  InitializeConditionVariable(&not_empty);

  for(i = 0; i < PRODUCERS; i++) {
    ids[i] = i;
    th[n] = CreateThread(NULL, 0, producer, &ids[i], 0, NULL);
    if(!th[n]) return 2;
    n++;
  }
  for(i = 0; i < CONSUMERS; i++) {
    th[n] = CreateThread(NULL, 0, consumer, NULL, 0, NULL);
    if(!th[n]) return 3;
    n++;
  }

  if(WaitForMultipleObjects((DWORD)n, th, TRUE, 30000) != WAIT_OBJECT_0) {
    printf("FAIL %s: %s mode deadlocked (GLE=%lu, consumed=%d)\n", TEST_NAME,
           srw_mode ? "SRW" : "CS", GetLastError(), consumed_items);
    return 10;
  }
  for(i = 0; i < n; i++)
    CloseHandle(th[i]);

  for(i = 0; i < PRODUCERS; i++) {
    int j;
    for(j = 0; j < PER_PRODUCER; j++)
      expect += (long long)(i * PER_PRODUCER + j + 1);
  }

  if(bad_state)
    return 4;
  if(max_count > CAP)
    return 5;
  if(consumed_items != TOTAL)
    return 6;
  if(consumed_sum != produced_sum || produced_sum != expect)
    return 7;
  if(count != 0)
    return 8;

  if(!srw_mode)
    DeleteCriticalSection(&cs);
  return 0;
}

int main(void)
{
  int rc;

  rc = run_pipeline(0);
  if(rc == 10)
    return 1; /* already printed */
  if(rc != 0)
    FAILF("CS pipeline failed with code %d (consumed=%d sum=%lld/%lld)",
          rc, consumed_items, consumed_sum, produced_sum);

  rc = run_pipeline(1);
  if(rc == 10)
    return 1;
  if(rc != 0)
    FAILF("SRW pipeline failed with code %d (consumed=%d sum=%lld/%lld)",
          rc, consumed_items, consumed_sum, produced_sum);

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
