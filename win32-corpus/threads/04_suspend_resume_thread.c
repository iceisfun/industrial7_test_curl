/*
 * Test: suspend_resume_thread
 *
 * Purpose: SuspendThread/ResumeThread return the previous suspend count, a
 *   thread created with CREATE_SUSPENDED does not run until resumed, and a
 *   suspended thread stops making progress while suspended.
 *
 * APIs: CreateThread (CREATE_SUSPENDED), SuspendThread, ResumeThread,
 *   WaitForSingleObject, GetExitCodeThread, InterlockedIncrement, Sleep,
 *   CloseHandle.
 *
 * Success: a suspended-at-create thread has not run after 100 ms, ResumeThread
 *   returns 1; a running spinner suspends with previous count 0, a second
 *   suspend returns 1, counter stops advancing while suspended, and it
 *   advances again once fully resumed.
 *
 * curl reference: no curl code suspends threads; this covers the thread
 *   primitives used by the curl test-suite helper threads (tests/server).
 *   Stands in for the create/start sequence used by Curl_thread_create
 *   (lib/curl_threads.c:35).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "suspend_resume_thread"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static volatile LONG ran_flag = 0;
static volatile LONG ticks = 0;
static volatile LONG stop_flag = 0;

static DWORD WINAPI marker(LPVOID p)
{
  (void)p;
  InterlockedExchange(&ran_flag, 1);
  return 0;
}

static DWORD WINAPI spinner(LPVOID p)
{
  (void)p;
  while(!stop_flag) {
    InterlockedIncrement(&ticks);
    Sleep(1);
  }
  return 0;
}

int main(void)
{
  HANDLE h1, h2;
  DWORD tid1 = 0, tid2 = 0, prev;
  LONG t1, t2, t3, t4;

  /* 1. CREATE_SUSPENDED thread does not run until resumed */
  h1 = CreateThread(NULL, 0, marker, NULL, CREATE_SUSPENDED, &tid1);
  if(!h1)
    FAILF("CreateThread(CREATE_SUSPENDED) failed (GLE=%lu)", GetLastError());
  Sleep(100);
  if(InterlockedCompareExchange(&ran_flag, 0, 0) != 0)
    FAILF("CREATE_SUSPENDED thread ran before ResumeThread");

  prev = ResumeThread(h1);
  if(prev != 1)
    FAILF("ResumeThread returned previous count %lu, expected 1 (GLE=%lu)", prev, GetLastError());
  if(WaitForSingleObject(h1, 5000) != WAIT_OBJECT_0)
    FAILF("resumed thread did not finish (GLE=%lu)", GetLastError());
  if(InterlockedCompareExchange(&ran_flag, 0, 0) != 1)
    FAILF("resumed thread did not set its flag");
  CloseHandle(h1);

  /* 2. suspend a running thread */
  h2 = CreateThread(NULL, 0, spinner, NULL, 0, &tid2);
  if(!h2)
    FAILF("CreateThread(spinner) failed (GLE=%lu)", GetLastError());
  Sleep(50);

  prev = SuspendThread(h2);
  if(prev != 0)
    FAILF("first SuspendThread returned %lu, expected 0 (GLE=%lu)", prev, GetLastError());
  t1 = InterlockedCompareExchange(&ticks, 0, 0);
  Sleep(100);
  t2 = InterlockedCompareExchange(&ticks, 0, 0);
  if(t2 != t1)
    FAILF("counter advanced while suspended (%ld -> %ld)", (long)t1, (long)t2);

  /* 3. second suspend stacks: returns previous count 1 */
  prev = SuspendThread(h2);
  if(prev != 1)
    FAILF("second SuspendThread returned %lu, expected 1 (GLE=%lu)", prev, GetLastError());

  /* one resume leaves the thread suspended (count goes 2 -> 1) */
  prev = ResumeThread(h2);
  if(prev != 2)
    FAILF("first ResumeThread returned %lu, expected 2 (GLE=%lu)", prev, GetLastError());
  t3 = InterlockedCompareExchange(&ticks, 0, 0);
  Sleep(100);
  t4 = InterlockedCompareExchange(&ticks, 0, 0);
  if(t4 != t3)
    FAILF("counter advanced while still suspended once (%ld -> %ld)", (long)t3, (long)t4);

  /* second resume makes it run (count 1 -> 0) */
  prev = ResumeThread(h2);
  if(prev != 1)
    FAILF("second ResumeThread returned %lu, expected 1 (GLE=%lu)", prev, GetLastError());
  Sleep(100);
  if(InterlockedCompareExchange(&ticks, 0, 0) <= t4)
    FAILF("counter did not advance after full resume");

  InterlockedExchange(&stop_flag, 1);
  if(WaitForSingleObject(h2, 5000) != WAIT_OBJECT_0)
    FAILF("spinner did not stop after stop flag (GLE=%lu)", GetLastError());
  CloseHandle(h2);

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
