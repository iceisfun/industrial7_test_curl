/*
 * Test: critical_section_internals
 *
 * Purpose: the observable state of a CRITICAL_SECTION initialised exactly the
 * way curl does (Curl_mutex_init = InitializeCriticalSectionEx(m, 0,
 * CRITICAL_SECTION_NO_DEBUG_INFO), lib/curl_threads.h). The LockCount /
 * RecursionCount / OwningThread fields are documented in winnt.h and relied
 * upon by debuggers and by libraries that assert lock ownership; pinning them
 * detects a runtime that implements a different lock layout.
 *
 * APIs: InitializeCriticalSectionEx, InitializeCriticalSection,
 *   InitializeCriticalSectionAndSpinCount, EnterCriticalSection,
 *   TryEnterCriticalSection, LeaveCriticalSection, DeleteCriticalSection,
 *   GetCurrentThreadId.
 *
 * Success (probed on Windows 10 22H2): a fresh section has LockCount -1,
 * RecursionCount 0, OwningThread NULL and DebugInfo == (void *)-1 (also for
 * plain InitializeCriticalSection). After Enter: LockCount -2, RecursionCount
 * 1, OwningThread == the caller's thread id; a recursive Enter gives
 * RecursionCount 2 and leaves LockCount at -2; after both Leaves the fields
 * are back to -1 / 0 / NULL. InitializeCriticalSectionEx(.., 4000, ..) stores
 * SpinCount 4000; InitializeCriticalSectionAndSpinCount with the high bit set
 * (0x80000100) stores 0x100 (the bit is stripped); flags 0x80000000 are
 * rejected with ERROR_INVALID_PARAMETER (87).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "critical_section_internals"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

int main(void)
{
  CRITICAL_SECTION c, d, e, f, g;

  if(!InitializeCriticalSectionEx(&c, 0, CRITICAL_SECTION_NO_DEBUG_INFO))
    FAILF("InitializeCriticalSectionEx failed (GLE=%lu)", (unsigned long)GetLastError());
  if(c.LockCount != -1 || c.RecursionCount != 0 || c.OwningThread != NULL)
    FAILF("fresh section: LockCount=%ld Recursion=%ld Owner=%p", (long)c.LockCount, (long)c.RecursionCount,
          (void *)c.OwningThread);
  if(c.DebugInfo != (PRTL_CRITICAL_SECTION_DEBUG)(LONG_PTR)-1)
    FAILF("NO_DEBUG_INFO section has DebugInfo=%p, expected (void *)-1", (void *)c.DebugInfo);

  EnterCriticalSection(&c);
  if(c.LockCount != -2 || c.RecursionCount != 1 || c.OwningThread != (HANDLE)(ULONG_PTR)GetCurrentThreadId())
    FAILF("after Enter: LockCount=%ld Recursion=%ld Owner=%p", (long)c.LockCount, (long)c.RecursionCount,
          (void *)c.OwningThread);
  EnterCriticalSection(&c);
  if(c.LockCount != -2 || c.RecursionCount != 2)
    FAILF("after recursive Enter: LockCount=%ld Recursion=%ld", (long)c.LockCount, (long)c.RecursionCount);
  LeaveCriticalSection(&c);
  if(c.RecursionCount != 1 || c.OwningThread != (HANDLE)(ULONG_PTR)GetCurrentThreadId())
    FAILF("after one Leave: Recursion=%ld Owner=%p", (long)c.RecursionCount, (void *)c.OwningThread);
  LeaveCriticalSection(&c);
  if(c.LockCount != -1 || c.RecursionCount != 0 || c.OwningThread != NULL)
    FAILF("after both Leaves: LockCount=%ld Recursion=%ld Owner=%p", (long)c.LockCount,
          (long)c.RecursionCount, (void *)c.OwningThread);
  if(!TryEnterCriticalSection(&c) || c.RecursionCount != 1)
    FAILF("TryEnterCriticalSection on a free section failed");
  LeaveCriticalSection(&c);
  DeleteCriticalSection(&c);

  InitializeCriticalSection(&d);
  if(d.DebugInfo != (PRTL_CRITICAL_SECTION_DEBUG)(LONG_PTR)-1)
    FAILF("InitializeCriticalSection DebugInfo=%p, expected (void *)-1", (void *)d.DebugInfo);
  DeleteCriticalSection(&d);

  if(!InitializeCriticalSectionEx(&e, 4000, 0) || e.SpinCount != 4000)
    FAILF("InitializeCriticalSectionEx spin 4000 stored %llu", (unsigned long long)e.SpinCount);
  DeleteCriticalSection(&e);

  if(!InitializeCriticalSectionAndSpinCount(&f, 0x80000100) || f.SpinCount != 0x100)
    FAILF("InitializeCriticalSectionAndSpinCount(0x80000100) stored 0x%llx, expected 0x100",
          (unsigned long long)f.SpinCount);
  DeleteCriticalSection(&f);

  SetLastError(0);
  if(InitializeCriticalSectionEx(&g, 0, 0x80000000) || GetLastError() != ERROR_INVALID_PARAMETER)
    FAILF("flags 0x80000000 should fail with 87 (GLE=%lu)", (unsigned long)GetLastError());

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
