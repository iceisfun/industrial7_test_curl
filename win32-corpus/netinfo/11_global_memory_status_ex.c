/*
 * Test: global_memory_status_ex
 *
 * Purpose: Read physical and virtual memory totals with GlobalMemoryStatusEx,
 *   checking the dwLength contract and the internal consistency of the
 *   returned figures. Covers the failure path for a dwLength of 0.
 *
 * APIs: GlobalMemoryStatusEx, MEMORYSTATUSEX (kernel32).
 *
 * Success means: the call with dwLength=sizeof(MEMORYSTATUSEX) returns TRUE;
 *   dwMemoryLoad is in [0, 100]; ullTotalPhys > 0; ullAvailPhys <= ullTotalPhys;
 *   ullAvailVirtual <= ullTotalVirtual; ullTotalVirtual > 0; the call with
 *   dwLength=0 returns FALSE and does not modify the output structure's
 *   totals (it stays zero).
 *
 * Source reference: none. curl's tree has no GlobalMemoryStatusEx call site.
 *   Included to pin the memory-query contract for the corpus.
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
#define TEST_NAME "global_memory_status_ex"

#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
  MEMORYSTATUSEX ms;
  MEMORYSTATUSEX zero;
  BOOL ok;

  memset(&ms, 0, sizeof(ms));
  ms.dwLength = sizeof(ms);
  ok = GlobalMemoryStatusEx(&ms);
  if(!ok) {
    printf("FAIL %s: GlobalMemoryStatusEx GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }
  if(ms.dwMemoryLoad > 100) {
    printf("FAIL %s: dwMemoryLoad=%lu exceeds 100\n",
           TEST_NAME, (unsigned long)ms.dwMemoryLoad);
    return 1;
  }
  if(ms.ullTotalPhys == 0) {
    printf("FAIL %s: ullTotalPhys is 0\n", TEST_NAME);
    return 1;
  }
  if(ms.ullAvailPhys > ms.ullTotalPhys) {
    printf("FAIL %s: ullAvailPhys=%llu > ullTotalPhys=%llu\n", TEST_NAME,
           (unsigned long long)ms.ullAvailPhys, (unsigned long long)ms.ullTotalPhys);
    return 1;
  }
  if(ms.ullTotalVirtual == 0) {
    printf("FAIL %s: ullTotalVirtual is 0\n", TEST_NAME);
    return 1;
  }
  if(ms.ullAvailVirtual > ms.ullTotalVirtual) {
    printf("FAIL %s: ullAvailVirtual=%llu > ullTotalVirtual=%llu\n", TEST_NAME,
           (unsigned long long)ms.ullAvailVirtual, (unsigned long long)ms.ullTotalVirtual);
    return 1;
  }

  /* Failure path: dwLength must be set; 0 is rejected. */
  memset(&zero, 0, sizeof(zero));
  zero.dwLength = 0;
  SetLastError(0);
  ok = GlobalMemoryStatusEx(&zero);
  if(ok) {
    printf("FAIL %s: GlobalMemoryStatusEx with dwLength=0 unexpectedly succeeded\n", TEST_NAME);
    return 1;
  }
  if(zero.ullTotalPhys != 0 || zero.ullTotalVirtual != 0) {
    printf("FAIL %s: output written despite dwLength=0 failure\n", TEST_NAME);
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
