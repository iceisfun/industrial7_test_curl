/*
 * Test: system_info
 *
 * Purpose: Validate the fields of GetSystemInfo and GetNativeSystemInfo that
 *   a native allocator depends on: page size, allocation granularity,
 *   the application address range, the processor count, and the processor
 *   architecture for the build target.
 *
 * APIs: GetSystemInfo, GetNativeSystemInfo, GetActiveProcessorCount
 *   (kernel32).
 *
 * Success means: dwPageSize is a power of two in [4096, 1 MiB];
 *   dwAllocationGranularity is a power of two >= dwPageSize; lpMinimum
 *   ApplicationAddress < lpMaximumApplicationAddress; a stack address lies
 *   inside that range; dwNumberOfProcessors >= 1 and does not exceed
 *   GetActiveProcessorCount(ALL_PROCESSOR_GROUPS); the architecture is
 *   PROCESSOR_ARCHITECTURE_AMD64 for this x86_64 build and the native
 *   architecture is not reported as unknown (0xFFFF). Failure of
 *   GetActiveProcessorCount (returns 0) is a FAIL.
 *
 * Source reference: none in curl's tree for GetSystemInfo. Included to pin
 *   the page, granularity and processor-count contract for the corpus.
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
#define TEST_NAME "system_info"

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static int is_pow2(unsigned long long v)
{
  return v != 0 && (v & (v - 1)) == 0;
}

int main(void)
{
  SYSTEM_INFO si, nsi;
  DWORD active;
  int stack_marker = 0;
  uintptr_t here = (uintptr_t)&stack_marker;
  uintptr_t lo, hi;

  GetSystemInfo(&si);
  GetNativeSystemInfo(&nsi);

  if(!is_pow2(si.dwPageSize) || si.dwPageSize < 4096 || si.dwPageSize > (1UL << 20)) {
    printf("FAIL %s: dwPageSize=%lu not a power of two in [4096, 1MiB]\n",
           TEST_NAME, (unsigned long)si.dwPageSize);
    return 1;
  }
  if(!is_pow2(si.dwAllocationGranularity) ||
     si.dwAllocationGranularity < si.dwPageSize) {
    printf("FAIL %s: dwAllocationGranularity=%lu invalid (page=%lu)\n",
           TEST_NAME, (unsigned long)si.dwAllocationGranularity,
           (unsigned long)si.dwPageSize);
    return 1;
  }

  lo = (uintptr_t)si.lpMinimumApplicationAddress;
  hi = (uintptr_t)si.lpMaximumApplicationAddress;
  if(!(lo < hi)) {
    printf("FAIL %s: min app address not below max app address\n", TEST_NAME);
    return 1;
  }
  if(here < lo || here > hi) {
    printf("FAIL %s: stack address %p outside [%p, %p]\n", TEST_NAME,
           (void *)here, si.lpMinimumApplicationAddress,
           si.lpMaximumApplicationAddress);
    return 1;
  }

  active = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
  if(active == 0) {
    printf("FAIL %s: GetActiveProcessorCount returned 0 GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }
  if(si.dwNumberOfProcessors < 1 || si.dwNumberOfProcessors > active) {
    printf("FAIL %s: dwNumberOfProcessors=%lu outside [1, %lu]\n", TEST_NAME,
           (unsigned long)si.dwNumberOfProcessors, (unsigned long)active);
    return 1;
  }

#if defined(_M_X64) || defined(__x86_64__)
  if(si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
    printf("FAIL %s: wProcessorArchitecture=%u (want AMD64=%u)\n", TEST_NAME,
           (unsigned)si.wProcessorArchitecture, (unsigned)PROCESSOR_ARCHITECTURE_AMD64);
    return 1;
  }
#endif
  if(nsi.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_UNKNOWN) {
    printf("FAIL %s: GetNativeSystemInfo architecture is UNKNOWN\n", TEST_NAME);
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
