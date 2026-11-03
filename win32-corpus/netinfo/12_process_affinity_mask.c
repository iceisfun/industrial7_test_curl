/*
 * Test: process_affinity_mask
 *
 * Purpose: Read the current process affinity mask with GetProcessAffinityMask
 *   and check it against the system mask and the active processor count. The
 *   process mask must be a non-empty subset of the system mask.
 *
 * APIs: GetProcessAffinityMask, GetCurrentProcess, GetActiveProcessorCount,
 *   DWORD_PTR (kernel32).
 *
 * Success means: GetProcessAffinityMask(GetCurrentProcess()) returns TRUE;
 *   the process mask is nonzero; the system mask is nonzero; the process mask
 *   is a subset of the system mask; popcount(process mask) <=
 *   GetActiveProcessorCount(ALL_PROCESSOR_GROUPS).
 *   No affinity is changed.
 *
 * Source reference: none. curl's tree has no GetProcessAffinityMask call site.
 *   This pins the affinity contract for the corpus.
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
#define TEST_NAME "process_affinity_mask"

#include <windows.h>
#include <stdio.h>

static unsigned popcount_dw(DWORD_PTR v)
{
  unsigned n = 0;
  while(v) {
    n += (unsigned)(v & 1);
    v >>= 1;
  }
  return n;
}

int main(void)
{
  DWORD_PTR proc_mask = 0, sys_mask = 0;
  DWORD active;
  unsigned bits;

  if(!GetProcessAffinityMask(GetCurrentProcess(), &proc_mask, &sys_mask)) {
    printf("FAIL %s: GetProcessAffinityMask GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }
  if(proc_mask == 0 || sys_mask == 0) {
    printf("FAIL %s: zero mask (process=0x%llx system=0x%llx)\n", TEST_NAME,
           (unsigned long long)proc_mask, (unsigned long long)sys_mask);
    return 1;
  }
  if((proc_mask & ~sys_mask) != 0) {
    printf("FAIL %s: process mask 0x%llx is not a subset of system mask 0x%llx\n",
           TEST_NAME, (unsigned long long)proc_mask, (unsigned long long)sys_mask);
    return 1;
  }

  active = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
  bits = popcount_dw(proc_mask);
  if(active == 0) {
    printf("FAIL %s: GetActiveProcessorCount returned 0\n", TEST_NAME);
    return 1;
  }
  if(bits == 0 || bits > active) {
    printf("FAIL %s: process mask has %u bits, active processors=%lu\n",
           TEST_NAME, bits, (unsigned long)active);
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
