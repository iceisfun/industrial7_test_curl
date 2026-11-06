/*
 * Test: timing_system_time_precise_gpa
 * Purpose: Resolve GetSystemTimePreciseAsFileTime at run time with
 *          LoadLibrary/GetProcAddress, falling back to
 *          GetSystemTimeAsFileTime when it is not exported, and check that
 *          the resulting wall-clock values are sane and mutually consistent.
 * APIs: LoadLibraryW, GetProcAddress, GetSystemTimePreciseAsFileTime
 *       (dynamic), GetSystemTimeAsFileTime (fallback)
 * Success: the chosen function returns FILETIMEs that convert to a unix
 *          time between 2020-01-01 and 2100-01-01; 1000 samples are
 *          non-decreasing; the precise and legacy clocks agree within 2 s.
 *          GetSystemTimePreciseAsFileTime must be exported on Windows 10 (probed);
 *          only under wine a missing export falls back to the legacy clock.
 * Source: none in curl's Windows code path for the precise clock; curl's
 *         wall-clock consumers (lib/parsedate.c) only need unix seconds.
 *         This test covers the Windows primitive itself, which curl does
 *         not call directly.
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
#include <windows.h>
#include <stdio.h>

typedef VOID (WINAPI *pfn_filetime_t)(LPFILETIME);

#define EPOCH_DIFF 116444736000000000ULL

static ULONGLONG ft_u64(FILETIME f)
{
  return ((ULONGLONG)f.dwHighDateTime << 32) | (ULONGLONG)f.dwLowDateTime;
}

static long long ft_unix(FILETIME f)
{
  return (long long)((ft_u64(f) - EPOCH_DIFF) / 10000000ULL);
}

static long long ll_abs(long long v)
{
  return v < 0 ? -v : v;
}

int main(void)
{
  HMODULE k32;
  pfn_filetime_t precise, legacy, chosen;
  FILETIME ft, ft_legacy, prev_ft;
  long long unix_s;
  int i;

  k32 = LoadLibraryW(L"kernel32.dll");
  if(!k32) {
    printf("FAIL timing_system_time_precise_gpa: LoadLibraryW(kernel32) error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }

  /* Function-pointer casts go through void* to avoid -Wcast-function-type. */
  precise = (pfn_filetime_t)(void *)GetProcAddress(k32, "GetSystemTimePreciseAsFileTime");
  legacy = (pfn_filetime_t)(void *)GetProcAddress(k32, "GetSystemTimeAsFileTime");
  if(!legacy) {
    printf("FAIL timing_system_time_precise_gpa: GetSystemTimeAsFileTime not exported\n");
    FreeLibrary(k32);
    return 1;
  }
  if(!precise) {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if(!(nt && GetProcAddress(nt, "wine_get_version"))) {
      printf("FAIL timing_system_time_precise_gpa: GetSystemTimePreciseAsFileTime not exported by kernel32 on Windows 10\n");
      FreeLibrary(k32);
      return 1;
    }
  }
  chosen = precise ? precise : legacy;

  chosen(&ft);
  unix_s = ft_unix(ft);
  if(unix_s < 1577836800LL || unix_s > 4102444800LL) {
    printf("FAIL timing_system_time_precise_gpa: unix time %lld outside 2020..2100\n",
           unix_s);
    FreeLibrary(k32);
    return 1;
  }

  prev_ft = ft;
  for(i = 0; i < 1000; i++) {
    chosen(&ft);
    if(ft_u64(ft) < ft_u64(prev_ft)) {
      printf("FAIL timing_system_time_precise_gpa: FILETIME decreased on sample %d\n", i);
      FreeLibrary(k32);
      return 1;
    }
    prev_ft = ft;
  }

  /* Cross-check the chosen clock against the legacy clock. */
  legacy(&ft_legacy);
  if(ll_abs((long long)ft_u64(ft) - (long long)ft_u64(ft_legacy)) > 20000000LL) {
    printf("FAIL timing_system_time_precise_gpa: clocks differ by more than 2 s\n");
    FreeLibrary(k32);
    return 1;
  }

  FreeLibrary(k32);
  printf("PASS timing_system_time_precise_gpa\n");
  return 0;
}
