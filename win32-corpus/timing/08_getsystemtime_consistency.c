/*
 * Test: timing_getsystemtime_consistency
 * Purpose: GetSystemTime (UTC SYSTEMTIME) agrees with
 *          GetSystemTimeAsFileTime once both are normalised to unix time,
 *          and the SYSTEMTIME fields are valid calendar values.
 * APIs: GetSystemTime, GetSystemTimeAsFileTime, FileTimeToSystemTime,
 *       SystemTimeToFileTime
 * Success: GetSystemTime fields are in range (year >= 2020, month 1..12,
 *          day 1..31, hour < 24, minute < 60, second < 60, ms < 1000);
 *          the unix seconds derived from both clocks differ by at most 2;
 *          SystemTimeToFileTime of the GetSystemTime value lands within
 *          2 s of GetSystemTimeAsFileTime; 100 consecutive samples never
 *          go backwards.
 * Source: curl lib/curlx/timeval.c:255 (curlx_gmtime) converts unix time to
 *         UTC calendar fields; lib/parsedate.c works in unix time. This test
 *         checks the Windows UTC clock that feeds those conversions.
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

#define EPOCH_DIFF 116444736000000000ULL

static ULONGLONG ft_u64(FILETIME f)
{
  return ((ULONGLONG)f.dwHighDateTime << 32) | (ULONGLONG)f.dwLowDateTime;
}

static long long ll_abs(long long v)
{
  return v < 0 ? -v : v;
}

int main(void)
{
  SYSTEMTIME st, prev_st;
  FILETIME ft_now, ft_from_st, ft_prev;
  long long sys_unix, ft_unix_s, from_st_unix;
  ULONGLONG from_st_u64;
  int i;

  GetSystemTime(&st);
  if(st.wYear < 2020 || st.wMonth < 1 || st.wMonth > 12 || st.wDay < 1 ||
     st.wDay > 31 || st.wHour >= 24 || st.wMinute >= 60 || st.wSecond >= 60 ||
     st.wMilliseconds >= 1000) {
    printf("FAIL timing_getsystemtime_consistency: invalid SYSTEMTIME %u-%u-%u %u:%u:%u.%u\n",
           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
           st.wMilliseconds);
    return 1;
  }

  GetSystemTimeAsFileTime(&ft_now);
  if(!SystemTimeToFileTime(&st, &ft_from_st)) {
    printf("FAIL timing_getsystemtime_consistency: SystemTimeToFileTime error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }

  ft_unix_s = (long long)((ft_u64(ft_now) - EPOCH_DIFF) / 10000000ULL);
  from_st_u64 = ft_u64(ft_from_st);
  from_st_unix = (long long)((from_st_u64 - EPOCH_DIFF) / 10000000ULL);
  sys_unix = from_st_unix;
  if(ll_abs(ft_unix_s - sys_unix) > 2) {
    printf("FAIL timing_getsystemtime_consistency: GetSystemTime (%lld) and GetSystemTimeAsFileTime (%lld) differ by more than 2 s\n",
           sys_unix, ft_unix_s);
    return 1;
  }

  /* Round-trip the SYSTEMTIME back to FILETIME: the 100 ns values must be
     within 2 s of each other. */
  if(ll_abs((long long)from_st_u64 - (long long)ft_u64(ft_now)) > 20000000LL) {
    printf("FAIL timing_getsystemtime_consistency: round-trip FILETIME off by more than 2 s\n");
    return 1;
  }

  prev_st = st;
  ft_prev = ft_now;
  for(i = 0; i < 100; i++) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    if(ft_u64(ft) < ft_u64(ft_prev)) {
      printf("FAIL timing_getsystemtime_consistency: GetSystemTimeAsFileTime went backwards on sample %d\n",
             i);
      return 1;
    }
    ft_prev = ft;
    GetSystemTime(&st);
    if(st.wYear < prev_st.wYear ||
       (st.wYear == prev_st.wYear && st.wMonth < prev_st.wMonth) ||
       (st.wYear == prev_st.wYear && st.wMonth == prev_st.wMonth &&
        st.wDay < prev_st.wDay)) {
      printf("FAIL timing_getsystemtime_consistency: GetSystemTime date went backwards on sample %d\n",
             i);
      return 1;
    }
    prev_st = st;
  }

  printf("PASS timing_getsystemtime_consistency\n");
  return 0;
}
