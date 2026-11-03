/*
 * Test: timing_filetime_unix_epoch
 * Purpose: FILETIME <-> unix epoch conversion with known reference points,
 *          including a value beyond 2038 that needs 64-bit arithmetic.
 * APIs: SystemTimeToFileTime, FileTimeToSystemTime
 * Success: 1970-01-01 maps to FILETIME 116444736000000000 exactly; the
 *          formula (ft - 116444736000000000) / 1e7 yields 946684800 for
 *          2000-01-01 and 2147483648 for 2038-01-19 03:14:08; 1 tick before
 *          the epoch is 1969-12-31 23:59:59.999; 1700000000 round-trips to
 *          2023-11-14 22:13:20 UTC (Tuesday); FILETIME 0 is 1601-01-01.
 * Source: curl lib/parsedate.c works in unix time_t, so a Windows FILETIME
 *         must be converted to unix seconds exactly; this checks that
 *         conversion (the divisor is not in curl's code, it is the 1601 to
 *         1970 offset).
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

static FILETIME u64_ft(ULONGLONG v)
{
  FILETIME f;
  f.dwLowDateTime = (DWORD)(v & 0xFFFFFFFFULL);
  f.dwHighDateTime = (DWORD)(v >> 32);
  return f;
}

static long long ft_unix(FILETIME f)
{
  return (long long)((ft_u64(f) - EPOCH_DIFF) / 10000000ULL);
}

static int sys_to_unix(WORD y, WORD mo, WORD d, WORD h, WORD mi, WORD s,
                       long long *out, DWORD *err)
{
  SYSTEMTIME st;
  FILETIME ft;
  ZeroMemory(&st, sizeof(st));
  st.wYear = y;
  st.wMonth = mo;
  st.wDay = d;
  st.wHour = h;
  st.wMinute = mi;
  st.wSecond = s;
  if(!SystemTimeToFileTime(&st, &ft)) {
    *err = GetLastError();
    return 0;
  }
  *out = ft_unix(ft);
  return 1;
}

#define CHECK_UNIX(y, mo, d, h, mi, s, expect, label)                         \
  do {                                                                        \
    long long got_;                                                           \
    DWORD err_ = 0;                                                           \
    if(!sys_to_unix(y, mo, d, h, mi, s, &got_, &err_)) {                      \
      printf("FAIL timing_filetime_unix_epoch: SystemTimeToFileTime(%s) error %lu\n", \
             label, (unsigned long)err_);                                     \
      return 1;                                                               \
    }                                                                         \
    if(got_ != (expect)) {                                                    \
      printf("FAIL timing_filetime_unix_epoch: %s gave unix %lld, expected %lld\n", \
             label, got_, (long long)(expect));                               \
      return 1;                                                               \
    }                                                                         \
  } while(0)

int main(void)
{
  SYSTEMTIME st;
  FILETIME ft;
  ULONGLONG v;

  /* 1970-01-01 00:00:00 must be exactly the divisor. */
  ZeroMemory(&st, sizeof(st));
  st.wYear = 1970;
  st.wMonth = 1;
  st.wDay = 1;
  if(!SystemTimeToFileTime(&st, &ft)) {
    printf("FAIL timing_filetime_unix_epoch: SystemTimeToFileTime(1970) error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  if(ft_u64(ft) != EPOCH_DIFF) {
    printf("FAIL timing_filetime_unix_epoch: 1970-01-01 FILETIME is %llu, expected %llu\n",
           (unsigned long long)ft_u64(ft), (unsigned long long)EPOCH_DIFF);
    return 1;
  }

  CHECK_UNIX(2000, 1, 1, 0, 0, 0, 946684800LL, "2000-01-01");
  CHECK_UNIX(2038, 1, 19, 3, 14, 8, 2147483648LL, "2038-01-19 03:14:08");
  CHECK_UNIX(2023, 11, 14, 22, 13, 20, 1700000000LL, "2023-11-14 22:13:20");

  /* One tick before the epoch: 1969-12-31 23:59:59.9999999. */
  v = EPOCH_DIFF - 1;
  ft = u64_ft(v);
  ZeroMemory(&st, sizeof(st));
  if(!FileTimeToSystemTime(&ft, &st)) {
    printf("FAIL timing_filetime_unix_epoch: FileTimeToSystemTime error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  if(st.wYear != 1969 || st.wMonth != 12 || st.wDay != 31 ||
     st.wHour != 23 || st.wMinute != 59 || st.wSecond != 59 ||
     st.wMilliseconds != 999) {
    printf("FAIL timing_filetime_unix_epoch: epoch-1 tick is %u-%u-%u %u:%u:%u.%u\n",
           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
           st.wMilliseconds);
    return 1;
  }

  /* 1700000000 back to calendar fields, checking weekday too. */
  ft = u64_ft(EPOCH_DIFF + 1700000000ULL * 10000000ULL);
  ZeroMemory(&st, sizeof(st));
  if(!FileTimeToSystemTime(&ft, &st)) {
    printf("FAIL timing_filetime_unix_epoch: FileTimeToSystemTime(1700000000) error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  if(st.wYear != 2023 || st.wMonth != 11 || st.wDay != 14 ||
     st.wHour != 22 || st.wMinute != 13 || st.wSecond != 20 ||
     st.wDayOfWeek != 2) {
    printf("FAIL timing_filetime_unix_epoch: 1700000000 decoded as %u-%u-%u %u:%u:%u dow %u\n",
           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
           st.wDayOfWeek);
    return 1;
  }

  /* FILETIME 0 is the start of 1601. */
  ft = u64_ft(0);
  ZeroMemory(&st, sizeof(st));
  if(!FileTimeToSystemTime(&ft, &st) || st.wYear != 1601 || st.wMonth != 1 || st.wDay != 1) {
    printf("FAIL timing_filetime_unix_epoch: FILETIME 0 did not decode to 1601-01-01 (error %lu)\n",
           (unsigned long)GetLastError());
    return 1;
  }

  printf("PASS timing_filetime_unix_epoch\n");
  return 0;
}
