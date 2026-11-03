/*
 * Test: timing_gmtime_s_epoch
 * Purpose: gmtime_s, the thread-safe UTC breakdown that curl's
 *          curlx_gmtime wrapper uses on Windows, returns correct calendar
 *          fields for known time_t values, including one past 2038 (needs
 *          a 64-bit time_t).
 * APIs: gmtime_s (msvcrt/ucrt), time_t
 * Success: gmtime_s returns 0 and the fields match: 0 -> 1970-01-01
 *          00:00:00 Thursday (wday 4, yday 0); 1000000000 -> 2001-09-09
 *          01:46:40 Sunday (yday 251); 1700000000 -> 2023-11-14 22:13:20
 *          Tuesday (yday 317); 4102444800 -> 2100-01-01 (tm_year 200).
 *          sizeof(time_t) must be 8.
 * Source: curl lib/curlx/timeval.c:255-276 (curlx_gmtime uses gmtime_s on
 *         _WIN32, returning CURLE_BAD_FUNCTION_ARGUMENT on nonzero).
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
#include <time.h>
#include <stdio.h>

struct expect {
  time_t t;
  int year, mon, mday, hour, min, sec, wday, yday;
  const char *label;
};

static int check(const struct expect *e)
{
  struct tm tm;
  errno_t rc;
  time_t t = e->t;

  ZeroMemory(&tm, sizeof(tm));
  rc = gmtime_s(&tm, &t);
  if(rc != 0) {
    printf("FAIL timing_gmtime_s_epoch: gmtime_s(%s) returned %d\n", e->label, (int)rc);
    return 0;
  }
  if(tm.tm_year + 1900 != e->year || tm.tm_mon + 1 != e->mon ||
     tm.tm_mday != e->mday || tm.tm_hour != e->hour || tm.tm_min != e->min ||
     tm.tm_sec != e->sec || tm.tm_wday != e->wday || tm.tm_yday != e->yday) {
    printf("FAIL timing_gmtime_s_epoch: %s decoded as %d-%02d-%02d %02d:%02d:%02d wday %d yday %d\n",
           e->label, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
           tm.tm_min, tm.tm_sec, tm.tm_wday, tm.tm_yday);
    return 0;
  }
  return 1;
}

int main(void)
{
  static const struct expect cases[] = {
    {0, 1970, 1, 1, 0, 0, 0, 4, 0, "epoch 0"},
    {1000000000, 2001, 9, 9, 1, 46, 40, 0, 251, "1000000000"},
    {1700000000, 2023, 11, 14, 22, 13, 20, 2, 317, "1700000000"},
    {4102444800, 2100, 1, 1, 0, 0, 0, 5, 0, "4102444800"},
  };
  size_t i;

  if(sizeof(time_t) != 8) {
    printf("FAIL timing_gmtime_s_epoch: sizeof(time_t) is %lu, expected 8\n",
           (unsigned long)sizeof(time_t));
    return 1;
  }

  for(i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    if(!check(&cases[i]))
      return 1;
  }

  printf("PASS timing_gmtime_s_epoch\n");
  return 0;
}
