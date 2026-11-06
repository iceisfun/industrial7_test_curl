/*
 * Test: 17_gmtime64_range_limits
 * Purpose: The time_t range of the C runtime curl's date parsing
 *   (lib/parsedate.c, lib/curlx/timeval.c, curl_getdate) and cookie expiry
 *   depend on: _gmtime64_s, _mkgmtime64, _localtime64_s at the edges.
 * APIs: _gmtime64_s, _mkgmtime64, _time64
 * Success (probed on Windows 10 22H2, mingw default C runtime = msvcrt.dll):
 *   0, 2^31-1 and 2^31 (2038-01-19 03:14:08) convert with a 64 bit time_t;
 *   -1 converts to 1969-12-31 23:59:59; the lowest accepted value is -43200
 *   (1969-12-31 12:00:00): -43201 and 1900-01-01 fail with EINVAL (this
 *   runtime does not reach back before 1969, unlike the UCRT); the highest
 *   accepted value is 32535291599 and 32535291600 fails with EINVAL;
 *   _mkgmtime64 round-trips 2038-01-19 03:14:08 to 2147483648 and returns
 *   -1 for any 1969 date (including 1969-12-31 23:59:59, which is -1 itself
 *   and so indistinguishable from the error). Pre-1970
 *   inputs matter for curl's date parsing of cookie/HTTP dates.
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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if(!(cond)) {                                                          \
      printf("FAIL %s: ", TEST_NAME);                                      \
      printf(__VA_ARGS__);                                                 \
      printf(" [line %d, GetLastError=%lu]\n", __LINE__,                   \
             (unsigned long)GetLastError());                               \
      rc = 1;                                                              \
      goto out;                                                            \
    }                                                                      \
  } while(0)

__attribute__((unused)) static double qpc_ms(void)
{
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
}

__attribute__((unused)) static int is_wine(void)
{
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  return nt && GetProcAddress(nt, "wine_get_version") != NULL;
}

#define TEST_NAME "17_gmtime64_range_limits"

#include <time.h>

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  int rc = 0, e;
  struct tm t;
  __time64_t v = 0;

  memset(&t, 0, sizeof(t));
  CHECK(_gmtime64_s(&t, &v) == 0 && t.tm_year == 70 && t.tm_mday == 1, "epoch");
  v = 2147483647LL;
  CHECK(_gmtime64_s(&t, &v) == 0 && t.tm_year == 138 && t.tm_mday == 19 && t.tm_sec == 7, "2^31-1");
  v = 2147483648LL;
  CHECK(_gmtime64_s(&t, &v) == 0 && t.tm_year == 138 && t.tm_mday == 19 && t.tm_min == 14 && t.tm_sec == 8, "2^31");

  v = -1;
  memset(&t, 0, sizeof(t));
  e = _gmtime64_s(&t, &v);
  printf("INFO _gmtime64_s(-1): rc=%d year=%d mon=%d mday=%d %02d:%02d:%02d\n", e, t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
  CHECK(e == 0 && t.tm_year == 69 && t.tm_mon == 11 && t.tm_mday == 31 && t.tm_hour == 23 && t.tm_min == 59 && t.tm_sec == 59,
        "-1 handled differently (rc=%d)", e);

  /* msvcrt limits (probed) */
  v = -43200;
  e = _gmtime64_s(&t, &v);
  CHECK(e == 0 && t.tm_year == 69 && t.tm_mday == 31 && t.tm_hour == 12, "-43200 rc=%d", e);
  v = -43201;
  e = _gmtime64_s(&t, &v);
  CHECK(e == EINVAL, "-43201 returned %d, expected EINVAL", e);
  v = -2208988800LL; /* 1900-01-01 */
  e = _gmtime64_s(&t, &v);
  CHECK(e == EINVAL, "1900-01-01 returned %d, expected EINVAL", e);
  v = 32535291599LL;
  e = _gmtime64_s(&t, &v);
  printf("INFO _gmtime64_s(32535291599): rc=%d %d-%02d-%02d %02d:%02d:%02d\n", e, t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
  CHECK(e == 0, "32535291599 rc=%d", e);
  v = 32535291600LL;
  e = _gmtime64_s(&t, &v);
  CHECK(e == EINVAL, "32535291600 returned %d, expected EINVAL", e);

  memset(&t, 0, sizeof(t));
  t.tm_year = 138; t.tm_mon = 0; t.tm_mday = 19; t.tm_hour = 3; t.tm_min = 14; t.tm_sec = 8;
  v = _mkgmtime64(&t);
  CHECK(v == 2147483648LL, "_mkgmtime64 = %lld", (long long)v);
  memset(&t, 0, sizeof(t));
  t.tm_year = 69; t.tm_mon = 11; t.tm_mday = 31; t.tm_hour = 23; t.tm_min = 59; t.tm_sec = 59;
  v = _mkgmtime64(&t);
  CHECK(v == -1, "_mkgmtime64(1969-12-31 23:59:59) = %lld", (long long)v);
  memset(&t, 0, sizeof(t));
  t.tm_year = 69; t.tm_mon = 0; t.tm_mday = 1;
  v = _mkgmtime64(&t);
  CHECK(v == -1, "_mkgmtime64(1969-01-01) = %lld, expected -1 (failure)", (long long)v);

  printf("PASS %s\n", TEST_NAME);
out:
  return rc;
}
