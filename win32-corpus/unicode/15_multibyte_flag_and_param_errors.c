/*
 * Test: 15_multibyte_flag_and_param_errors
 * Purpose: Error codes of MultiByteToWideChar / WideCharToMultiByte for bad
 *   parameters and flags, the inputs curl's curlx_convert_* helpers must not
 *   crash on (lib/curlx/multibyte.c).
 * APIs: MultiByteToWideChar, WideCharToMultiByte, GetLastError
 * Success (probed on Windows 10 22H2; these differ from the documentation):
 *   - MultiByteToWideChar(CP_UTF8) accepts flags 0, 1, 2, 4 and 8
 *     (MB_ERR_INVALID_CHARS) and rejects 0x10, 0x20, 0x40, 0x80 and 0x1000
 *     with ERROR_INVALID_FLAGS (1004);
 *   - WideCharToMultiByte(CP_UTF8) accepts flags 0, 0x10, 0x20, 0x40 and
 *     0x80 (WC_ERR_INVALID_CHARS) and rejects 1, 2, 4 and 8 with 1004;
 *   - lpDefaultChar and lpUsedDefaultChar with CP_UTF8 are IGNORED (the call
 *     succeeds, used stays FALSE) although the documentation says they must
 *     be NULL;
 *   - NULL source -> 87 (ERROR_INVALID_PARAMETER), zero source length -> 87,
 *     buffer too small -> 122, lone surrogate with WC_ERR_INVALID_CHARS ->
 *     1113 (ERROR_NO_UNICODE_TRANSLATION), L"" with -1 -> 1 and a NUL byte;
 *   - CP_ACP: ASCII converts like CP_UTF8, flag 0x1000 -> 1004.
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

#define TEST_NAME "15_multibyte_flag_and_param_errors"

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  int rc = 0, n;
  wchar_t w[8];
  char u[8];
  char def = '?';
  BOOL used = FALSE;
  const wchar_t lone[] = { 0xD800, 0 };

  {
    DWORD fl;
    for(fl = 0; fl <= 0x80; fl = fl ? fl << 1 : 1) {
      SetLastError(0);
      n = MultiByteToWideChar(CP_UTF8, fl, "a", -1, w, 8);
      printf("INFO MB2WC UTF8 flags=0x%02lx: n=%d err=%lu\n", (unsigned long)fl, n, (unsigned long)GetLastError());
      SetLastError(0);
      n = WideCharToMultiByte(CP_UTF8, fl, L"a", -1, u, 8, NULL, NULL);
      printf("INFO WC2MB UTF8 flags=0x%02lx: n=%d err=%lu\n", (unsigned long)fl, n, (unsigned long)GetLastError());
    }
    SetLastError(0);
    n = MultiByteToWideChar(CP_UTF8, 0x1000, "a", -1, w, 8);
    printf("INFO MB2WC UTF8 flags=0x1000: n=%d err=%lu\n", n, (unsigned long)GetLastError());
  }

  {
    DWORD fl;
    for(fl = 0; fl <= 0x80; fl = fl ? fl << 1 : 1) {
      int ok_mb = (fl <= 8);
      int ok_wc = (fl == 0 || fl >= 0x10);
      SetLastError(0);
      n = MultiByteToWideChar(CP_UTF8, fl, "a", -1, w, 8);
      CHECK(ok_mb ? (n == 2) : (n == 0 && GetLastError() == ERROR_INVALID_FLAGS),
            "MB2WC flags 0x%lx n=%d err=%lu", (unsigned long)fl, n, (unsigned long)GetLastError());
      SetLastError(0);
      n = WideCharToMultiByte(CP_UTF8, fl, L"a", -1, u, 8, NULL, NULL);
      CHECK(ok_wc ? (n == 2) : (n == 0 && GetLastError() == ERROR_INVALID_FLAGS),
            "WC2MB flags 0x%lx n=%d err=%lu", (unsigned long)fl, n, (unsigned long)GetLastError());
    }
    SetLastError(0);
    n = MultiByteToWideChar(CP_UTF8, 0x1000, "a", -1, w, 8);
    CHECK(n == 0 && GetLastError() == ERROR_INVALID_FLAGS, "MB2WC flags 0x1000 n=%d", n);
  }

  SetLastError(0);
  n = MultiByteToWideChar(CP_UTF8, 0, NULL, -1, w, 8);
  CHECK(n == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "NULL source n=%d", n);

  SetLastError(0);
  n = MultiByteToWideChar(CP_UTF8, 0, "abc", 0, w, 8);
  CHECK(n == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "zero length n=%d", n);

  SetLastError(0);
  n = MultiByteToWideChar(CP_UTF8, 0, "abc", -1, w, 2);
  CHECK(n == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "small buffer n=%d", n);

  /* lpDefaultChar / lpUsedDefaultChar are IGNORED for CP_UTF8 on this system
     (the documentation says they must be NULL) */
  SetLastError(0);
  n = WideCharToMultiByte(CP_UTF8, 0, L"a", -1, u, 8, &def, NULL);
  CHECK(n == 2, "default char n=%d err=%lu", n, (unsigned long)GetLastError());
  SetLastError(0);
  used = TRUE;
  n = WideCharToMultiByte(CP_UTF8, 0, L"a", -1, u, 8, NULL, &used);
  CHECK(n == 2 && used == FALSE, "used-default flag n=%d used=%d", n, used);

  SetLastError(0);
  n = WideCharToMultiByte(CP_UTF8, 0, NULL, -1, u, 8, NULL, NULL);
  CHECK(n == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "NULL wide n=%d", n);

  SetLastError(0);
  n = WideCharToMultiByte(CP_UTF8, 0, L"\x20ac", -1, u, 3, NULL, NULL);
  CHECK(n == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "small utf8 buffer n=%d", n);

  SetLastError(0);
  n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, lone, -1, u, 8, NULL, NULL);
  CHECK(n == 0 && GetLastError() == ERROR_NO_UNICODE_TRANSLATION, "lone surrogate n=%d", n);

  SetLastError(0);
  n = WideCharToMultiByte(CP_UTF8, 0, L"", -1, u, 8, NULL, NULL);
  CHECK(n == 1 && u[0] == 0, "empty string n=%d", n);

  n = MultiByteToWideChar(CP_ACP, 0, "Az09", -1, w, 8);
  CHECK(n == 5 && w[0] == L'A' && w[3] == L'9', "CP_ACP ascii n=%d", n);
  n = MultiByteToWideChar(CP_ACP, 0x1000, "a", -1, w, 8);
  CHECK(n == 0 && GetLastError() == ERROR_INVALID_FLAGS, "CP_ACP bad flag n=%d", n);

  printf("PASS %s\n", TEST_NAME);
out:
  return rc;
}
