/*
 * Test: 17_searchpath_module_filename
 * Purpose: The file-location primitives curl uses to find its CA bundle and
 *   config next to the executable (lib/curl_sspi / src/tool_doswin.c
 *   FindWin32CACert via SearchPathW, GetModuleFileNameW for the exe dir).
 * APIs: SearchPathW, GetModuleFileNameW, GetSystemDirectoryW,
 *   GetCurrentDirectoryW, SetCurrentDirectoryW
 * Success (probed on Windows 10 22H2): GetModuleFileNameW(NULL) returns the
 *   length of an absolute path ending in this program's name; with a buffer
 *   of 8 it returns 8, writes a NUL-terminated truncation (7 characters) and
 *   sets ERROR_INSUFFICIENT_BUFFER (122); SearchPathW(NULL, L"kernel32.dll",
 *   NULL) finds <system dir>\kernel32.dll; SearchPathW of a name that does
 *   not exist fails with ERROR_FILE_NOT_FOUND (2) returning 0; SearchPathW
 *   with an explicit directory finds a file there and fills lpFilePart; the
 *   required-size query (nBufferLength 0) returns length + 1; SearchPathW
 *   with the extension argument appends ".dll" for "ws2_32"; the exe's own
 *   directory is found when passed as search path.
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

#define TEST_NAME "17_searchpath_module_filename"

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  int rc = 0;
  wchar_t exe[MAX_PATH], sys[MAX_PATH], found[MAX_PATH], want[MAX_PATH + 16];
  wchar_t small[8], dir[MAX_PATH], *part = NULL, *slash;
  DWORD n, e;

  n = GetModuleFileNameW(NULL, exe, MAX_PATH);
  CHECK(n > 3 && exe[1] == L':' && exe[2] == L'\\', "module name '%ls' (%lu)", exe, (unsigned long)n);
  CHECK(wcslen(exe) == n, "returned length %lu != wcslen %u", (unsigned long)n, (unsigned)wcslen(exe));

  SetLastError(0);
  memset(small, 0xAA, sizeof(small));
  n = GetModuleFileNameW(NULL, small, 8);
  e = GetLastError();
  printf("INFO truncated module name: n=%lu err=%lu len=%u\n", (unsigned long)n, (unsigned long)e, (unsigned)wcsnlen(small, 8));
  CHECK(n == 8 && e == ERROR_INSUFFICIENT_BUFFER, "truncation n=%lu err=%lu", (unsigned long)n, (unsigned long)e);
  CHECK(small[7] == 0 && wcsncmp(small, exe, 7) == 0, "truncated name is not NUL terminated prefix");

  CHECK(GetSystemDirectoryW(sys, MAX_PATH) > 3, "GetSystemDirectoryW");
  _snwprintf(want, MAX_PATH + 15, L"%ls\\kernel32.dll", sys);
  want[MAX_PATH + 15] = 0;
  n = SearchPathW(NULL, L"kernel32.dll", NULL, MAX_PATH, found, &part);
  CHECK(n == wcslen(want) && _wcsicmp(found, want) == 0, "kernel32 found '%ls' (%lu)", found, (unsigned long)n);
  CHECK(part && _wcsicmp(part, L"kernel32.dll") == 0, "file part");
  n = SearchPathW(NULL, L"kernel32.dll", NULL, 0, NULL, NULL);
  CHECK(n == wcslen(want) + 1, "size query %lu", (unsigned long)n);
  n = SearchPathW(NULL, L"ws2_32", L".dll", MAX_PATH, found, NULL);
  CHECK(n > 0 && _wcsicmp(found + wcslen(found) - 10, L"ws2_32.dll") == 0, "extension append '%ls'", found);

  SetLastError(0);
  n = SearchPathW(NULL, L"curl-test-no-such-file.crt", NULL, MAX_PATH, found, NULL);
  e = GetLastError();
  CHECK(n == 0 && e == ERROR_FILE_NOT_FOUND, "missing file n=%lu err=%lu", (unsigned long)n, (unsigned long)e);

  /* explicit directory: this exe's own directory */
  wcscpy(dir, exe);
  slash = wcsrchr(dir, L'\\');
  CHECK(slash != NULL, "no slash in exe path");
  part = slash + 1;
  *slash = 0;
  n = SearchPathW(dir, part, NULL, MAX_PATH, found, &part);
  CHECK(n == wcslen(exe) && _wcsicmp(found, exe) == 0, "own dir search '%ls' (%lu)", found, (unsigned long)n);
  CHECK(part && _wcsicmp(part, wcsrchr(exe, L'\\') + 1) == 0, "own dir file part");

  printf("PASS %s\n", TEST_NAME);
out:
  return rc;
}
