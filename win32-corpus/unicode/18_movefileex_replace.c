/*
 * Test: 18_movefileex_replace
 * Purpose: curl's rename (curlx_win32_rename: MoveFileExW with
 *   MOVEFILE_REPLACE_EXISTING) used when finishing downloads / cookie jars,
 *   and the CRT rename it replaces.
 * APIs: MoveFileExW, MoveFileW, _wrename, CreateFileW, WriteFile, DeleteFileW
 * Source: lib/curlx/win32-fopen.c curlx_win32_rename.
 * Success (probed on Windows 10 22H2): MoveFileW onto an existing file fails
 *   with ERROR_ALREADY_EXISTS (183); MoveFileExW with REPLACE_EXISTING
 *   succeeds and the target holds the source's bytes and the source is gone;
 *   replacing a target that another handle holds open without
 *   FILE_SHARE_DELETE fails with ERROR_ACCESS_DENIED (5) and leaves both
 *   files; replacing a target that is open WITH FILE_SHARE_DELETE (no DELETE
 *   access) also fails with ERROR_ACCESS_DENIED (5): any open handle on the
 *   target blocks the replace; after the handle is closed it succeeds;
 *   _wrename onto an existing file fails with errno EEXIST (17); MoveFileExW
 *   of a missing source fails with ERROR_FILE_NOT_FOUND (2).
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

#define TEST_NAME "18_movefileex_replace"

static int put(const wchar_t *p, const char *s)
{
  DWORD w;
  HANDLE h = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(h == INVALID_HANDLE_VALUE)
    return 0;
  WriteFile(h, s, (DWORD)strlen(s), &w, NULL);
  CloseHandle(h);
  return 1;
}

static int get(const wchar_t *p, char *buf, int cap)
{
  DWORD r = 0;
  HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
  if(h == INVALID_HANDLE_VALUE)
    return -1;
  ReadFile(h, buf, (DWORD)cap - 1, &r, NULL);
  CloseHandle(h);
  buf[r] = 0;
  return (int)r;
}

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  int rc = 0;
  wchar_t tmp[MAX_PATH], a[MAX_PATH + 32], b[MAX_PATH + 32];
  char buf[32];
  HANDLE hold;
  DWORD e;
  int made = 0;

  CHECK(GetTempPathW(MAX_PATH, tmp) > 0, "GetTempPathW");
  _snwprintf(a, MAX_PATH + 31, L"%lsumv18a-%lu.tmp", tmp, (unsigned long)GetCurrentProcessId());
  _snwprintf(b, MAX_PATH + 31, L"%lsumv18b-%lu.tmp", tmp, (unsigned long)GetCurrentProcessId());
  a[MAX_PATH + 31] = b[MAX_PATH + 31] = 0;
  made = 1;

  CHECK(put(a, "AAA") && put(b, "BB"), "create files");
  SetLastError(0);
  CHECK(!MoveFileW(a, b) && GetLastError() == ERROR_ALREADY_EXISTS, "MoveFileW onto existing err=%lu", (unsigned long)GetLastError());
  errno = 0;
  CHECK(_wrename(a, b) == -1 && errno == EEXIST, "_wrename errno=%d", errno);

  CHECK(MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING), "replace failed");
  CHECK(get(b, buf, sizeof(buf)) == 3 && strcmp(buf, "AAA") == 0, "target content '%s'", buf);
  CHECK(GetFileAttributesW(a) == INVALID_FILE_ATTRIBUTES, "source still exists");

  /* target held open without FILE_SHARE_DELETE */
  CHECK(put(a, "CCCC"), "recreate source");
  hold = CreateFileW(b, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  CHECK(hold != INVALID_HANDLE_VALUE, "hold open");
  SetLastError(0);
  CHECK(!MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING), "replace over open file succeeded");
  e = GetLastError();
  printf("INFO replace over held target err=%lu\n", (unsigned long)e);
  CHECK(e == ERROR_ACCESS_DENIED, "error %lu, expected 5", (unsigned long)e);
  CHECK(get(a, buf, sizeof(buf)) == 4 && get(b, buf, sizeof(buf)) == 3, "files changed after failed replace");
  CloseHandle(hold);

  /* target held open with FILE_SHARE_DELETE */
  hold = CreateFileW(b, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
  CHECK(hold != INVALID_HANDLE_VALUE, "hold open (2)");
  SetLastError(0);
  CHECK(!MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING), "replace over shared-delete file succeeded");
  e = GetLastError();
  printf("INFO replace over FILE_SHARE_DELETE target err=%lu\n", (unsigned long)e);
  CHECK(e == ERROR_ACCESS_DENIED, "shared-delete error %lu, expected 5", (unsigned long)e);
  CloseHandle(hold);
  CHECK(MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING), "replace after closing failed");
  CHECK(get(b, buf, sizeof(buf)) == 4 && strcmp(buf, "CCCC") == 0, "content after replace '%s'", buf);

  SetLastError(0);
  CHECK(!MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING) && GetLastError() == ERROR_FILE_NOT_FOUND,
        "missing source err=%lu", (unsigned long)GetLastError());

  printf("PASS %s\n", TEST_NAME);
out:
  if(made) {
    DeleteFileW(a);
    DeleteFileW(b);
  }
  return rc;
}
