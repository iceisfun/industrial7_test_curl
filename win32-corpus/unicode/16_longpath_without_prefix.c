/*
 * Test: 16_longpath_without_prefix
 * Purpose: Why curl's fix_excessive_path() adds the \\?\ prefix: in a process
 *   without a longPathAware manifest, Win32 file APIs reject non-prefixed
 *   paths of MAX_PATH or more, while the prefixed form works.
 * APIs: CreateDirectoryW, CreateFileW, GetFileAttributesW, _wfopen, _wstat64,
 *   RemoveDirectoryW, DeleteFileW, GetTempPathW
 * Source: lib/curlx/win32-fopen.c fix_excessive_path.
 * Success (probed on Windows 10 22H2, no manifest): with a 270 character
 *   path of 280+ characters below the temp directory, the non-prefixed
 *   CreateDirectoryW, CreateFileW and GetFileAttributesW all fail with
 *   ERROR_PATH_NOT_FOUND (3), _wfopen fails with errno ENOENT (2), and the
 *   \\?\-prefixed forms of all of them succeed.
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

#define TEST_NAME "16_longpath_without_prefix"

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  int rc = 0, i;
  wchar_t tmp[MAX_PATH], base[MAX_PATH + 32], dir[600], file[700], pre[720];
  wchar_t seg[64];
  HANDLE h;
  FILE *f;
  DWORD e, attr;
  int made = 0;
  size_t len;

  CHECK(GetTempPathW(MAX_PATH, tmp) > 0, "GetTempPathW");
  _snwprintf(base, MAX_PATH + 31, L"%lsulp16-%lu", tmp, (unsigned long)GetCurrentProcessId());
  base[MAX_PATH + 31] = 0;
  CHECK(CreateDirectoryW(base, NULL), "create base");
  made = 1;
  wcscpy(dir, base);
  for(i = 0; i < 4; i++) {
    _snwprintf(seg, 63, L"\\%0*d", 60, i);
    seg[63] = 0;
    wcscat(dir, seg);
    _snwprintf(pre, 719, L"\\\\?\\%ls", dir);
    pre[719] = 0;
    SetLastError(0);
    if(wcslen(dir) < 240)
      CHECK(CreateDirectoryW(dir, NULL), "level %d plain mkdir len %u", i,
            (unsigned)wcslen(dir));
    else {
      BOOL ok = CreateDirectoryW(dir, NULL);
      e = GetLastError();
      printf("INFO plain CreateDirectoryW len=%u ok=%d err=%lu\n",
             (unsigned)wcslen(dir), ok, (unsigned long)e);
      CHECK(!ok && e == ERROR_PATH_NOT_FOUND, "plain long mkdir ok=%d err=%lu", ok, (unsigned long)e);
      CHECK(CreateDirectoryW(pre, NULL), "prefixed mkdir");
    }
  }
  /* dir is now longer than 248; build a file in it */
  len = wcslen(dir);
  CHECK(len > 248, "dir length %u", (unsigned)len);
  _snwprintf(file, 699, L"%ls\\f.txt", dir);
  file[699] = 0;
  _snwprintf(pre, 719, L"\\\\?\\%ls", file);
  pre[719] = 0;
  CHECK(wcslen(file) > MAX_PATH, "file path length %u", (unsigned)wcslen(file));

  SetLastError(0);
  h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  e = GetLastError();
  printf("INFO plain CreateFileW len=%u h=%p err=%lu\n", (unsigned)wcslen(file), h, (unsigned long)e);
  CHECK(h == INVALID_HANDLE_VALUE && e == ERROR_PATH_NOT_FOUND,
        "plain CreateFileW err=%lu, expected 3", (unsigned long)e);
  h = CreateFileW(pre, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  CHECK(h != INVALID_HANDLE_VALUE, "prefixed CreateFileW");
  CloseHandle(h);

  SetLastError(0);
  attr = GetFileAttributesW(file);
  e = GetLastError();
  printf("INFO plain GetFileAttributesW attr=0x%lx err=%lu\n", (unsigned long)attr, (unsigned long)e);
  CHECK(attr == INVALID_FILE_ATTRIBUTES && e == ERROR_PATH_NOT_FOUND,
        "plain GetFileAttributesW err=%lu, expected 3", (unsigned long)e);
  CHECK(GetFileAttributesW(pre) != INVALID_FILE_ATTRIBUTES, "prefixed attributes");

  errno = 0;
  f = _wfopen(file, L"rb");
  printf("INFO plain _wfopen f=%p errno=%d\n", (void *)f, errno);
  CHECK(f == NULL && errno == ENOENT, "plain _wfopen f=%p errno=%d", (void *)f, errno);
  f = _wfopen(pre, L"rb");
  CHECK(f != NULL, "prefixed _wfopen");
  fclose(f);

  printf("PASS %s\n", TEST_NAME);
out:
  /* cleanup, deepest first, always via the prefixed form */
  if(made) {
    _snwprintf(pre, 719, L"\\\\?\\%ls\\f.txt", dir);
    pre[719] = 0;
    DeleteFileW(pre);
    for(i = 3; i >= 0; i--) {
      wchar_t *p = wcsrchr(dir, L'\\');
      _snwprintf(pre, 719, L"\\\\?\\%ls", dir);
      pre[719] = 0;
      RemoveDirectoryW(pre);
      if(p) *p = 0;
    }
    _snwprintf(pre, 719, L"\\\\?\\%ls", base);
    pre[719] = 0;
    RemoveDirectoryW(pre);
  }
  return rc;
}
