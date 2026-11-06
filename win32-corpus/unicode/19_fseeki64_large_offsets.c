/*
 * Test: 19_fseeki64_large_offsets
 * Purpose: 64-bit file offsets curl needs for resume (-C) and ranges on
 *   Windows, where C "long" is 32 bit: _fseeki64/_ftelli64, _lseeki64, and
 *   SetFilePointerEx beyond 4 GiB without allocating disk (nothing is written
 *   past offset 0; the file stays tiny).
 * APIs: _wfopen, _fseeki64, _ftelli64, fseek, ftell, _wopen, _lseeki64,
 *   SetFilePointerEx, GetFileSizeEx
 * Success (probed on Windows 10 22H2): after writing one byte,
 *   _fseeki64(f, 5 GiB, SEEK_SET) returns 0 and _ftelli64 returns exactly
 *   5368709120; a seek to a negative offset fails with -1/EINVAL and leaves
 *   the position unchanged; _lseeki64 to 5 GiB returns it; SetFilePointerEx
 *   to 5 GiB returns it in the out-parameter; the file size stays 1 (a seek
 *   past the end allocates nothing).
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

#define TEST_NAME "19_fseeki64_large_offsets"

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  int rc = 0, fd;
  wchar_t tmp[MAX_PATH], p[MAX_PATH + 32];
  FILE *f = NULL;
  long long five = 5368709120LL, pos;
  LARGE_INTEGER li, out, sz;
  HANDLE h = INVALID_HANDLE_VALUE;
  int made = 0;

  CHECK(GetTempPathW(MAX_PATH, tmp) > 0, "GetTempPathW");
  _snwprintf(p, MAX_PATH + 31, L"%lsumv19-%lu.tmp", tmp, (unsigned long)GetCurrentProcessId());
  p[MAX_PATH + 31] = 0;
  f = _wfopen(p, L"wb");
  CHECK(f != NULL, "_wfopen");
  made = 1;
  CHECK(fputs("x", f) >= 0 && fflush(f) == 0, "write");
  CHECK(_fseeki64(f, five, SEEK_SET) == 0, "_fseeki64 5GiB errno=%d", errno);
  pos = _ftelli64(f);
  printf("INFO _ftelli64 after seek = %lld\n", pos);
  CHECK(pos == five, "_ftelli64 = %lld", pos);

  errno = 0;
  CHECK(_fseeki64(f, -1, SEEK_SET) == -1 && errno == EINVAL, "negative seek errno=%d", errno);
  CHECK(_ftelli64(f) == five, "position changed by a failed seek");
  fclose(f);
  f = NULL;

  fd = _wopen(p, _O_RDONLY | _O_BINARY);
  CHECK(fd >= 0, "_wopen");
  pos = _lseeki64(fd, five, SEEK_SET);
  printf("INFO _lseeki64 = %lld\n", pos);
  CHECK(pos == five, "_lseeki64 = %lld", pos);
  _close(fd);

  h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  CHECK(h != INVALID_HANDLE_VALUE, "CreateFileW");
  li.QuadPart = five;
  out.QuadPart = 0;
  CHECK(SetFilePointerEx(h, li, &out, FILE_BEGIN) && out.QuadPart == five, "SetFilePointerEx out=%lld", out.QuadPart);
  CHECK(GetFileSizeEx(h, &sz) && sz.QuadPart == 1, "file size %lld, expected 1", sz.QuadPart);

  printf("PASS %s\n", TEST_NAME);
out:
  if(h != INVALID_HANDLE_VALUE)
    CloseHandle(h);
  if(f)
    fclose(f);
  if(made)
    DeleteFileW(p);
  return rc;
}
