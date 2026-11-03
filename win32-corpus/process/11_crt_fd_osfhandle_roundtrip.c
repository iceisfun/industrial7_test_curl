/*
 * Test: 11_crt_fd_osfhandle_roundtrip
 *
 * Purpose: verify the CRT file-descriptor <-> OS handle bridge that curl's
 *   Windows tool code uses to get at the native handle behind a C FILE*:
 *   _open_osfhandle wraps an existing HANDLE in a CRT fd, _get_osfhandle
 *   returns the same HANDLE back, _isatty is 0 for a regular file, writes and
 *   reads through the fd reach the file, and after _close the fd is invalid
 *   (_get_osfhandle returns -1 with errno EBADF). A FILE* from _wfopen is also
 *   checked: fileno() then _get_osfhandle gives a disk handle.
 *
 * APIs: GetTempPathW, CreateDirectoryW, CreateFileW, _open_osfhandle,
 *   _get_osfhandle, _isatty, _write, _lseek, _read, _close, _wfopen, fileno,
 *   fclose, GetFileType, GetFileSize, DeleteFileW, RemoveDirectoryW.
 *
 * Success means: _get_osfhandle(fd) equals the original HANDLE; _isatty returns
 *   0; _write returns 6 and _read returns the same 6 bytes; GetFileType is
 *   FILE_TYPE_DISK; the file on disk is 6 bytes; _get_osfhandle on a closed fd
 *   returns -1; the FILE* path yields FILE_TYPE_DISK. All files live in a
 *   directory this test creates under %TEMP% and removes again.
 *
 * Source reference: src/tool_util.c:87 (intptr_t handle = _get_osfhandle(fd)
 *   followed by SetEndOfFile), src/tool_cb_wrt.c:363 (fhnd = _get_osfhandle
 *   (fileno(outs->stream)) with an isatty check first), and
 *   src/tool_operate.c:1358 (stream_isatty using isatty(fileno(stream))).
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
#include <string.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

#define NAME "crt_fd_osfhandle_roundtrip"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

static void put_u(wchar_t *dst, unsigned long v)
{
  wchar_t tmp[16];
  size_t n = 0, i;
  do {
    tmp[n++] = (wchar_t)(L'0' + (v % 10));
    v /= 10;
  } while(v);
  for(i = 0; i < n; i++)
    dst[i] = tmp[n - 1 - i];
  dst[n] = 0;
}

static int body(const wchar_t *path)
{
  HANDLE h, h2;
  intptr_t osh;
  int fd, rc;
  char buf[8];
  FILE *fp;
  DWORD fsize;

  h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  if(h == INVALID_HANDLE_VALUE)
    FAILF("CreateFileW(CREATE_NEW)");

  fd = _open_osfhandle((intptr_t)h, _O_RDWR | _O_BINARY);
  if(fd < 0) {
    CloseHandle(h);
    FAILF("_open_osfhandle");
  }

  osh = _get_osfhandle(fd);
  if(osh == -1 || (HANDLE)osh != h) {
    _close(fd);
    FAILF("_get_osfhandle(fd) does not return the original HANDLE");
  }

  if(_isatty(fd) != 0) {
    _close(fd);
    FAILF("_isatty reports a regular file as a terminal");
  }

  if(GetFileType(h) != FILE_TYPE_DISK) {
    _close(fd);
    FAILF("GetFileType(file) is not FILE_TYPE_DISK");
  }

  if(_write(fd, "abcdef", 6) != 6) {
    _close(fd);
    FAILF("_write(6 bytes)");
  }
  if(_lseek(fd, 0, SEEK_SET) != 0) {
    _close(fd);
    FAILF("_lseek(0)");
  }
  memset(buf, 0, sizeof(buf));
  if(_read(fd, buf, 6) != 6 || memcmp(buf, "abcdef", 6) != 0) {
    _close(fd);
    FAILF("_read did not return the written bytes");
  }

  /* _close also closes the underlying handle; do not CloseHandle(h) after. */
  if(_close(fd) != 0)
    FAILF("_close(fd)");
  errno = 0;
  if(_get_osfhandle(fd) != -1)
    FAILF("_get_osfhandle on a closed fd did not return -1");
  if(errno != EBADF)
    FAILF("errno after _get_osfhandle on closed fd is %d, expected EBADF", errno);

  /* The file must hold the 6 bytes on disk. */
  h2 = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                   FILE_ATTRIBUTE_NORMAL, NULL);
  if(h2 == INVALID_HANDLE_VALUE)
    FAILF("reopen file");
  fsize = GetFileSize(h2, NULL);
  CloseHandle(h2);
  if(fsize != 6)
    FAILF("file size %lu, expected 6", (unsigned long)fsize);

  /* FILE* -> fileno -> _get_osfhandle gives a disk handle. */
  fp = _wfopen(path, L"rb");
  if(!fp)
    FAILF("_wfopen(rb)");
  rc = 0;
  {
    HANDLE fh = (HANDLE)_get_osfhandle(fileno(fp));
    if(fh == INVALID_HANDLE_VALUE || fh == NULL) {
      rc = 1;
    }
    else if(GetFileType(fh) != FILE_TYPE_DISK) {
      rc = 2;
    }
    else if(_isatty(fileno(fp)) != 0) {
      rc = 3;
    }
  }
  fclose(fp);
  if(rc == 1)
    FAILF("_get_osfhandle(fileno(FILE*)) invalid");
  if(rc == 2)
    FAILF("GetFileType(fileno(FILE*)) is not FILE_TYPE_DISK");
  if(rc == 3)
    FAILF("_isatty(fileno(FILE*)) reports a terminal for a file");

  return 0;
}

static int run(void)
{
  wchar_t tmp[MAX_PATH];
  wchar_t dir[MAX_PATH + 64];
  wchar_t path[MAX_PATH + 96];
  DWORD n;
  int rc;

  n = GetTempPathW(MAX_PATH, tmp);
  if(n == 0 || n >= MAX_PATH)
    FAILF("GetTempPathW");

  wcscpy(dir, tmp);
  wcscat(dir, L"curl-corpus-proc-11-");
  {
    wchar_t pid[16];
    put_u(pid, GetCurrentProcessId());
    wcscat(dir, pid);
  }
  if(!CreateDirectoryW(dir, NULL))
    FAILF("CreateDirectoryW(temp dir)");

  wcscpy(path, dir);
  wcscat(path, L"\\data.bin");

  rc = body(path);

  DeleteFileW(path);
  RemoveDirectoryW(dir);
  return rc;
}

int main(void)
{
  int rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
