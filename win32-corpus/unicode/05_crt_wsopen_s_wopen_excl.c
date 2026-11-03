/*
 * Test: 05_crt_wsopen_s_wopen_excl
 *
 * Purpose: exercise the low-level wide CRT descriptor API that curl uses
 *          for its own file opens on Windows: _wsopen_s with _SH_DENYNO and
 *          create/exclusive flags, _write/_read/_lseek on the descriptor,
 *          and _wopen for a read-only open of the same non-ASCII name.
 *
 * APIs:    _wsopen_s, _wopen, _write, _read, _lseek, _close, _wunlink,
 *          RemoveDirectoryW, CreateDirectoryW, GetTempPathW
 *
 * Success: - _wsopen_s(_O_WRONLY|_O_CREAT|_O_EXCL|_O_BINARY, _SH_DENYNO)
 *            returns 0 and a valid descriptor
 *          - a second _wsopen_s with _O_EXCL on the same name returns
 *            errno EEXIST (17) and leaves the descriptor at -1
 *          - _write of "abc" returns 3; _lseek(fd, 0, SEEK_END) returns 3
 *          - _wopen(_O_RDONLY|_O_BINARY) reads back "abc"
 *          - _wopen on a missing name returns -1 with errno ENOENT
 *          - _wsopen_s with _O_TRUNC on the existing file yields size 0
 *
 * Source:  lib/curlx/win32-fopen.c:328-367 (curlx_win32_open calls
 *          _wsopen_s(&res, target, oflag, _SH_DENYNO, pmode) under _UNICODE).
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
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>

#define NAME "crt_wsopen_s_wopen_excl"

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if(!(cond)) {                                                          \
      printf("FAIL %s: ", NAME);                                           \
      printf(__VA_ARGS__);                                                 \
      printf(" [line %d, GetLastError=%lu, errno=%d]\n", __LINE__,         \
             (unsigned long)GetLastError(), errno);                        \
      rc = 1;                                                              \
      goto out;                                                            \
    }                                                                      \
  } while(0)

int main(void)
{
  int rc = 0;
  wchar_t tmp[MAX_PATH];
  wchar_t dir[MAX_PATH];
  wchar_t path[MAX_PATH + 64];
  int fd = -1, fd2 = -1, err, n;
  char buf[16];
  long pos;
  int dir_made = 0;

  if(GetTempPathW(MAX_PATH, tmp) == 0)
    CHECK(0, "GetTempPathW failed");
  _snwprintf(dir, MAX_PATH, L"%lsucorp05-%lu", tmp,
             (unsigned long)GetCurrentProcessId());
  dir[MAX_PATH - 1] = 0;
  CHECK(CreateDirectoryW(dir, NULL), "CreateDirectoryW failed");
  dir_made = 1;

  _snwprintf(path, MAX_PATH + 64, L"%ls\\oü日.bin", dir);
  path[MAX_PATH + 63] = 0;

  /* 1. exclusive create through _wsopen_s */
  err = _wsopen_s(&fd, path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                  _SH_DENYNO, _S_IREAD | _S_IWRITE);
  CHECK(err == 0, "_wsopen_s create returned errno-style %d", err);
  CHECK(fd >= 0, "_wsopen_s created fd=%d", fd);

  /* 2. second exclusive create must fail with EEXIST */
  err = _wsopen_s(&fd2, path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                  _SH_DENYNO, _S_IREAD | _S_IWRITE);
  CHECK(err == EEXIST, "second exclusive create returned %d, expected %d",
        err, EEXIST);
  CHECK(fd2 == -1, "failed open left fd2=%d, expected -1", fd2);

  /* 3. write and seek on the descriptor */
  n = _write(fd, "abc", 3);
  CHECK(n == 3, "_write returned %d, expected 3", n);
  pos = _lseek(fd, 0, SEEK_END);
  CHECK(pos == 3, "_lseek(SEEK_END) returned %ld, expected 3", pos);
  CHECK(_close(fd) == 0, "_close(write fd) failed");
  fd = -1;

  /* 4. read-only _wopen of the same name */
  fd = _wopen(path, _O_RDONLY | _O_BINARY);
  CHECK(fd >= 0, "_wopen(RDONLY) returned %d", fd);
  memset(buf, 0, sizeof(buf));
  n = _read(fd, buf, sizeof(buf));
  CHECK(n == 3, "_read returned %d, expected 3", n);
  CHECK(memcmp(buf, "abc", 3) == 0, "_read content differs");
  CHECK(_close(fd) == 0, "_close(read fd) failed");
  fd = -1;

  /* 5. _wopen on a missing name */
  errno = 0;
  _snwprintf(path, MAX_PATH + 64, L"%ls\\missingü.bin", dir);
  path[MAX_PATH + 63] = 0;
  fd = _wopen(path, _O_RDONLY | _O_BINARY);
  CHECK(fd == -1, "_wopen(missing) returned %d, expected -1", fd);
  CHECK(errno == ENOENT, "_wopen(missing) errno=%d, expected ENOENT", errno);

  /* 6. _O_TRUNC through _wsopen_s empties the file */
  _snwprintf(path, MAX_PATH + 64, L"%ls\\oü日.bin", dir);
  path[MAX_PATH + 63] = 0;
  err = _wsopen_s(&fd, path, _O_WRONLY | _O_TRUNC | _O_BINARY,
                  _SH_DENYNO, _S_IREAD | _S_IWRITE);
  CHECK(err == 0 && fd >= 0, "_wsopen_s(TRUNC) failed, err=%d", err);
  CHECK(_close(fd) == 0, "_close(trunc fd) failed");
  fd = -1;
  {
    struct _stat64 st;
    memset(&st, 0, sizeof(st));
    CHECK(_wstat64(path, &st) == 0, "_wstat64 after truncate failed");
    CHECK(st.st_size == 0, "size after _O_TRUNC is %lld, expected 0",
          (long long)st.st_size);
  }

  CHECK(_wunlink(path) == 0, "_wunlink(path) failed");
  printf("PASS %s\n", NAME);

out:
  if(fd >= 0)
    _close(fd);
  if(fd2 >= 0)
    _close(fd2);
  if(dir_made) {
    _snwprintf(path, MAX_PATH + 64, L"%ls\\oü日.bin", dir);
    path[MAX_PATH + 63] = 0;
    _wunlink(path);
    RemoveDirectoryW(dir);
  }
  return rc;
}
