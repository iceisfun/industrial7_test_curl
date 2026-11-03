/*
 * Test: 04_crt_wfopen_wstat64
 *
 * Purpose: use the wide CRT file API on a non-ASCII path inside a private
 *          temp directory, the way curl's Windows file layer does when
 *          UNICODE is defined: _wfopen for read/write, _wstat64 for size and
 *          mode, _wunlink for removal, plus a narrow _stat64 check on a pure
 *          ASCII name when the temp path itself is ASCII.
 *
 * APIs:    GetTempPathW, CreateDirectoryW, RemoveDirectoryW, _wfopen,
 *          fwrite, fread, fclose, _wstat64, _stat64, _wunlink, errno
 *
 * Success: - _wfopen(L"tëst_€_名.txt", L"wb") succeeds and six
 *            bytes written are read back identical with _wfopen(..., L"rb")
 *          - _wstat64 reports st_size == 6 and S_IFREG in st_mode
 *          - _wstat64 on a directory reports S_IFDIR
 *          - _wunlink returns 0; afterwards _wstat64 returns -1 with
 *            errno == ENOENT and _wfopen(...,L"rb") returns NULL
 *          - _wfopen on a missing file in read mode returns NULL, ENOENT
 *
 * Source:  lib/curlx/win32-fopen.c:369-400 (curlx_win32_fopen uses
 *          _wfopen/_wfsopen under _UNICODE), lib/curlx/win32-fopen.c:440-469
 *          (curlx_win32_stat uses _wstati64, same struct family as
 *          _wstat64).
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
#include <sys/types.h>
#include <sys/stat.h>

#define NAME "crt_wfopen_wstat64"

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
  wchar_t dir[MAX_PATH];
  wchar_t tmp[MAX_PATH];
  wchar_t file[MAX_PATH + 64];
  wchar_t plain[MAX_PATH + 64];
  DWORD tlen;
  FILE *f = NULL;
  struct _stat64 st;
  char rbuf[16];
  size_t got;
  int r;
  const char payload[] = "hello\n";
  int dir_made = 0;
  int ascii_temp = 1;
  size_t i;

  tlen = GetTempPathW(MAX_PATH, tmp);
  CHECK(tlen > 0 && tlen < MAX_PATH, "GetTempPathW returned %lu",
        (unsigned long)tlen);
  for(i = 0; i < wcslen(tmp); i++)
    if(tmp[i] > 0x7f)
      ascii_temp = 0;

  _snwprintf(dir, MAX_PATH, L"%lsucorp04-%lu", tmp,
             (unsigned long)GetCurrentProcessId());
  dir[MAX_PATH - 1] = 0;
  CHECK(CreateDirectoryW(dir, NULL), "CreateDirectoryW failed");
  dir_made = 1;

  _snwprintf(file, MAX_PATH + 64, L"%ls\\tëst_€_名.txt", dir);
  file[MAX_PATH + 63] = 0;
  /* set up front so the cleanup path can always remove it */
  _snwprintf(plain, MAX_PATH + 64, L"%ls\\plain.bin", dir);
  plain[MAX_PATH + 63] = 0;

  /* 1. write through the wide CRT open */
  f = _wfopen(file, L"wb");
  CHECK(f != NULL, "_wfopen(wb) returned NULL for %ls", file);
  got = fwrite(payload, 1, sizeof(payload) - 1, f);
  CHECK(got == 6, "fwrite wrote %lu, expected 6", (unsigned long)got);
  CHECK(fclose(f) == 0, "fclose failed");
  f = NULL;

  /* 2. stat reports regular file, correct size */
  memset(&st, 0, sizeof(st));
  r = _wstat64(file, &st);
  CHECK(r == 0, "_wstat64 returned %d, expected 0", r);
  CHECK(st.st_size == 6, "st_size=%lld expected 6",
        (long long)st.st_size);
  CHECK((st.st_mode & _S_IFMT) == _S_IFREG,
        "st_mode=0x%x is not a regular file", (unsigned)st.st_mode);

  /* 3. read back identical bytes */
  f = _wfopen(file, L"rb");
  CHECK(f != NULL, "_wfopen(rb) returned NULL");
  memset(rbuf, 0, sizeof(rbuf));
  got = fread(rbuf, 1, sizeof(rbuf), f);
  CHECK(got == 6, "fread returned %lu, expected 6", (unsigned long)got);
  CHECK(memcmp(rbuf, payload, 6) == 0, "read bytes differ from payload");
  CHECK(fclose(f) == 0, "fclose(read) failed");
  f = NULL;

  /* 4. stat on the directory reports S_IFDIR */
  memset(&st, 0, sizeof(st));
  r = _wstat64(dir, &st);
  CHECK(r == 0, "_wstat64(dir) returned %d", r);
  CHECK((st.st_mode & _S_IFMT) == _S_IFDIR,
        "dir st_mode=0x%x is not a directory", (unsigned)st.st_mode);

  /* 5. narrow _stat64 on an ASCII name, only if the temp path is ASCII */
  if(ascii_temp) {
    char narrow_path[MAX_PATH + 64];
    char narrow_dir[MAX_PATH];
    int nl;

    f = _wfopen(plain, L"wb");
    CHECK(f != NULL, "_wfopen(plain.bin) failed");
    CHECK(fwrite("abc", 1, 3, f) == 3, "fwrite plain failed");
    CHECK(fclose(f) == 0, "fclose plain failed");
    f = NULL;

    nl = WideCharToMultiByte(CP_ACP, 0, dir, -1, narrow_dir,
                             sizeof(narrow_dir), NULL, NULL);
    CHECK(nl > 0, "WideCharToMultiByte(dir) failed");
    _snprintf(narrow_path, sizeof(narrow_path), "%s\\plain.bin", narrow_dir);
    memset(&st, 0, sizeof(st));
    r = _stat64(narrow_path, &st);
    CHECK(r == 0, "_stat64(%s) returned %d", narrow_path, r);
    CHECK(st.st_size == 3, "narrow st_size=%lld expected 3",
          (long long)st.st_size);
    CHECK(_wunlink(plain) == 0, "_wunlink(plain.bin) failed");
  }

  /* 6. unlink, then stat and open must fail with ENOENT */
  CHECK(_wunlink(file) == 0, "_wunlink(file) returned nonzero");
  memset(&st, 0, sizeof(st));
  errno = 0;
  r = _wstat64(file, &st);
  CHECK(r == -1, "_wstat64 after unlink returned %d, expected -1", r);
  CHECK(errno == ENOENT, "errno=%d after stat, expected ENOENT", errno);

  errno = 0;
  f = _wfopen(file, L"rb");
  CHECK(f == NULL, "_wfopen on deleted file returned a stream");
  CHECK(errno == ENOENT, "errno=%d after open, expected ENOENT", errno);

  printf("PASS %s\n", NAME);

out:
  if(f)
    fclose(f);
  if(dir_made) {
    /* remove leftovers from a failed run before the directory */
    _wunlink(file);
    _wunlink(plain);
    RemoveDirectoryW(dir);
  }
  return rc;
}
