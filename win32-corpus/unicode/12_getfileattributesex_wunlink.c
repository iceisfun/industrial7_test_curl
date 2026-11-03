/*
 * Test: 12_getfileattributesex_wunlink
 *
 * Purpose: check the attribute and removal calls curl's file layer makes on
 *          a wide path: GetFileAttributesExW for size, attributes and times,
 *          GetFileAttributesW for existence, and _wunlink for removal,
 *          including the read-only case where removal must fail with EACCES
 *          until the attribute is cleared, and the missing-file case.
 *
 * APIs:    GetFileAttributesExW, GetFileAttributesW, SetFileAttributesW,
 *          _wunlink, DeleteFileW, _wfopen, CreateDirectoryW,
 *          RemoveDirectoryW, GetTempPathW, errno, GetLastError
 *
 * Success: - GetFileAttributesExW(file, GetFileExInfoStandard) succeeds
 *            with nFileSizeLow == 3, no DIRECTORY bit, and a non-zero
 *            last-write time
 *          - GetFileAttributesExW on a missing name fails with
 *            ERROR_FILE_NOT_FOUND (2)
 *          - after SetFileAttributesW(FILE_ATTRIBUTE_READONLY) the
 *            GetFileAttributesExW result carries FILE_ATTRIBUTE_READONLY
 *          - _wunlink on the read-only file returns -1 with errno EACCES (13)
 *            and the file still exists
 *          - after clearing the attribute _wunlink returns 0 and the name is
 *            gone (GetFileAttributesW returns INVALID_FILE_ATTRIBUTES, error 2)
 *          - _wunlink on a missing name returns -1 with errno ENOENT (2)
 *
 * Source:  lib/curlx/win32-fopen.c:440-469 (curlx_win32_stat) reads metadata
 *          through the wide CRT path; lib/curlx/win32-fopen.c:507-565
 *          (curlx_win32_rename) and lib/curlx/win32-fopen.c:328-367 show the
 *          wide-path plumbing shared with removal.
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
#include <errno.h>
#include <io.h>
#include <sys/stat.h>

#define NAME "getfileattributesex_wunlink"

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
  wchar_t file[MAX_PATH + 64];
  wchar_t missing[MAX_PATH + 64];
  WIN32_FILE_ATTRIBUTE_DATA fad;
  HANDLE w;
  DWORD n = 0;
  int dir_made = 0, file_made = 0;
  int r;

  CHECK(GetTempPathW(MAX_PATH, tmp) > 0, "GetTempPathW failed");
  _snwprintf(dir, MAX_PATH, L"%lsucorp12-%lu", tmp,
             (unsigned long)GetCurrentProcessId());
  dir[MAX_PATH - 1] = 0;
  CHECK(CreateDirectoryW(dir, NULL), "CreateDirectoryW failed");
  dir_made = 1;

  _snwprintf(file, MAX_PATH + 64, L"%ls\\atté.dat", dir);
  file[MAX_PATH + 63] = 0;
  _snwprintf(missing, MAX_PATH + 64, L"%ls\\nothereé.dat", dir);
  missing[MAX_PATH + 63] = 0;

  w = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  CHECK(w != INVALID_HANDLE_VALUE, "create file failed");
  CHECK(WriteFile(w, "xyz", 3, &n, NULL) && n == 3, "WriteFile failed");
  CHECK(CloseHandle(w), "CloseHandle failed");
  file_made = 1;

  /* 1. standard attributes and size */
  memset(&fad, 0, sizeof(fad));
  CHECK(GetFileAttributesExW(file, GetFileExInfoStandard, &fad),
        "GetFileAttributesExW(file) failed");
  CHECK(fad.nFileSizeLow == 3, "size %lu expected 3",
        (unsigned long)fad.nFileSizeLow);
  CHECK(fad.nFileSizeHigh == 0, "high size %lu expected 0",
        (unsigned long)fad.nFileSizeHigh);
  CHECK(!(fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY),
        "file reported as directory");
  CHECK(fad.ftLastWriteTime.dwLowDateTime != 0 ||
        fad.ftLastWriteTime.dwHighDateTime != 0,
        "last write time is zero");

  /* 2. missing file through GetFileAttributesExW */
  memset(&fad, 0, sizeof(fad));
  SetLastError(0);
  CHECK(!GetFileAttributesExW(missing, GetFileExInfoStandard, &fad),
        "GetFileAttributesExW(missing) unexpectedly succeeded");
  CHECK(GetLastError() == ERROR_FILE_NOT_FOUND,
        "missing lookup error %lu, expected 2",
        (unsigned long)GetLastError());

  /* 3. read-only flag shows through */
  CHECK(SetFileAttributesW(file, FILE_ATTRIBUTE_READONLY),
        "SetFileAttributesW(RO) failed");
  memset(&fad, 0, sizeof(fad));
  CHECK(GetFileAttributesExW(file, GetFileExInfoStandard, &fad),
        "GetFileAttributesExW after RO failed");
  CHECK(fad.dwFileAttributes & FILE_ATTRIBUTE_READONLY,
        "READONLY bit not reported (attrs=0x%lx)",
        (unsigned long)fad.dwFileAttributes);

  /* 4. _wunlink refuses a read-only file */
  errno = 0;
  r = _wunlink(file);
  CHECK(r == -1, "_wunlink(RO) returned %d, expected -1", r);
  CHECK(errno == EACCES, "_wunlink(RO) errno=%d, expected EACCES", errno);
  CHECK(GetFileAttributesW(file) != INVALID_FILE_ATTRIBUTES,
        "read-only file vanished after refused unlink");

  /* 5. clear the attribute, then unlink succeeds */
  CHECK(SetFileAttributesW(file, FILE_ATTRIBUTE_NORMAL),
        "SetFileAttributesW(NORMAL) failed");
  errno = 0;
  r = _wunlink(file);
  CHECK(r == 0, "_wunlink after clear returned %d, expected 0", r);
  file_made = 0;

  SetLastError(0);
  CHECK(GetFileAttributesW(file) == INVALID_FILE_ATTRIBUTES,
        "file still present after unlink");
  CHECK(GetLastError() == ERROR_FILE_NOT_FOUND,
        "post-unlink lookup error %lu, expected 2",
        (unsigned long)GetLastError());

  /* 6. _wunlink of a missing name */
  errno = 0;
  r = _wunlink(missing);
  CHECK(r == -1, "_wunlink(missing) returned %d, expected -1", r);
  CHECK(errno == ENOENT, "_wunlink(missing) errno=%d, expected ENOENT",
        errno);

  printf("PASS %s\n", NAME);

out:
  if(file_made) {
    SetFileAttributesW(file, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(file);
  }
  if(dir_made)
    RemoveDirectoryW(dir);
  return rc;
}
