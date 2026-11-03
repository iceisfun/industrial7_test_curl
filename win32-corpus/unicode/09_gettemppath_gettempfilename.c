/*
 * Test: 09_gettemppath_gettempfilename
 *
 * Purpose: check the temp-directory contract curl relies on when it needs a
 *          scratch file on Windows: GetTempPathW must report the required
 *          size for a zero-length buffer, must return a directory with a
 *          trailing backslash, and GetTempFileNameW must create a unique
 *          zero-byte file whose name starts with the requested prefix.
 *
 * APIs:    GetTempPathW, GetTempFileNameW, GetFileAttributesW, GetFileSize,
 *          DeleteFileW, GetLastError
 *
 * Success: - GetTempPathW(0, NULL) returns n > 0; GetTempPathW(n, buf)
 *            returns n - 1 (length without terminator), buf ends in '\'
 *          - the directory exists and has FILE_ATTRIBUTE_DIRECTORY
 *          - GetTempPathW(3, small) returns more than 3 and does not
 *            succeed in filling the buffer
 *          - GetTempFileNameW(path, L"cur", 0, out) returns a non-zero unique
 *            value, out starts with the temp path, its base name starts with
 *            "cur" and ends with ".tmp", and the file exists with size 0
 *          - a second call with uUnique = 0 returns a different name
 *          - GetTempFileNameW with uUnique = 0x1234 returns exactly
 *            "cur1234.tmp" as base name (the caller-chosen unique value);
 *            with a non-zero uUnique Win32 does not create that file, so the
 *            test does not create or delete it
 *
 * Source:  no direct call site: grep of lib/ and src/ finds no use of
 *          GetTempPath or GetTempFileName. Included as the scratch-file
 *          contract for Windows builds; the behaviour checked is Win32's.
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

#define NAME "gettemppath_gettempfilename"

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if(!(cond)) {                                                          \
      printf("FAIL %s: ", NAME);                                           \
      printf(__VA_ARGS__);                                                 \
      printf(" [line %d, GetLastError=%lu]\n", __LINE__,                   \
             (unsigned long)GetLastError());                               \
      rc = 1;                                                              \
      goto out;                                                            \
    }                                                                      \
  } while(0)

int main(void)
{
  int rc = 0;
  DWORD need, n;
  wchar_t *tmp = NULL;
  wchar_t tmp_small[4];
  wchar_t name1[MAX_PATH];
  wchar_t name2[MAX_PATH];
  wchar_t name3[MAX_PATH];
  UINT u;
  DWORD attr;
  HANDLE h;
  DWORD fsize;
  const wchar_t *base;
  int have1 = 0, have2 = 0;

  /* 1. size query */
  need = GetTempPathW(0, NULL);
  CHECK(need > 0, "GetTempPathW(0) returned %lu", (unsigned long)need);

  tmp = (wchar_t *)malloc((size_t)need * sizeof(wchar_t));
  CHECK(tmp != NULL, "malloc failed");

  /* 2. full read: returns length without terminator */
  n = GetTempPathW(need, tmp);
  CHECK(n == need - 1, "GetTempPathW returned %lu, expected %lu",
        (unsigned long)n, (unsigned long)(need - 1));
  CHECK(tmp[n - 1] == L'\\', "temp path does not end in backslash");

  /* 3. the directory exists */
  attr = GetFileAttributesW(tmp);
  CHECK(attr != INVALID_FILE_ATTRIBUTES &&
        (attr & FILE_ATTRIBUTE_DIRECTORY),
        "temp path '%ls' is not an existing directory", tmp);

  /* 4. small buffer reports a larger required size */
  n = GetTempPathW(3, tmp_small);
  CHECK(n > 3, "small GetTempPathW returned %lu, expected > 3",
        (unsigned long)n);

  /* 5. unique file creation with a prefix */
  u = GetTempFileNameW(tmp, L"cur", 0, name1);
  CHECK(u != 0, "GetTempFileNameW failed");
  have1 = 1;
  CHECK(wcsncmp(name1, tmp, wcslen(tmp)) == 0,
        "temp file '%ls' is not under '%ls'", name1, tmp);
  base = wcsrchr(name1, L'\\');
  CHECK(base != NULL, "no separator in temp file name");
  base++;
  CHECK(wcsncmp(base, L"cur", 3) == 0, "base '%ls' lacks prefix", base);
  CHECK(wcslen(base) > 7 && wcscmp(base + wcslen(base) - 4, L".tmp") == 0,
        "base '%ls' lacks .tmp suffix", base);

  h = CreateFileW(name1, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  CHECK(h != INVALID_HANDLE_VALUE, "temp file does not exist");
  fsize = GetFileSize(h, NULL);
  CHECK(fsize == 0, "fresh temp file size %lu, expected 0",
        (unsigned long)fsize);
  CHECK(CloseHandle(h), "CloseHandle failed");

  /* 6. second call returns a different name */
  u = GetTempFileNameW(tmp, L"cur", 0, name2);
  CHECK(u != 0, "second GetTempFileNameW failed");
  have2 = 1;
  CHECK(wcscmp(name1, name2) != 0, "two calls returned the same name");

  /* 7. caller-chosen unique value is used verbatim */
  u = GetTempFileNameW(tmp, L"cur", 0x1234, name3);
  CHECK(u != 0, "GetTempFileNameW(0x1234) failed");
  base = wcsrchr(name3, L'\\');
  CHECK(base != NULL, "no separator in fixed-unique name");
  CHECK(wcscmp(base + 1, L"cur1234.tmp") == 0,
        "fixed-unique base is '%ls', expected 'cur1234.tmp'", base + 1);

  printf("PASS %s\n", NAME);

out:
  if(have1)
    DeleteFileW(name1);
  if(have2)
    DeleteFileW(name2);
  free(tmp);
  return rc;
}
