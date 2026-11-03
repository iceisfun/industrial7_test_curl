/*
 * Test: 11_findfirst_findnext_wide
 *
 * Purpose: enumerate a directory with the wide find API, the way curl's
 *          file:// directory listing does through curlx_FindFirstFile:
 *          FindFirstFileW with a wildcard pattern, FindNextFileW until
 *          ERROR_NO_MORE_FILES, file sizes and directory flags from
 *          WIN32_FIND_DATAW, and the no-match case. Names are non-ASCII so
 *          the UTF-16 names must survive intact.
 *
 * APIs:    CreateDirectoryW, RemoveDirectoryW, _wfopen, fclose, DeleteFileW,
 *          FindFirstFileW, FindNextFileW, FindClose, GetLastError,
 *          GetTempPathW
 *
 * Success: - the directory holds alpha.txt (3 bytes), über.txt (0 bytes),
 *            文件.log (1 byte) and a subdirectory "sub"
 *          - enumerating "*" returns "." and ".." plus those four entries,
 *            each name matching exactly once
 *          - the subdirectory entry has FILE_ATTRIBUTE_DIRECTORY and the
 *          files do not
 *          - alpha.txt reports nFileSizeLow == 3
 *          - FindNextFileW returns FALSE with ERROR_NO_MORE_FILES (18) at
 *            the end
 *          - pattern "*.txt" returns exactly 2 files (alpha.txt, über.txt)
 *          - pattern "*.nomatch" returns INVALID_HANDLE_VALUE with
 *            ERROR_FILE_NOT_FOUND (2)
 *
 * Source:  lib/file.c:431 (file_do uses curlx_FindFirstFile on the directory
 *          pattern and then walks entries with FindNextFile); the wrapper is
 *          lib/curlx/win32-fopen.c:296-325.
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

#define NAME "findfirst_findnext_wide"

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

#define N_EXPECT 4

static const wchar_t *expect_names[N_EXPECT] = {
  L"alpha.txt", L"über.txt", L"文件.log", L"sub"
};
static const DWORD expect_size[N_EXPECT] = { 3, 0, 1, 0 };
static int seen[N_EXPECT];

static void make_file(const wchar_t *path, const char *data, size_t len)
{
  FILE *f = _wfopen(path, L"wb");
  if(f) {
    if(len)
      fwrite(data, 1, len, f);
    fclose(f);
  }
}

int main(void)
{
  int rc = 0;
  wchar_t tmp[MAX_PATH];
  wchar_t dir[MAX_PATH];
  wchar_t pattern[MAX_PATH + 64];
  wchar_t path[MAX_PATH + 64];
  WIN32_FIND_DATAW fd;
  HANDLE hf;
  int dir_made = 0;
  int i, dots = 0, total = 0, txt = 0;
  int ok;

  CHECK(GetTempPathW(MAX_PATH, tmp) > 0, "GetTempPathW failed");
  _snwprintf(dir, MAX_PATH, L"%lsucorp11-%lu", tmp,
             (unsigned long)GetCurrentProcessId());
  dir[MAX_PATH - 1] = 0;
  CHECK(CreateDirectoryW(dir, NULL), "CreateDirectoryW(dir) failed");
  dir_made = 1;

  _snwprintf(path, MAX_PATH + 64, L"%ls\\alpha.txt", dir);
  make_file(path, "abc", 3);
  _snwprintf(path, MAX_PATH + 64, L"%ls\\über.txt", dir);
  make_file(path, "", 0);
  _snwprintf(path, MAX_PATH + 64, L"%ls\\文件.log", dir);
  make_file(path, "Z", 1);
  _snwprintf(path, MAX_PATH + 64, L"%ls\\sub", dir);
  CHECK(CreateDirectoryW(path, NULL), "CreateDirectoryW(sub) failed");

  /* 1. enumerate everything */
  _snwprintf(pattern, MAX_PATH + 64, L"%ls\\*", dir);
  hf = FindFirstFileW(pattern, &fd);
  CHECK(hf != INVALID_HANDLE_VALUE, "FindFirstFileW(*) failed");
  ok = 1;
  do {
    total++;
    if(wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) {
      dots++;
      continue;
    }
    for(i = 0; i < N_EXPECT; i++) {
      if(wcscmp(fd.cFileName, expect_names[i]) == 0) {
        seen[i]++;
        if(i == 3) {
          if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            ok = 0;
        }
        else if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
          ok = 0;
        if(fd.nFileSizeLow != expect_size[i] && i != 3)
          ok = 0;
        break;
      }
    }
    if(i == N_EXPECT)
      CHECK(0, "unexpected entry '%ls'", fd.cFileName);
  } while(FindNextFileW(hf, &fd));

  CHECK(GetLastError() == ERROR_NO_MORE_FILES,
        "enumeration ended with %lu, expected 18",
        (unsigned long)GetLastError());
  CHECK(FindClose(hf), "FindClose(*) failed");

  CHECK(dots == 2, "saw %d dot entries, expected 2", dots);
  CHECK(total == N_EXPECT + 2, "total entries %d, expected 6", total);
  for(i = 0; i < N_EXPECT; i++)
    CHECK(seen[i] == 1, "entry '%ls' seen %d times", expect_names[i], seen[i]);
  CHECK(ok, "attribute or size mismatch in enumeration");

  /* 2. wildcard filter on extension */
  _snwprintf(pattern, MAX_PATH + 64, L"%ls\\*.txt", dir);
  hf = FindFirstFileW(pattern, &fd);
  CHECK(hf != INVALID_HANDLE_VALUE, "FindFirstFileW(*.txt) failed");
  do {
    txt++;
    CHECK(wcscmp(fd.cFileName, L"alpha.txt") == 0 ||
          wcscmp(fd.cFileName, L"über.txt") == 0,
          "unexpected .txt match '%ls'", fd.cFileName);
  } while(FindNextFileW(hf, &fd));
  CHECK(GetLastError() == ERROR_NO_MORE_FILES,
        "*.txt ended with %lu, expected 18", (unsigned long)GetLastError());
  FindClose(hf);
  CHECK(txt == 2, "*.txt matched %d files, expected 2", txt);

  /* 3. pattern with no match */
  _snwprintf(pattern, MAX_PATH + 64, L"%ls\\*.nomatch", dir);
  SetLastError(0);
  hf = FindFirstFileW(pattern, &fd);
  CHECK(hf == INVALID_HANDLE_VALUE, "*.nomatch returned a handle");
  CHECK(GetLastError() == ERROR_FILE_NOT_FOUND,
        "*.nomatch error %lu, expected 2", (unsigned long)GetLastError());

  printf("PASS %s\n", NAME);

out:
  if(dir_made) {
    _snwprintf(path, MAX_PATH + 64, L"%ls\\alpha.txt", dir);
    DeleteFileW(path);
    _snwprintf(path, MAX_PATH + 64, L"%ls\\über.txt", dir);
    DeleteFileW(path);
    _snwprintf(path, MAX_PATH + 64, L"%ls\\文件.log", dir);
    DeleteFileW(path);
    _snwprintf(path, MAX_PATH + 64, L"%ls\\sub", dir);
    RemoveDirectoryW(path);
    RemoveDirectoryW(dir);
  }
  return rc;
}
