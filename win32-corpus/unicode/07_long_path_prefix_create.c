/*
 * Test: 07_long_path_prefix_create
 *
 * Purpose: create, write, stat, enumerate and remove a file whose full path
 *          is longer than MAX_PATH (260) by using the \\?\ extended-length
 *          prefix on every wide call, as curl's fix_excessive_path() does for
 *          paths it cannot pass through unchanged.
 *
 * APIs:    CreateDirectoryW, CreateFileW, WriteFile, CloseHandle,
 *          GetFileAttributesExW, FindFirstFileW, FindNextFileW, FindClose,
 *          DeleteFileW, RemoveDirectoryW, GetTempPathW
 *
 * Success: - every nested CreateDirectoryW(L"\\\\?\\...") returns TRUE
 *          - the final file path is longer than 260 characters
 *          - CreateFileW(CREATE_NEW) on it succeeds and WriteFile writes 5
 *            bytes
 *          - GetFileAttributesExW reports nFileSizeLow == 5 and is not a
 *            directory
 *          - FindFirstFileW on the directory with the prefix finds exactly
 *            the long file name
 *          - a second CREATE_NEW on the same path fails with
 *            ERROR_FILE_EXISTS (80)
 *          - cleanup removes the file and every directory level
 *
 * Source:  lib/curlx/win32-fopen.c:108-252 (fix_excessive_path) adds the
 *          \\?\ prefix to paths over MAX_PATH; lib/curlx/win32-fopen.c:255-294
 *          (curlx_CreateFile) and 296-326 (curlx_FindFirstFile) are the
 *          call sites that receive the prefixed string.
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

#define NAME "long_path_prefix_create"
#define LEVELS 6
#define SEG_LEN 48
#define PATH_CAP 2048

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

static wchar_t levels[LEVELS + 1][PATH_CAP];
static int made[LEVELS + 1];
static int file_made;

int main(void)
{
  int rc = 0;
  wchar_t tmp[MAX_PATH];
  wchar_t seg[SEG_LEN + 1];
  wchar_t file[PATH_CAP];
  wchar_t pattern[PATH_CAP];
  wchar_t fname[] = L"long_file_xxxxxxxxxxxxxxxxxxxxxxxxxx.txt";
  int i, j;
  HANDLE h;
  DWORD written = 0;
  WIN32_FILE_ATTRIBUTE_DATA fad;
  WIN32_FIND_DATAW fd;
  HANDLE find;
  int found = 0;
  const char payload[5] = { 'h', 'e', 'l', 'l', 'o' };

  if(GetTempPathW(MAX_PATH, tmp) == 0)
    CHECK(0, "GetTempPathW failed");

  /* level 0: prefixed temp root plus a unique directory name */
  _snwprintf(levels[0], PATH_CAP, L"\\\\?\\%lsucorp07-%lu", tmp,
             (unsigned long)GetCurrentProcessId());
  levels[0][PATH_CAP - 1] = 0;
  CHECK(CreateDirectoryW(levels[0], NULL), "CreateDirectoryW(root) failed");
  made[0] = 1;

  /* levels 1..LEVELS: 48-character directory names, each creation is
   * one more level deeper so the full path blows past MAX_PATH */
  for(i = 1; i <= LEVELS; i++) {
    for(j = 0; j < SEG_LEN; j++)
      seg[j] = (j == 0) ? (wchar_t)(L'a' + i) : L'x';
    seg[SEG_LEN] = 0;
    _snwprintf(levels[i], PATH_CAP, L"%ls\\%ls", levels[i - 1], seg);
    levels[i][PATH_CAP - 1] = 0;
    CHECK(CreateDirectoryW(levels[i], NULL),
          "CreateDirectoryW level %d (len %lu) failed", i,
          (unsigned long)wcslen(levels[i]));
    made[i] = 1;
  }
  CHECK(wcslen(levels[LEVELS]) > MAX_PATH,
        "deepest directory only %lu chars", (unsigned long)wcslen(levels[LEVELS]));

  _snwprintf(file, PATH_CAP, L"%ls\\%ls", levels[LEVELS], fname);
  file[PATH_CAP - 1] = 0;
  CHECK(wcslen(file) > MAX_PATH, "file path only %lu chars",
        (unsigned long)wcslen(file));

  /* create, write */
  h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  CHECK(h != INVALID_HANDLE_VALUE, "CreateFileW(CREATE_NEW) failed");
  file_made = 1;
  CHECK(WriteFile(h, payload, sizeof(payload), &written, NULL),
        "WriteFile failed");
  CHECK(written == sizeof(payload), "WriteFile wrote %lu",
        (unsigned long)written);
  CHECK(CloseHandle(h), "CloseHandle failed");

  /* second create must report ERROR_FILE_EXISTS */
  SetLastError(0);
  h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  CHECK(h == INVALID_HANDLE_VALUE, "second CREATE_NEW succeeded");
  CHECK(GetLastError() == ERROR_FILE_EXISTS,
        "second CREATE_NEW error %lu, expected 80",
        (unsigned long)GetLastError());

  /* attributes and size through the prefixed path */
  memset(&fad, 0, sizeof(fad));
  CHECK(GetFileAttributesExW(file, GetFileExInfoStandard, &fad),
        "GetFileAttributesExW failed");
  CHECK(fad.nFileSizeLow == 5, "size %lu expected 5",
        (unsigned long)fad.nFileSizeLow);
  CHECK(!(fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY),
        "file reported as directory");

  /* enumerate the deepest directory and find the long name */
  _snwprintf(pattern, PATH_CAP, L"%ls\\*", levels[LEVELS]);
  pattern[PATH_CAP - 1] = 0;
  find = FindFirstFileW(pattern, &fd);
  CHECK(find != INVALID_HANDLE_VALUE, "FindFirstFileW failed");
  do {
    if(wcscmp(fd.cFileName, fname) == 0)
      found++;
  } while(FindNextFileW(find, &fd));
  CHECK(GetLastError() == ERROR_NO_MORE_FILES,
        "enumeration ended with %lu, expected 18",
        (unsigned long)GetLastError());
  CHECK(FindClose(find), "FindClose failed");
  CHECK(found == 1, "long name found %d times, expected 1", found);

  /* cleanup of the file, then the directories deepest first */
  CHECK(DeleteFileW(file), "DeleteFileW failed");
  file_made = 0;
  printf("PASS %s\n", NAME);

out:
  if(file_made)
    DeleteFileW(file);
  for(i = LEVELS; i >= 0; i--) {
    if(made[i]) {
      RemoveDirectoryW(levels[i]);
      made[i] = 0;
    }
  }
  return rc;
}
