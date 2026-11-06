/*
 * Test: 10_createfile_share_modes
 *
 * Purpose: verify the sharing rules that curl's Windows file layer depends
 *          on when it opens a file that another handle may hold: a reader
 *          that does not share write access blocks a later writer, read/read
 *          is compatible, a handle without FILE_SHARE_DELETE blocks deletion,
 *          and FILE_SHARE_DELETE allows it.
 *
 * APIs:    CreateFileW, WriteFile, ReadFile, DeleteFileW, GetFileAttributesW,
 *          CloseHandle, GetLastError, GetTempPathW
 *
 * Success: - h1 = CreateFileW(GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING)
 *            is valid
 *          - h2 = CreateFileW(GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE)
 *            fails with ERROR_SHARING_VIOLATION (32)
 *          - h3 = CreateFileW(GENERIC_READ, FILE_SHARE_READ) succeeds
 *          - DeleteFileW while h1 is open fails with ERROR_SHARING_VIOLATION (32,
 *            probed on Windows 10 22H2)
 *          - after closing h1 and h3, h4 = CreateFileW(GENERIC_READ,
 *            FILE_SHARE_READ|FILE_SHARE_DELETE) is valid and DeleteFileW
 *            succeeds while h4 is still open
 *          - h4 can still read the original 4 bytes "data" before delete
 *
 * Source:  lib/curlx/win32-fopen.c:255-294 (curlx_CreateFile) forwards the
 *          caller's dwShareMode unchanged to CreateFileW, so the share rules
 *          here are the exact contract curl inherits.
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

#define NAME "createfile_share_modes"

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
  wchar_t tmp[MAX_PATH];
  wchar_t dir[MAX_PATH];
  wchar_t path[MAX_PATH + 64];
  HANDLE h1 = INVALID_HANDLE_VALUE, h2 = INVALID_HANDLE_VALUE;
  HANDLE h3 = INVALID_HANDLE_VALUE, h4 = INVALID_HANDLE_VALUE;
  DWORD n = 0, err;
  char buf[8];
  int dir_made = 0, file_made = 0;
  HANDLE w;

  CHECK(GetTempPathW(MAX_PATH, tmp) > 0, "GetTempPathW failed");
  _snwprintf(dir, MAX_PATH, L"%lsucorp10-%lu", tmp,
             (unsigned long)GetCurrentProcessId());
  dir[MAX_PATH - 1] = 0;
  CHECK(CreateDirectoryW(dir, NULL), "CreateDirectoryW failed");
  dir_made = 1;
  _snwprintf(path, MAX_PATH + 64, L"%ls\\share10.bin", dir);
  path[MAX_PATH + 63] = 0;

  /* create the file with content */
  w = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  CHECK(w != INVALID_HANDLE_VALUE, "create share10.bin failed");
  CHECK(WriteFile(w, "data", 4, &n, NULL) && n == 4, "WriteFile failed");
  CHECK(CloseHandle(w), "CloseHandle(create) failed");
  file_made = 1;

  /* 1. reader with FILE_SHARE_READ only */
  h1 = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  CHECK(h1 != INVALID_HANDLE_VALUE, "h1 open failed");

  /* 2. writer must be refused: h1 did not share write access */
  SetLastError(0);
  h2 = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  CHECK(h2 == INVALID_HANDLE_VALUE, "writer open succeeded against h1");
  err = GetLastError();
  CHECK(err == ERROR_SHARING_VIOLATION,
        "writer error %lu, expected 32", (unsigned long)err);

  /* 3. second reader is compatible */
  h3 = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  CHECK(h3 != INVALID_HANDLE_VALUE, "second reader refused");

  /* 4. delete is refused while a handle lacks FILE_SHARE_DELETE */
  SetLastError(0);
  CHECK(!DeleteFileW(path), "DeleteFileW succeeded while h1 is open");
  err = GetLastError();
  CHECK(err == ERROR_SHARING_VIOLATION,
        "delete error %lu, expected 32", (unsigned long)err);

  /* the file must still be there */
  CHECK(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES,
        "file vanished after refused delete");

  CHECK(CloseHandle(h1), "CloseHandle(h1) failed");
  h1 = INVALID_HANDLE_VALUE;
  CHECK(CloseHandle(h3), "CloseHandle(h3) failed");
  h3 = INVALID_HANDLE_VALUE;

  /* 5. handle that shares delete does not block DeleteFileW */
  h4 = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  CHECK(h4 != INVALID_HANDLE_VALUE, "h4 open failed");
  memset(buf, 0, sizeof(buf));
  CHECK(ReadFile(h4, buf, 4, &n, NULL) && n == 4, "ReadFile(h4) failed");
  CHECK(memcmp(buf, "data", 4) == 0, "h4 read wrong bytes");
  CHECK(DeleteFileW(path), "DeleteFileW refused despite FILE_SHARE_DELETE");
  file_made = 0;
  CHECK(CloseHandle(h4), "CloseHandle(h4) failed");
  h4 = INVALID_HANDLE_VALUE;

  printf("PASS %s\n", NAME);

out:
  if(h1 != INVALID_HANDLE_VALUE)
    CloseHandle(h1);
  if(h2 != INVALID_HANDLE_VALUE)
    CloseHandle(h2);
  if(h3 != INVALID_HANDLE_VALUE)
    CloseHandle(h3);
  if(h4 != INVALID_HANDLE_VALUE)
    CloseHandle(h4);
  if(file_made)
    DeleteFileW(path);
  if(dir_made)
    RemoveDirectoryW(dir);
  return rc;
}
