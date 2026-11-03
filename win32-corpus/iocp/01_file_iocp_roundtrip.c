/*
 * 01_file_iocp_roundtrip
 *
 * Purpose: associate an overlapped (FILE_FLAG_OVERLAPPED) file handle with an
 *   I/O completion port and check that overlapped WriteFile and ReadFile calls
 *   deliver completion packets that carry the association key and the
 *   OVERLAPPED pointer we passed in.
 * APIs: CreateIoCompletionPort (port creation and file association),
 *   CreateFileW (FILE_FLAG_OVERLAPPED), WriteFile/ReadFile with OVERLAPPED,
 *   GetQueuedCompletionStatus, GetFileSizeEx, GetTempPathW, CreateDirectoryW,
 *   DeleteFileW, RemoveDirectoryW.
 * Success: each operation either completes synchronously or returns
 *   ERROR_IO_PENDING, and in both cases exactly one packet arrives with
 *   bytes == 4096, key == 0xC0FFEE and lpOverlapped == our OVERLAPPED. The
 *   file size is 4096 and the data read back matches the data written.
 * Source: none. Generic completion port contract. curl does not drive file
 *   handles through IOCP directly.
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

#define TEST_NAME "01_file_iocp_roundtrip"
#define TEST_KEY ((ULONG_PTR)0xC0FFEEUL)
#define LEN 4096

static void fail_exit(const char *why, DWORD gle)
{
  printf("FAIL %s: %s (gle=%lu)\n", TEST_NAME, why, (unsigned long)gle);
  exit(1);
}

/* Dequeue one packet and require it to belong to the expected operation. */
static void expect_packet(HANDLE port, OVERLAPPED *expect, DWORD want_bytes,
                          const char *what)
{
  OVERLAPPED *done = NULL;
  DWORD bytes = 0;
  ULONG_PTR key = 0;
  BOOL ok = GetQueuedCompletionStatus(port, &bytes, &key, &done, 5000);
  DWORD gle = GetLastError();

  if(!done)
    fail_exit(what, gle); /* timeout: no packet was posted */
  if(done != expect) {
    printf("FAIL %s: %s packet has wrong OVERLAPPED\n", TEST_NAME, what);
    exit(1);
  }
  if(!ok) {
    printf("FAIL %s: %s completed with error\n", TEST_NAME, what);
    exit(1);
  }
  if(key != TEST_KEY) {
    printf("FAIL %s: %s key=0x%llx expected 0xC0FFEE\n", TEST_NAME, what,
           (unsigned long long)key);
    exit(1);
  }
  if(bytes != want_bytes) {
    printf("FAIL %s: %s bytes=%lu expected %lu\n", TEST_NAME, what,
           (unsigned long)bytes, (unsigned long)want_bytes);
    exit(1);
  }
}

int main(void)
{
  wchar_t tmp[MAX_PATH], dir[MAX_PATH], path[MAX_PATH];
  unsigned char wbuf[LEN], rbuf[LEN];
  HANDLE port, file, assoc;
  OVERLAPPED ovw, ovr;
  DWORD n = 0;
  LARGE_INTEGER size;
  size_t i;

  for(i = 0; i < LEN; i++)
    wbuf[i] = (unsigned char)(i * 31 + 7);
  memset(rbuf, 0, sizeof rbuf);

  if(!GetTempPathW(MAX_PATH, tmp))
    fail_exit("GetTempPathW", GetLastError());
  _snwprintf(dir, MAX_PATH, L"%lsxcorp_iocp01_%lu", tmp,
             (unsigned long)GetCurrentProcessId());
  if(!CreateDirectoryW(dir, NULL))
    fail_exit("CreateDirectoryW", GetLastError());
  _snwprintf(path, MAX_PATH, L"%ls\\data.bin", dir);

  file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                     NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
  if(file == INVALID_HANDLE_VALUE)
    fail_exit("CreateFileW(FILE_FLAG_OVERLAPPED)", GetLastError());

  port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
  if(!port)
    fail_exit("CreateIoCompletionPort(new port)", GetLastError());

  /* Associating a file must return the same port handle. */
  assoc = CreateIoCompletionPort(file, port, TEST_KEY, 0);
  if(assoc != port)
    fail_exit("CreateIoCompletionPort(file association) != port",
              GetLastError());

  /* Overlapped write at offset 0. */
  memset(&ovw, 0, sizeof ovw);
  if(!WriteFile(file, wbuf, LEN, &n, &ovw) &&
     GetLastError() != ERROR_IO_PENDING)
    fail_exit("WriteFile(overlapped)", GetLastError());
  expect_packet(port, &ovw, LEN, "write packet");

  if(!GetFileSizeEx(file, &size))
    fail_exit("GetFileSizeEx", GetLastError());
  if(size.QuadPart != LEN) {
    printf("FAIL %s: file size %lld expected %d\n", TEST_NAME,
           (long long)size.QuadPart, LEN);
    return 1;
  }

  /* Overlapped read back from offset 0. */
  memset(&ovr, 0, sizeof ovr);
  n = 0;
  if(!ReadFile(file, rbuf, LEN, &n, &ovr) &&
     GetLastError() != ERROR_IO_PENDING)
    fail_exit("ReadFile(overlapped)", GetLastError());
  expect_packet(port, &ovr, LEN, "read packet");

  if(memcmp(wbuf, rbuf, LEN) != 0) {
    printf("FAIL %s: data read back differs from data written\n", TEST_NAME);
    return 1;
  }

  /* Exactly one packet per operation: the port must now be empty. */
  {
    OVERLAPPED *extra = NULL;
    DWORD eb = 0;
    ULONG_PTR ek = 0;
    SetLastError(0);
    if(GetQueuedCompletionStatus(port, &eb, &ek, &extra, 0) || extra)
      fail_exit("extra completion packet posted", 0);
    if(GetLastError() != WAIT_TIMEOUT)
      fail_exit("empty-port probe: expected WAIT_TIMEOUT", GetLastError());
  }

  CloseHandle(file);
  CloseHandle(port);
  DeleteFileW(path);
  RemoveDirectoryW(dir);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
