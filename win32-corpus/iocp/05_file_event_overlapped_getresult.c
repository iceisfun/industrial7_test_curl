/*
 * 05_file_event_overlapped_getresult
 *
 * Purpose: the non-IOCP overlapped pattern. Each operation carries its own
 *   manual-reset event in OVERLAPPED.hEvent, the caller waits on that event
 *   and collects the result with GetOverlappedResult. Also checks the
 *   ERROR_HANDLE_EOF result for a read at end of file.
 * APIs: CreateFileW (FILE_FLAG_OVERLAPPED), CreateEventW, WriteFile/ReadFile
 *   with OVERLAPPED.hEvent, WaitForSingleObject, GetOverlappedResult,
 *   GetFileSizeEx, DeleteFileW, RemoveDirectoryW.
 * Success:
 *   - write of 8192 bytes: either sync success, or ERROR_IO_PENDING followed
 *     by the event becoming signaled; GetOverlappedResult(bWait=FALSE or
 *     TRUE) then returns TRUE with 8192 bytes.
 *   - read of the same 8192 bytes at offset 0 returns the same data.
 *   - read at offset 8192 (EOF) fails with ERROR_HANDLE_EOF (38), reported
 *     by ReadFile or GetOverlappedResult, and transfers 0 bytes.
 * Source: none. Generic overlapped file I/O contract. curl does not use
 *   overlapped file I/O on Windows.
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

#define TEST_NAME "05_file_event_overlapped_getresult"
#define LEN 8192

static void fail_exit(const char *why, DWORD gle)
{
  printf("FAIL %s: %s (gle=%lu)\n", TEST_NAME, why, (unsigned long)gle);
  exit(1);
}

/* Wait for the per-operation event, then collect the result. */
static void collect(HANDLE f, OVERLAPPED *ov, DWORD want, const char *what)
{
  DWORD n = 0;
  DWORD w = WaitForSingleObject(ov->hEvent, 5000);
  if(w != WAIT_OBJECT_0)
    fail_exit(what, w);
  if(!GetOverlappedResult(f, ov, &n, FALSE)) {
    printf("FAIL %s: %s GetOverlappedResult failed (gle=%lu)\n", TEST_NAME,
           what, (unsigned long)GetLastError());
    exit(1);
  }
  if(n != want) {
    printf("FAIL %s: %s transferred %lu expected %lu\n", TEST_NAME, what,
           (unsigned long)n, (unsigned long)want);
    exit(1);
  }
}

int main(void)
{
  wchar_t tmp[MAX_PATH], dir[MAX_PATH], path[MAX_PATH];
  static unsigned char wbuf[LEN], rbuf[LEN];
  HANDLE f, ev;
  OVERLAPPED ovw, ovr, ove;
  DWORD n = 0;
  DWORD gle;
  BOOL ok;
  LARGE_INTEGER size;
  size_t i;

  for(i = 0; i < LEN; i++)
    wbuf[i] = (unsigned char)(i ^ 0x5A);

  if(!GetTempPathW(MAX_PATH, tmp))
    fail_exit("GetTempPathW", GetLastError());
  _snwprintf(dir, MAX_PATH, L"%lsxcorp_iocp05_%lu", tmp,
             (unsigned long)GetCurrentProcessId());
  if(!CreateDirectoryW(dir, NULL))
    fail_exit("CreateDirectoryW", GetLastError());
  _snwprintf(path, MAX_PATH, L"%ls\\ev.bin", dir);

  f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                  FILE_FLAG_OVERLAPPED, NULL);
  if(f == INVALID_HANDLE_VALUE)
    fail_exit("CreateFileW(FILE_FLAG_OVERLAPPED)", GetLastError());

  /* Write with a manual-reset event attached. */
  ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!ev)
    fail_exit("CreateEventW", GetLastError());
  memset(&ovw, 0, sizeof ovw);
  ovw.hEvent = ev;
  ok = WriteFile(f, wbuf, LEN, &n, &ovw);
  if(ok) {
    /* Synchronous completion: bytes are reported directly. */
    if(n != LEN)
      fail_exit("sync write byte count", n);
  } else {
    gle = GetLastError();
    if(gle != ERROR_IO_PENDING)
      fail_exit("WriteFile", gle);
    collect(f, &ovw, LEN, "write completion");
  }

  if(!GetFileSizeEx(f, &size) || size.QuadPart != LEN) {
    printf("FAIL %s: file size %lld expected %d\n", TEST_NAME,
           (long long)size.QuadPart, LEN);
    return 1;
  }

  /* Read back. Reset the event first, as a reused OVERLAPPED would need. */
  ResetEvent(ev);
  memset(&ovr, 0, sizeof ovr);
  ovr.hEvent = ev;
  memset(rbuf, 0, sizeof rbuf);
  n = 0;
  ok = ReadFile(f, rbuf, LEN, &n, &ovr);
  if(!ok) {
    gle = GetLastError();
    if(gle != ERROR_IO_PENDING)
      fail_exit("ReadFile", gle);
    collect(f, &ovr, LEN, "read completion");
  } else if(n != LEN) {
    fail_exit("sync read byte count", n);
  }
  if(memcmp(wbuf, rbuf, LEN) != 0) {
    printf("FAIL %s: read data differs from written data\n", TEST_NAME);
    return 1;
  }

  /* Read at EOF. The result must be ERROR_HANDLE_EOF with 0 bytes. */
  ResetEvent(ev);
  memset(&ove, 0, sizeof ove);
  ove.hEvent = ev;
  ove.Offset = LEN;
  n = 99;
  SetLastError(0);
  ok = ReadFile(f, rbuf, 16, &n, &ove);
  if(ok) {
    fail_exit("read at EOF unexpectedly succeeded", 0);
  }
  gle = GetLastError();
  if(gle == ERROR_IO_PENDING) {
    DWORD w = WaitForSingleObject(ev, 5000);
    DWORD got = 0;
    if(w != WAIT_OBJECT_0)
      fail_exit("EOF read event", w);
    ok = GetOverlappedResult(f, &ove, &got, FALSE);
    if(ok || GetLastError() != ERROR_HANDLE_EOF)
      fail_exit("EOF read via GetOverlappedResult: expected ERROR_HANDLE_EOF",
                GetLastError());
    if(got != 0)
      fail_exit("EOF read transferred bytes", got);
  } else if(gle != ERROR_HANDLE_EOF) {
    fail_exit("EOF read: expected ERROR_HANDLE_EOF", gle);
  }

  CloseHandle(ev);
  CloseHandle(f);
  DeleteFileW(path);
  RemoveDirectoryW(dir);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
