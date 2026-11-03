/*
 * 06_pipe_pending_incomplete
 *
 * Purpose: the ERROR_IO_PENDING lifecycle on an overlapped named pipe. A
 *   server ConnectNamedPipe and a server ReadFile are started before the
 *   peer has written anything, so both must return FALSE with
 *   ERROR_IO_PENDING. GetOverlappedResult(bWait=FALSE) must report
 *   ERROR_IO_INCOMPLETE while pending, and succeed only after the data
 *   arrives.
 * APIs: CreateNamedPipeW (FILE_FLAG_OVERLAPPED), ConnectNamedPipe,
 *   CreateFileW (client, FILE_FLAG_OVERLAPPED), ReadFile/WriteFile with
 *   OVERLAPPED.hEvent, GetOverlappedResult, WaitForSingleObject,
 *   DisconnectNamedPipe.
 * Success:
 *   - ConnectNamedPipe returns FALSE/ERROR_IO_PENDING before the client opens.
 *   - ReadFile returns FALSE/ERROR_IO_PENDING with no data written.
 *   - GetOverlappedResult(bWait=FALSE) returns FALSE/ERROR_IO_INCOMPLETE and
 *     the event is not signaled.
 *   - after the client writes "ping", the server event is signaled and
 *     GetOverlappedResult returns TRUE with 4 bytes "ping".
 * Source: none. Generic overlapped named pipe contract. curl does not use
 *   named pipes on Windows.
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

#define TEST_NAME "06_pipe_pending_incomplete"

static void fail_exit(const char *why, DWORD gle)
{
  printf("FAIL %s: %s (gle=%lu)\n", TEST_NAME, why, (unsigned long)gle);
  exit(1);
}

int main(void)
{
  wchar_t name[128];
  HANDLE srv, cli, ev_c, ev_r, ev_w;
  OVERLAPPED ov_c, ov_r, ov_w;
  char rbuf[16];
  DWORD n = 0, gle, w;
  BOOL ok;

  _snwprintf(name, 128, L"\\\\.\\pipe\\xcorp_iocp06_%lu",
             (unsigned long)GetCurrentProcessId());

  srv = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                         PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                         1, 4096, 4096, 0, NULL);
  if(srv == INVALID_HANDLE_VALUE)
    fail_exit("CreateNamedPipeW(FILE_FLAG_OVERLAPPED)", GetLastError());

  ev_c = CreateEventW(NULL, TRUE, FALSE, NULL);
  ev_r = CreateEventW(NULL, TRUE, FALSE, NULL);
  ev_w = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!ev_c || !ev_r || !ev_w)
    fail_exit("CreateEventW", GetLastError());

  /* 1. ConnectNamedPipe with no client yet: pending. */
  memset(&ov_c, 0, sizeof ov_c);
  ov_c.hEvent = ev_c;
  ok = ConnectNamedPipe(srv, &ov_c);
  gle = GetLastError();
  if(ok)
    fail_exit("ConnectNamedPipe succeeded with no client", 0);
  if(gle != ERROR_IO_PENDING)
    fail_exit("ConnectNamedPipe: expected ERROR_IO_PENDING", gle);

  /* 2. Client connects; the server's event must be signaled. */
  cli = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
  if(cli == INVALID_HANDLE_VALUE)
    fail_exit("CreateFileW(client)", GetLastError());

  w = WaitForSingleObject(ev_c, 5000);
  if(w != WAIT_OBJECT_0)
    fail_exit("connect event not signaled", w);
  n = 0;
  if(!GetOverlappedResult(srv, &ov_c, &n, FALSE))
    fail_exit("GetOverlappedResult(connect)", GetLastError());

  /* 3. Server read with nothing written: pending. */
  memset(&ov_r, 0, sizeof ov_r);
  ov_r.hEvent = ev_r;
  memset(rbuf, 0, sizeof rbuf);
  ok = ReadFile(srv, rbuf, sizeof rbuf, &n, &ov_r);
  gle = GetLastError();
  if(ok)
    fail_exit("ReadFile returned TRUE with no data written", 0);
  if(gle != ERROR_IO_PENDING)
    fail_exit("ReadFile: expected ERROR_IO_PENDING", gle);

  /* 4. While pending: bWait=FALSE gives ERROR_IO_INCOMPLETE, event unsignaled. */
  SetLastError(0);
  n = 1234;
  ok = GetOverlappedResult(srv, &ov_r, &n, FALSE);
  if(ok)
    fail_exit("GetOverlappedResult TRUE while read pending", 0);
  if(GetLastError() != ERROR_IO_INCOMPLETE)
    fail_exit("GetOverlappedResult: expected ERROR_IO_INCOMPLETE",
              GetLastError());
  w = WaitForSingleObject(ev_r, 0);
  if(w != WAIT_TIMEOUT)
    fail_exit("read event signaled while still pending", w);

  /* 5. Client writes 4 bytes. Wait for its own write to finish. */
  memset(&ov_w, 0, sizeof ov_w);
  ov_w.hEvent = ev_w;
  ok = WriteFile(cli, "ping", 4, &n, &ov_w);
  if(!ok) {
    gle = GetLastError();
    if(gle != ERROR_IO_PENDING)
      fail_exit("client WriteFile", gle);
    if(WaitForSingleObject(ev_w, 5000) != WAIT_OBJECT_0)
      fail_exit("client write event", GetLastError());
  }
  n = 0;
  if(!GetOverlappedResult(cli, &ov_w, &n, TRUE) || n != 4)
    fail_exit("client write did not transfer 4 bytes", n);

  /* 6. Server read completes. */
  w = WaitForSingleObject(ev_r, 5000);
  if(w != WAIT_OBJECT_0)
    fail_exit("server read event not signaled after write", w);
  n = 0;
  if(!GetOverlappedResult(srv, &ov_r, &n, FALSE))
    fail_exit("GetOverlappedResult(read) after data", GetLastError());
  if(n != 4)
    fail_exit("server read transferred wrong count", n);
  if(memcmp(rbuf, "ping", 4) != 0) {
    printf("FAIL %s: server read payload mismatch\n", TEST_NAME);
    return 1;
  }

  DisconnectNamedPipe(srv);
  CloseHandle(cli);
  CloseHandle(srv);
  CloseHandle(ev_c);
  CloseHandle(ev_r);
  CloseHandle(ev_w);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
