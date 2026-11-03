/*
 * 07_cancelioex_pending_read
 *
 * Purpose: cancel pending overlapped reads with CancelIoEx, both for one
 *   specific OVERLAPPED and for all requests on a handle (lpOverlapped NULL),
 *   and check the handle stays usable afterwards.
 * APIs: CreateNamedPipeW (FILE_FLAG_OVERLAPPED), ConnectNamedPipe,
 *   CreateFileW, ReadFile/WriteFile with OVERLAPPED, CancelIoEx,
 *   GetOverlappedResult, WaitForSingleObject.
 * Success:
 *   - CancelIoEx(h, &ov) on a pending read returns TRUE;
 *     GetOverlappedResult(bWait=TRUE) returns FALSE with
 *     ERROR_OPERATION_ABORTED and 0 bytes.
 *   - a second CancelIoEx(h, &ov) for the completed request returns FALSE
 *     with ERROR_NOT_FOUND.
 *   - after the cancel, a new read still receives client data "ok!".
 *   - CancelIoEx(h, NULL) cancels two pending reads at once; both report
 *     ERROR_OPERATION_ABORTED.
 * Source: none. Generic CancelIoEx contract. curl does not cancel overlapped
 *   I/O on Windows.
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

#define TEST_NAME "07_cancelioex_pending_read"

static void fail_exit(const char *why, DWORD gle)
{
  printf("FAIL %s: %s (gle=%lu)\n", TEST_NAME, why, (unsigned long)gle);
  exit(1);
}

/* Create a connected overlapped named pipe pair. */
static void make_pipe(const wchar_t *name, HANDLE *srv, HANDLE *cli)
{
  OVERLAPPED ov;
  HANDLE ev;
  DWORD n = 0;

  *srv = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                          PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                          1, 4096, 4096, 0, NULL);
  if(*srv == INVALID_HANDLE_VALUE)
    fail_exit("CreateNamedPipeW", GetLastError());
  ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!ev)
    fail_exit("CreateEventW", GetLastError());
  memset(&ov, 0, sizeof ov);
  ov.hEvent = ev;
  if(!ConnectNamedPipe(*srv, &ov) && GetLastError() != ERROR_IO_PENDING &&
     GetLastError() != ERROR_PIPE_CONNECTED)
    fail_exit("ConnectNamedPipe", GetLastError());
  *cli = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                     OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
  if(*cli == INVALID_HANDLE_VALUE)
    fail_exit("CreateFileW(client)", GetLastError());
  if(WaitForSingleObject(ev, 5000) != WAIT_OBJECT_0)
    fail_exit("connect did not complete", GetLastError());
  if(!GetOverlappedResult(*srv, &ov, &n, FALSE))
    fail_exit("GetOverlappedResult(connect)", GetLastError());
  CloseHandle(ev);
}

/* Start an overlapped read that must be pending (no data written). */
static void start_pending_read(HANDLE srv, OVERLAPPED *ov, char *buf, DWORD len,
                               const char *what)
{
  DWORD n = 0;
  if(ReadFile(srv, buf, len, &n, ov))
    fail_exit(what, 0);
  if(GetLastError() != ERROR_IO_PENDING)
    fail_exit(what, GetLastError());
}

int main(void)
{
  wchar_t name[128];
  HANDLE srv, cli, ev1, ev2, ev3;
  OVERLAPPED ov1, ov2, ov3;
  char b1[16], b2[16], b3[16];
  DWORD n = 0;

  _snwprintf(name, 128, L"\\\\.\\pipe\\xcorp_iocp07_%lu",
             (unsigned long)GetCurrentProcessId());
  make_pipe(name, &srv, &cli);

  ev1 = CreateEventW(NULL, TRUE, FALSE, NULL);
  ev2 = CreateEventW(NULL, TRUE, FALSE, NULL);
  ev3 = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!ev1 || !ev2 || !ev3)
    fail_exit("CreateEventW", GetLastError());

  /* 1. Cancel one specific pending read. */
  memset(&ov1, 0, sizeof ov1);
  ov1.hEvent = ev1;
  start_pending_read(srv, &ov1, b1, sizeof b1, "first ReadFile not pending");

  if(!CancelIoEx(srv, &ov1))
    fail_exit("CancelIoEx(&ov1) on pending read", GetLastError());
  if(GetOverlappedResult(srv, &ov1, &n, TRUE))
    fail_exit("cancelled read reported success", 0);
  if(GetLastError() != ERROR_OPERATION_ABORTED)
    fail_exit("cancelled read: expected ERROR_OPERATION_ABORTED",
              GetLastError());
  if(n != 0)
    fail_exit("cancelled read transferred bytes", n);

  /* 2. The request is gone now: cancelling it again finds nothing. */
  SetLastError(0);
  if(CancelIoEx(srv, &ov1))
    fail_exit("second CancelIoEx on completed request returned TRUE", 0);
  if(GetLastError() != ERROR_NOT_FOUND)
    fail_exit("second CancelIoEx: expected ERROR_NOT_FOUND", GetLastError());

  /* 3. Handle still works: client sends, server reads the bytes. */
  memset(&ov2, 0, sizeof ov2);
  ov2.hEvent = ev2;
  memset(b2, 0, sizeof b2);
  n = 0;
  if(!ReadFile(srv, b2, 3, &n, &ov2)) {
    if(GetLastError() != ERROR_IO_PENDING)
      fail_exit("read after cancel", GetLastError());
    if(WaitForSingleObject(ev2, 0) == WAIT_OBJECT_0)
      fail_exit("event signaled before any data", 0);
  }
  {
    OVERLAPPED ovw;
    HANDLE evw = CreateEventW(NULL, TRUE, FALSE, NULL);
    DWORD wn = 0;
    memset(&ovw, 0, sizeof ovw);
    ovw.hEvent = evw;
    if(!WriteFile(cli, "ok!", 3, &wn, &ovw) &&
       GetLastError() != ERROR_IO_PENDING)
      fail_exit("client WriteFile", GetLastError());
    if(!GetOverlappedResult(cli, &ovw, &wn, TRUE) || wn != 3)
      fail_exit("client write count", wn);
    CloseHandle(evw);
  }
  if(!GetOverlappedResult(srv, &ov2, &n, TRUE))
    fail_exit("read after cancel did not complete", GetLastError());
  if(n != 3 || memcmp(b2, "ok!", 3) != 0) {
    printf("FAIL %s: read after cancel got %lu bytes, data mismatch\n",
           TEST_NAME, (unsigned long)n);
    return 1;
  }

  /* 4. Two pending reads, cancel all requests on the handle with NULL. */
  memset(&ov1, 0, sizeof ov1);
  memset(&ov3, 0, sizeof ov3);
  ov1.hEvent = ev1;
  ov3.hEvent = ev3;
  ResetEvent(ev1);
  start_pending_read(srv, &ov1, b1, sizeof b1, "pending read A");
  start_pending_read(srv, &ov3, b3, sizeof b3, "pending read B");

  if(!CancelIoEx(srv, NULL))
    fail_exit("CancelIoEx(handle, NULL)", GetLastError());

  SetLastError(0);
  if(GetOverlappedResult(srv, &ov1, &n, TRUE) ||
     GetLastError() != ERROR_OPERATION_ABORTED)
    fail_exit("read A not aborted by cancel-all", GetLastError());
  SetLastError(0);
  if(GetOverlappedResult(srv, &ov3, &n, TRUE) ||
     GetLastError() != ERROR_OPERATION_ABORTED)
    fail_exit("read B not aborted by cancel-all", GetLastError());

  CloseHandle(ev1);
  CloseHandle(ev2);
  CloseHandle(ev3);
  CloseHandle(cli);
  CloseHandle(srv);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
