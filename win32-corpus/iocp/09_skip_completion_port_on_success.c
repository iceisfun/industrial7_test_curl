/*
 * 09_skip_completion_port_on_success
 *
 * Purpose: SetFileCompletionNotificationModes with
 *   FILE_SKIP_COMPLETION_PORT_ON_SUCCESS. When set, an overlapped operation
 *   that completes synchronously (returns success) does NOT post a packet to
 *   the associated completion port. Operations that return ERROR_IO_PENDING
 *   (or WSA_IO_PENDING) still post normally. An IOCP engine relies on this to
 *   avoid handling each synchronous completion twice.
 *   Two phases: a file handle (WriteFile) and a loopback TCP socket (WSASend),
 *   because whether a given operation completes synchronously depends on the
 *   handle type and the OS.
 * APIs: CreateFileW (FILE_FLAG_OVERLAPPED), CreateIoCompletionPort,
 *   SetFileCompletionNotificationModes, WriteFile, WSASocketW,
 *   WSASend, GetQueuedCompletionStatus (timeout 0 probes), GetFileSizeEx.
 * Success:
 *   - SetFileCompletionNotificationModes returns TRUE. If it fails with
 *     ERROR_CALL_NOT_IMPLEMENTED or ERROR_INVALID_FUNCTION the test SKIPs.
 *   - every operation that returned success synchronously leaves the port
 *     empty (timeout-0 probe returns WAIT_TIMEOUT with NULL OVERLAPPED);
 *   - every operation that returned pending posts exactly one packet with the
 *     expected OVERLAPPED, key and byte count;
 *   - the file size equals the total bytes written.
 *   If no operation in either phase completed synchronously, the skip
 *   behaviour cannot be observed and the test SKIPs.
 * Source: curl does not use this API. Generic Win32 contract.
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

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_NAME "09_skip_completion_port_on_success"
#define KEY ((ULONG_PTR)0x9999)
#define CHUNK 512
#define NWRITES 8

static void fail_exit(const char *why, DWORD gle)
{
  printf("FAIL %s: %s (gle=%lu)\n", TEST_NAME, why, (unsigned long)gle);
  exit(1);
}

/* Probe the port without waiting. Returns TRUE if a packet was present. */
static BOOL port_has_packet(HANDLE port)
{
  OVERLAPPED *done = NULL;
  DWORD b = 0;
  ULONG_PTR k = 0;
  BOOL got;
  SetLastError(0);
  got = GetQueuedCompletionStatus(port, &b, &k, &done, 0);
  if(got || done != NULL)
    return TRUE;
  if(GetLastError() != WAIT_TIMEOUT)
    fail_exit("port probe: expected WAIT_TIMEOUT", GetLastError());
  return FALSE;
}

/* Dequeue the packet that must belong to ov. */
static void expect_async_packet(HANDLE port, OVERLAPPED *ov, DWORD want,
                                const char *what)
{
  OVERLAPPED *done = NULL;
  DWORD b = 0;
  ULONG_PTR k = 0;
  BOOL got = GetQueuedCompletionStatus(port, &b, &k, &done, 5000);
  if(!done)
    fail_exit(what, GetLastError());
  if(done != ov || !got || b != want || k != KEY) {
    printf("FAIL %s: %s packet mismatch (bytes=%lu key=%llu)\n", TEST_NAME,
           what, (unsigned long)b, (unsigned long long)k);
    exit(1);
  }
}

/* Phase 1: overlapped file writes. Returns the number of sync completions. */
static int file_phase(HANDLE port)
{
  wchar_t tmp[MAX_PATH], dir[MAX_PATH], path[MAX_PATH];
  static unsigned char data[CHUNK];
  OVERLAPPED ov[NWRITES];
  HANDLE file;
  DWORD n = 0, gle;
  int i, sync_count = 0;
  LARGE_INTEGER size;

  memset(data, 0xAB, sizeof data);
  memset(ov, 0, sizeof ov);

  if(!GetTempPathW(MAX_PATH, tmp))
    fail_exit("GetTempPathW", GetLastError());
  _snwprintf(dir, MAX_PATH, L"%lsxcorp_iocp09_%lu", tmp,
             (unsigned long)GetCurrentProcessId());
  if(!CreateDirectoryW(dir, NULL))
    fail_exit("CreateDirectoryW", GetLastError());
  _snwprintf(path, MAX_PATH, L"%ls\\skip.bin", dir);

  file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                     FILE_FLAG_OVERLAPPED, NULL);
  if(file == INVALID_HANDLE_VALUE)
    fail_exit("CreateFileW(FILE_FLAG_OVERLAPPED)", GetLastError());
  if(CreateIoCompletionPort(file, port, KEY, 0) != port)
    fail_exit("file association", GetLastError());

  SetLastError(0);
  if(!SetFileCompletionNotificationModes(file,
                                         FILE_SKIP_COMPLETION_PORT_ON_SUCCESS)) {
    gle = GetLastError();
    if(gle == ERROR_CALL_NOT_IMPLEMENTED || gle == ERROR_INVALID_FUNCTION) {
      printf("SKIP %s: SetFileCompletionNotificationModes not implemented\n",
             TEST_NAME);
      CloseHandle(file);
      DeleteFileW(path);
      RemoveDirectoryW(dir);
      exit(77);
    }
    fail_exit("SetFileCompletionNotificationModes(file)", gle);
  }

  for(i = 0; i < NWRITES; i++) {
    ov[i].Offset = (DWORD)(i * CHUNK);
    n = 0;
    if(WriteFile(file, data, CHUNK, &n, &ov[i])) {
      sync_count++;
      if(n != CHUNK)
        fail_exit("sync write byte count", n);
      if(port_has_packet(port)) {
        printf("FAIL %s: file write %d completed synchronously but a packet "
               "was posted anyway\n", TEST_NAME, i);
        exit(1);
      }
    } else {
      gle = GetLastError();
      if(gle != ERROR_IO_PENDING)
        fail_exit("WriteFile", gle);
      expect_async_packet(port, &ov[i], CHUNK, "file async write");
    }
  }

  if(!GetFileSizeEx(file, &size) || size.QuadPart != (LONGLONG)NWRITES * CHUNK) {
    printf("FAIL %s: file size %lld expected %d\n", TEST_NAME,
           (long long)size.QuadPart, NWRITES * CHUNK);
    exit(1);
  }
  CloseHandle(file);
  DeleteFileW(path);
  RemoveDirectoryW(dir);
  return sync_count;
}

/* Phase 2: overlapped WSASend on a loopback TCP socket. */
static int socket_phase(HANDLE port)
{
  struct sockaddr_in sa;
  int salen = sizeof(sa);
  SOCKET listener, client, server;
  OVERLAPPED ov[NWRITES];
  WSABUF wb;
  char payload[8];
  DWORD n = 0;
  int i, sync_count = 0;
  char sink[NWRITES * 8];
  size_t total = 0;

  memset(&sa, 0, sizeof sa);
  listener = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                        WSA_FLAG_OVERLAPPED);
  client = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                      WSA_FLAG_OVERLAPPED);
  if(listener == INVALID_SOCKET || client == INVALID_SOCKET)
    fail_exit("WSASocketW", (DWORD)WSAGetLastError());
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(bind(listener, (struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR ||
     getsockname(listener, (struct sockaddr *)&sa, &salen) == SOCKET_ERROR ||
     listen(listener, 1) == SOCKET_ERROR)
    fail_exit("listener setup", (DWORD)WSAGetLastError());
  if(connect(client, (struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR)
    fail_exit("connect", (DWORD)WSAGetLastError());
  server = accept(listener, NULL, NULL);
  if(server == INVALID_SOCKET)
    fail_exit("accept", (DWORD)WSAGetLastError());
  closesocket(listener);

  if(CreateIoCompletionPort((HANDLE)client, port, KEY, 0) != port)
    fail_exit("socket association", GetLastError());
  if(!SetFileCompletionNotificationModes((HANDLE)client,
                                         FILE_SKIP_COMPLETION_PORT_ON_SUCCESS))
    fail_exit("SetFileCompletionNotificationModes(socket)", GetLastError());

  memset(ov, 0, sizeof ov);
  memset(payload, 'S', sizeof payload);
  for(i = 0; i < NWRITES; i++) {
    int rc;
    wb.buf = payload;
    wb.len = sizeof payload;
    n = 0;
    rc = WSASend(client, &wb, 1, &n, 0, &ov[i], NULL);
    if(rc == 0) {
      sync_count++;
      if(n != sizeof payload)
        fail_exit("sync WSASend byte count", n);
      if(port_has_packet(port)) {
        printf("FAIL %s: socket send %d completed synchronously but a packet "
               "was posted anyway\n", TEST_NAME, i);
        exit(1);
      }
    } else {
      if(WSAGetLastError() != WSA_IO_PENDING)
        fail_exit("WSASend", (DWORD)WSAGetLastError());
      expect_async_packet(port, &ov[i], sizeof payload, "socket async send");
    }
  }

  /* Drain what the peer received so the sender never blocks. */
  for(;;) {
    int r = recv(server, sink, sizeof sink, 0);
    if(r <= 0)
      break;
    total += (size_t)r;
    if(total >= NWRITES * sizeof payload)
      break;
  }
  if(total != NWRITES * sizeof payload) {
    printf("FAIL %s: peer received %lu bytes, expected %d\n", TEST_NAME,
           (unsigned long)total, NWRITES * (int)sizeof payload);
    exit(1);
  }

  closesocket(client);
  closesocket(server);
  return sync_count;
}

int main(void)
{
  WSADATA wsa;
  HANDLE port;
  int file_sync, sock_sync;

  port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
  if(!port)
    fail_exit("CreateIoCompletionPort", GetLastError());

  file_sync = file_phase(port);

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    fail_exit("WSAStartup", (DWORD)WSAGetLastError());
  sock_sync = socket_phase(port);
  WSACleanup();
  CloseHandle(port);

  if(file_sync == 0 && sock_sync == 0) {
    printf("SKIP %s: no operation completed synchronously in either phase; "
           "skip mode not observable here\n", TEST_NAME);
    return 77;
  }
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
