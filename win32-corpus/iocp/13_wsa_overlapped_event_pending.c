/*
 * 13_wsa_overlapped_event_pending
 *
 * Purpose: overlapped WSARecv and WSASend without a completion port, using
 *   OVERLAPPED.hEvent per request. Checks the WSA_IO_PENDING lifecycle and
 *   WSAGetOverlappedResult in both its non-waiting and waiting forms.
 * APIs: WSASocketW (WSA_FLAG_OVERLAPPED), connect/accept, WSARecv and WSASend
 *   with OVERLAPPED.hEvent, WSAGetOverlappedResult, WSAGetLastError,
 *   WaitForSingleObject, CreateEventW, closesocket.
 * Success:
 *   - WSARecv issued before any data returns SOCKET_ERROR with
 *     WSA_IO_PENDING (997, same value as ERROR_IO_PENDING);
 *   - WSAGetOverlappedResult(bWait=FALSE) returns FALSE with WSA_IO_INCOMPLETE
 *     (996) and the event is not signaled;
 *   - after WSASend("event-path") from the peer, the event is signaled and
 *     WSAGetOverlappedResult returns TRUE with 10 bytes and the payload;
 *   - a WSASend whose result is pending (or immediate) completes with
 *     WSAGetOverlappedResult(bWait=TRUE) reporting the 10 bytes sent;
 *   - a WSARecv after the peer closes completes with TRUE and 0 bytes.
 * Source: curl does not issue overlapped WSARecv/WSASend. Generic Winsock
 *   overlapped contract. The WSA_IO_PENDING check mirrors the lib/ style of
 *   SOCKERRNO comparisons; no curl file:line reference.
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

#define TEST_NAME "13_wsa_overlapped_event_pending"

static void fail_exit(const char *why, DWORD err)
{
  printf("FAIL %s: %s (err=%lu)\n", TEST_NAME, why, (unsigned long)err);
  exit(1);
}

static SOCKET make_socket(void)
{
  SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                        WSA_FLAG_OVERLAPPED);
  if(s == INVALID_SOCKET)
    fail_exit("WSASocketW", (DWORD)WSAGetLastError());
  return s;
}

int main(void)
{
  WSADATA wsa;
  struct sockaddr_in sa;
  int salen = sizeof(sa);
  SOCKET listener, client, server;
  OVERLAPPED ovr, ovs, ovz;
  WSABUF wb;
  char rbuf[32];
  const char payload[] = "event-path";
  DWORD n = 0, flags = 0, w;
  int rc;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    fail_exit("WSAStartup", (DWORD)WSAGetLastError());

  listener = make_socket();
  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(bind(listener, (struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR ||
     getsockname(listener, (struct sockaddr *)&sa, &salen) == SOCKET_ERROR ||
     listen(listener, 1) == SOCKET_ERROR)
    fail_exit("listener setup", (DWORD)WSAGetLastError());
  client = make_socket();
  if(connect(client, (struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR)
    fail_exit("connect", (DWORD)WSAGetLastError());
  server = accept(listener, NULL, NULL);
  if(server == INVALID_SOCKET)
    fail_exit("accept", (DWORD)WSAGetLastError());
  closesocket(listener);

  memset(&ovr, 0, sizeof ovr);
  ovr.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!ovr.hEvent)
    fail_exit("CreateEventW", GetLastError());

  /* 1. Receive before data exists: must be pending. */
  memset(rbuf, 0, sizeof rbuf);
  wb.buf = rbuf;
  wb.len = sizeof rbuf;
  flags = 0;
  n = 0;
  rc = WSARecv(server, &wb, 1, &n, &flags, &ovr, NULL);
  if(rc != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING)
    fail_exit("WSARecv: expected SOCKET_ERROR/WSA_IO_PENDING", (DWORD)WSAGetLastError());
  if(WSA_IO_PENDING != ERROR_IO_PENDING)
    fail_exit("WSA_IO_PENDING value differs from ERROR_IO_PENDING", 0);

  /* 2. Not waiting: incomplete, event unsignaled. */
  SetLastError(0);
  WSASetLastError(0);
  if(WSAGetOverlappedResult(server, &ovr, &n, FALSE, &flags))
    fail_exit("WSAGetOverlappedResult TRUE while pending", 0);
  if(WSAGetLastError() != WSA_IO_INCOMPLETE)
    fail_exit("WSAGetOverlappedResult: expected WSA_IO_INCOMPLETE",
              (DWORD)WSAGetLastError());
  if(WaitForSingleObject(ovr.hEvent, 0) != WAIT_TIMEOUT)
    fail_exit("receive event signaled while pending", 0);

  /* 3. Client sends the payload; receive must complete. */
  memset(&ovs, 0, sizeof ovs);
  ovs.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!ovs.hEvent)
    fail_exit("CreateEventW(send)", GetLastError());
  wb.buf = (char *)payload;
  wb.len = 10;
  n = 0;
  rc = WSASend(client, &wb, 1, &n, 0, &ovs, NULL);
  if(rc == SOCKET_ERROR) {
    if(WSAGetLastError() != WSA_IO_PENDING)
      fail_exit("WSASend", (DWORD)WSAGetLastError());
    /* Pending send: wait on its event, then collect with bWait=TRUE. */
    w = WaitForSingleObject(ovs.hEvent, 5000);
    if(w != WAIT_OBJECT_0)
      fail_exit("send event not signaled", w);
  }
  n = 0;
  flags = 0;
  if(!WSAGetOverlappedResult(client, &ovs, &n, TRUE, &flags) || n != 10)
    fail_exit("WSAGetOverlappedResult(send) did not report 10 bytes",
              (DWORD)WSAGetLastError());

  w = WaitForSingleObject(ovr.hEvent, 5000);
  if(w != WAIT_OBJECT_0)
    fail_exit("receive event not signaled after send", w);
  n = 0;
  flags = 0;
  if(!WSAGetOverlappedResult(server, &ovr, &n, FALSE, &flags))
    fail_exit("WSAGetOverlappedResult(recv)", (DWORD)WSAGetLastError());
  if(n != 10) {
    printf("FAIL %s: receive transferred %lu bytes, expected 10\n", TEST_NAME,
           (unsigned long)n);
    return 1;
  }
  if(memcmp(rbuf, payload, 10) != 0) {
    printf("FAIL %s: receive payload mismatch\n", TEST_NAME);
    return 1;
  }

  /* 4. Peer closes; a fresh overlapped receive completes with 0 bytes. */
  closesocket(client);
  client = INVALID_SOCKET;
  memset(&ovz, 0, sizeof ovz);
  ovz.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!ovz.hEvent)
    fail_exit("CreateEventW(eof)", GetLastError());
  wb.buf = rbuf;
  wb.len = sizeof rbuf;
  flags = 0;
  n = 99;
  rc = WSARecv(server, &wb, 1, &n, &flags, &ovz, NULL);
  if(rc == SOCKET_ERROR) {
    if(WSAGetLastError() != WSA_IO_PENDING)
      fail_exit("WSARecv(eof)", (DWORD)WSAGetLastError());
    w = WaitForSingleObject(ovz.hEvent, 5000);
    if(w != WAIT_OBJECT_0)
      fail_exit("EOF event not signaled", w);
  }
  n = 99;
  flags = 0;
  if(!WSAGetOverlappedResult(server, &ovz, &n, TRUE, &flags))
    fail_exit("WSAGetOverlappedResult(eof) reported error",
              (DWORD)WSAGetLastError());
  if(n != 0) {
    printf("FAIL %s: EOF receive transferred %lu bytes, expected 0\n",
           TEST_NAME, (unsigned long)n);
    return 1;
  }

  CloseHandle(ovr.hEvent);
  CloseHandle(ovs.hEvent);
  CloseHandle(ovz.hEvent);
  closesocket(server);
  WSACleanup();
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
