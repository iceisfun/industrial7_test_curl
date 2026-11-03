/*
 * Test: 05_wsaeventselect_wait
 * Purpose: Mirror curl's WSAEventSelect() based wait used when the multi
 *   interface waits on sockets with a per-multi WSAEVENT.
 * APIs: WSAStartup, socket, bind, getsockname, listen, connect, accept,
 *   WSACreateEvent, WSAEventSelect, WSAWaitForMultipleEvents,
 *   WSAEnumNetworkEvents, WSACloseEvent, ioctlsocket, recv, send
 * Source: lib/multi.c:1389 (WSAEventSelect(fd, multi->wsa_event, mask)),
 *   lib/multi.c:1409 (WSAWaitForMultipleEvents with the timeout in ms),
 *   lib/multi.c:1433 and 1458 (WSAEventSelect(s, event, 0) to unregister).
 *   telnet.c:1271 uses the same registration with FD_READ | FD_CLOSE.
 * Success: a wait with no traffic times out (WSA_WAIT_TIMEOUT); after the
 *   peer sends "hello" the wait returns WSA_WAIT_EVENT_0 and
 *   WSAEnumNetworkEvents reports FD_READ with no error; after the peer
 *   closes, the wait returns again and FD_CLOSE is reported; unregistering
 *   with WSAEventSelect(s, ev, 0) succeeds.
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
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "05_wsaeventselect_wait"

static SOCKET make_tcp_pair(SOCKET *accepted, int *err)
{
  struct sockaddr_in sa;
  int salen = (int)sizeof(sa);
  SOCKET listener, client;

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;

  listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(listener == INVALID_SOCKET) {
    *err = WSAGetLastError();
    return INVALID_SOCKET;
  }
  if(bind(listener, (struct sockaddr *)&sa, (int)sizeof(sa)) != 0 ||
     getsockname(listener, (struct sockaddr *)&sa, &salen) != 0 ||
     listen(listener, 1) != 0) {
    *err = WSAGetLastError();
    closesocket(listener);
    return INVALID_SOCKET;
  }
  client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(client == INVALID_SOCKET) {
    *err = WSAGetLastError();
    closesocket(listener);
    return INVALID_SOCKET;
  }
  if(connect(client, (struct sockaddr *)&sa, (int)sizeof(sa)) != 0) {
    *err = WSAGetLastError();
    closesocket(client);
    closesocket(listener);
    return INVALID_SOCKET;
  }
  *accepted = accept(listener, NULL, NULL);
  closesocket(listener);
  if(*accepted == INVALID_SOCKET) {
    *err = WSAGetLastError();
    closesocket(client);
    return INVALID_SOCKET;
  }
  return client;
}

static void cleanup_all(SOCKET a, SOCKET b, WSAEVENT ev)
{
  if(a != INVALID_SOCKET)
    closesocket(a);
  if(b != INVALID_SOCKET)
    closesocket(b);
  if(ev != WSA_INVALID_EVENT)
    WSACloseEvent(ev);
  WSACleanup();
}

int main(void)
{
  WSADATA wsa;
  SOCKET server = INVALID_SOCKET, client = INVALID_SOCKET;
  WSAEVENT ev = WSA_INVALID_EVENT;
  WSANETWORKEVENTS ne;
  DWORD w;
  char buf[16];
  int n;
  int err = 0;
  u_long mode;

  if(WSAStartup(MAKEWORD(2, 2), &wsa)) {
    printf("FAIL %s: WSAStartup failed\n", TEST_NAME);
    return 1;
  }

  client = make_tcp_pair(&server, &err);
  if(client == INVALID_SOCKET) {
    printf("FAIL %s: loopback pair setup failed, WSAGetLastError=%d\n",
           TEST_NAME, err);
    cleanup_all(client, server, ev);
    return 1;
  }

  ev = WSACreateEvent();
  if(ev == WSA_INVALID_EVENT) {
    printf("FAIL %s: WSACreateEvent failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    cleanup_all(client, server, ev);
    return 1;
  }

  if(WSAEventSelect(server, ev, FD_READ | FD_CLOSE) != 0) {
    printf("FAIL %s: WSAEventSelect(FD_READ|FD_CLOSE) failed, "
           "WSAGetLastError=%d\n", TEST_NAME, WSAGetLastError());
    cleanup_all(client, server, ev);
    return 1;
  }

  /* 1. No traffic yet: the wait must time out */
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 50, FALSE);
  if(w != WSA_WAIT_TIMEOUT) {
    printf("FAIL %s: idle wait returned %lu, expected WSA_WAIT_TIMEOUT\n",
           TEST_NAME, (unsigned long)w);
    cleanup_all(client, server, ev);
    return 1;
  }

  /* 2. Peer sends data: wait must signal and report FD_READ */
  if(send(client, "hello", 5, 0) != 5) {
    printf("FAIL %s: send failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    cleanup_all(client, server, ev);
    return 1;
  }
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 2000, FALSE);
  if(w != WSA_WAIT_EVENT_0) {
    printf("FAIL %s: data wait returned %lu, expected WSA_WAIT_EVENT_0\n",
           TEST_NAME, (unsigned long)w);
    cleanup_all(client, server, ev);
    return 1;
  }
  memset(&ne, 0, sizeof(ne));
  if(WSAEnumNetworkEvents(server, ev, &ne) != 0) {
    printf("FAIL %s: WSAEnumNetworkEvents failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    cleanup_all(client, server, ev);
    return 1;
  }
  if(!(ne.lNetworkEvents & FD_READ) || ne.iErrorCode[FD_READ_BIT] != 0) {
    printf("FAIL %s: events=0x%lx readerr=%d, expected FD_READ without error\n",
           TEST_NAME, (unsigned long)ne.lNetworkEvents,
           ne.iErrorCode[FD_READ_BIT]);
    cleanup_all(client, server, ev);
    return 1;
  }

  /* Drain the data so the next event is about the close only */
  mode = 1;
  ioctlsocket(server, FIONBIO, &mode);
  n = recv(server, buf, (int)sizeof(buf), 0);
  if(n != 5 || memcmp(buf, "hello", 5) != 0) {
    printf("FAIL %s: recv returned %d, expected 5 bytes 'hello'\n",
           TEST_NAME, n);
    cleanup_all(client, server, ev);
    return 1;
  }

  /* 3. Peer closes: wait must signal and report FD_CLOSE */
  closesocket(client);
  client = INVALID_SOCKET;
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 2000, FALSE);
  if(w != WSA_WAIT_EVENT_0) {
    printf("FAIL %s: close wait returned %lu, expected WSA_WAIT_EVENT_0\n",
           TEST_NAME, (unsigned long)w);
    cleanup_all(client, server, ev);
    return 1;
  }
  memset(&ne, 0, sizeof(ne));
  if(WSAEnumNetworkEvents(server, ev, &ne) != 0 ||
     !(ne.lNetworkEvents & FD_CLOSE)) {
    printf("FAIL %s: events=0x%lx after peer close, expected FD_CLOSE\n",
           TEST_NAME, (unsigned long)ne.lNetworkEvents);
    cleanup_all(client, server, ev);
    return 1;
  }

  /* 4. Unregister as curl does; afterwards the socket is non-blocking
        from WSAEventSelect, curl resets it with FIONBIO 0 */
  if(WSAEventSelect(server, ev, 0) != 0) {
    printf("FAIL %s: WSAEventSelect(s, ev, 0) failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    cleanup_all(client, server, ev);
    return 1;
  }
  mode = 0;
  if(ioctlsocket(server, FIONBIO, &mode) != 0) {
    printf("FAIL %s: ioctlsocket(FIONBIO, 0) failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    cleanup_all(client, server, ev);
    return 1;
  }

  cleanup_all(client, server, ev);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
