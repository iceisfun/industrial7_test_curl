/*
 * 10_wsaeventselect_enum_events
 *
 * Purpose: the WSAEventSelect / WSAEnumNetworkEvents readiness model on a
 *   connected loopback TCP pair. Verifies which network events are reported
 *   for writability, data arrival and peer close, and that WSAEnumNetworkEvents
 *   clears the reported state.
 * APIs: WSAStartup, WSASocketW, bind/listen/connect/accept, WSACreateEvent,
 *   WSAEventSelect, WSAWaitForMultipleEvents, WSAEnumNetworkEvents,
 *   WSACloseEvent, send, recv, ioctlsocket(FIONREAD), closesocket.
 * Success:
 *   - a freshly connected socket is writable: the event fires and
 *     WSAEnumNetworkEvents reports FD_WRITE with iErrorCode 0;
 *   - before any data is sent there is no FD_READ;
 *   - after the peer sends "abcde" the event fires and FD_READ is reported;
 *     the 5 bytes are received intact;
 *   - after the peer closes, FD_CLOSE is reported and recv returns 0.
 * Source: curl uses this model for winsock polling, see lib/multi.c:1389-1458
 *   (WSAEventSelect and WSAEnumNetworkEvents) and lib/telnet.c:1271 and 1370.
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

#define TEST_NAME "10_wsaeventselect_enum_events"

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

/* Wait up to ms for the event; returns TRUE when it is signaled. */
static BOOL wait_event(WSAEVENT ev, DWORD ms)
{
  DWORD r = WSAWaitForMultipleEvents(1, &ev, FALSE, ms, FALSE);
  if(r == WSA_WAIT_EVENT_0)
    return TRUE;
  if(r == WSA_WAIT_TIMEOUT)
    return FALSE;
  fail_exit("WSAWaitForMultipleEvents", (DWORD)WSAGetLastError());
  return FALSE;
}

int main(void)
{
  WSADATA wsa;
  struct sockaddr_in sa;
  int salen = sizeof(sa);
  SOCKET listener, client, server;
  WSAEVENT ev;
  WSANETWORKEVENTS ne;
  char buf[16];
  u_long avail = 0;
  int got = 0, r, tries;
  BOOL seen;

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

  ev = WSACreateEvent();
  if(ev == WSA_INVALID_EVENT)
    fail_exit("WSACreateEvent", (DWORD)WSAGetLastError());
  if(WSAEventSelect(client, ev, FD_READ | FD_WRITE | FD_CLOSE) == SOCKET_ERROR)
    fail_exit("WSAEventSelect", (DWORD)WSAGetLastError());

  /* 1. Fresh connection: writable. */
  if(!wait_event(ev, 2000))
    fail_exit("no event for a freshly connected socket", 0);
  memset(&ne, 0, sizeof ne);
  if(WSAEnumNetworkEvents(client, NULL, &ne) == SOCKET_ERROR)
    fail_exit("WSAEnumNetworkEvents(write)", (DWORD)WSAGetLastError());
  if(!(ne.lNetworkEvents & FD_WRITE))
    fail_exit("FD_WRITE not reported for connected socket", 0);
  if(ne.iErrorCode[FD_WRITE_BIT] != 0)
    fail_exit("FD_WRITE iErrorCode nonzero", (DWORD)ne.iErrorCode[FD_WRITE_BIT]);
  if(ne.lNetworkEvents & FD_READ)
    fail_exit("FD_READ reported before any data was sent", 0);

  /* 2. Server sends 5 bytes; client must see FD_READ. Poll with a bound. */
  if(send(server, "abcde", 5, 0) != 5)
    fail_exit("send", (DWORD)WSAGetLastError());
  seen = FALSE;
  for(tries = 0; tries < 20 && !seen; tries++) {
    if(!wait_event(ev, 100))
      continue;
    memset(&ne, 0, sizeof ne);
    if(WSAEnumNetworkEvents(client, ev, &ne) == SOCKET_ERROR)
      fail_exit("WSAEnumNetworkEvents(read)", (DWORD)WSAGetLastError());
    if(ne.lNetworkEvents & FD_READ) {
      seen = TRUE;
      if(ne.iErrorCode[FD_READ_BIT] != 0)
        fail_exit("FD_READ iErrorCode nonzero",
                  (DWORD)ne.iErrorCode[FD_READ_BIT]);
    }
  }
  if(!seen)
    fail_exit("FD_READ never reported after send", 0);

  /* Data must be there: FIONREAD >= 5, then recv 5 bytes. */
  if(ioctlsocket(client, FIONREAD, &avail) == SOCKET_ERROR)
    fail_exit("ioctlsocket(FIONREAD)", (DWORD)WSAGetLastError());
  if(avail < 5)
    fail_exit("FIONREAD below 5 after FD_READ", (DWORD)avail);

  memset(buf, 0, sizeof buf);
  for(tries = 0; got < 5 && tries < 200; tries++) {
    r = recv(client, buf + got, 5 - got, 0);
    if(r > 0) {
      got += r;
    } else if(r == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
      Sleep(10);
    } else {
      fail_exit("recv", (DWORD)WSAGetLastError());
    }
  }
  if(got != 5 || memcmp(buf, "abcde", 5) != 0) {
    printf("FAIL %s: received %d bytes, content mismatch\n", TEST_NAME, got);
    return 1;
  }

  /* 3. Server closes; client must see FD_CLOSE and recv must return 0. */
  closesocket(server);
  server = INVALID_SOCKET;
  seen = FALSE;
  for(tries = 0; tries < 20 && !seen; tries++) {
    if(!wait_event(ev, 100))
      continue;
    memset(&ne, 0, sizeof ne);
    if(WSAEnumNetworkEvents(client, ev, &ne) == SOCKET_ERROR)
      fail_exit("WSAEnumNetworkEvents(close)", (DWORD)WSAGetLastError());
    if(ne.lNetworkEvents & FD_CLOSE)
      seen = TRUE;
  }
  if(!seen)
    fail_exit("FD_CLOSE never reported after peer close", 0);

  for(tries = 0; tries < 200; tries++) {
    r = recv(client, buf, sizeof buf, 0);
    if(r == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
      Sleep(10);
      continue;
    }
    break;
  }
  if(r != 0)
    fail_exit("recv after peer close should return 0", (DWORD)WSAGetLastError());

  /* Deselect: clearing the mask must succeed. */
  if(WSAEventSelect(client, ev, 0) == SOCKET_ERROR)
    fail_exit("WSAEventSelect(0)", (DWORD)WSAGetLastError());
  if(!WSACloseEvent(ev))
    fail_exit("WSACloseEvent", (DWORD)WSAGetLastError());

  closesocket(client);
  WSACleanup();
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
