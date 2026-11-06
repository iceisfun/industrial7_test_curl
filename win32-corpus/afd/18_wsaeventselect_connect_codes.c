/*
 * Test: 18_wsaeventselect_connect_codes
 * Area: afd
 * Purpose: curl's event-driven paths (curl_multi_wait wakeup, WSAEventSelect
 *   in lib/cf-socket.c Curl_poll fallback) read connect results from
 *   WSAEnumNetworkEvents. Pin the event bits and per-event error codes.
 * APIs: WSAEventSelect, WSAEnumNetworkEvents, WSAWaitForMultipleEvents.
 * Success means: refused connect: event signalled, lNetworkEvents has FD_CONNECT
 *   only (no FD_WRITE), iErrorCode[FD_CONNECT_BIT] == 10061; accepted connect:
 *   FD_CONNECT with error 0 and FD_WRITE; a second WSAEnumNetworkEvents with
 *   no new activity returns 0 events and the event stays reset; FD_CLOSE after
 *   the peer closes has iErrorCode[FD_CLOSE_BIT] == 0 for FIN and 10053
 *   (WSAECONNABORTED, not 10054) for a loopback RST; WSAEventSelect(s, ev, 0) cancels delivery and makes the socket
 *   non-blocking again? -- recorded via ioctl probe (INFO).
 * Exit: 0 PASS, 1 FAIL.
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
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPECT(cond, ...) do { if(!(cond)) { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); fflush(stdout); return 1; } } while(0)
#define INFO(...) do { printf("INFO "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while(0)

__attribute__((unused)) static void nonblock(SOCKET s) { u_long on = 1; ioctlsocket(s, FIONBIO, &on); }

static SOCKET listener(struct sockaddr_in *sa)
{
  SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  int len = (int)sizeof(*sa);
  memset(sa, 0, sizeof(*sa));
  sa->sin_family = AF_INET;
  sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(l == INVALID_SOCKET || bind(l, (struct sockaddr *)sa, sizeof(*sa)) || listen(l, 4) ||
     getsockname(l, (struct sockaddr *)sa, &len)) return INVALID_SOCKET;
  return l;
}

/* A loopback port with no listener (bound, then closed). */
__attribute__((unused)) static void dead_port(struct sockaddr_in *sa)
{
  SOCKET l = listener(sa);
  closesocket(l);
}

__attribute__((unused)) static int pair(SOCKET *c, SOCKET *s)
{
  struct sockaddr_in sa;
  SOCKET l = listener(&sa);
  if(l == INVALID_SOCKET) return 0;
  *c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(connect(*c, (struct sockaddr *)&sa, sizeof(sa))) return 0;
  *s = accept(l, NULL, NULL);
  closesocket(l);
  return *s != INVALID_SOCKET;
}

#define TEST_NAME "18_wsaeventselect_connect_codes"

int main(void)
{
  WSADATA d;
  struct sockaddr_in sa;
  SOCKET c, s, l;
  WSAEVENT ev;
  WSANETWORKEVENTS ne;
  struct linger lg = { 1, 0 };
  int rc;

  WSAStartup(MAKEWORD(2, 2), &d);
  ev = WSACreateEvent();

  dead_port(&sa);
  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  EXPECT(WSAEventSelect(c, ev, FD_CONNECT | FD_WRITE | FD_CLOSE | FD_READ) == 0, "WSAEventSelect");
  connect(c, (struct sockaddr *)&sa, sizeof(sa));
  EXPECT(WSAWaitForMultipleEvents(1, &ev, FALSE, 5000, FALSE) == WSA_WAIT_EVENT_0, "refused: event not signalled");
  memset(&ne, 0, sizeof(ne));
  rc = WSAEnumNetworkEvents(c, ev, &ne);
  INFO("refused: rc=%d events=0x%lx connect_err=%d", rc, ne.lNetworkEvents, ne.iErrorCode[FD_CONNECT_BIT]);
  EXPECT(rc == 0, "enum rc=%d", rc);
  EXPECT(ne.lNetworkEvents == FD_CONNECT, "refused: events 0x%lx want FD_CONNECT only", ne.lNetworkEvents);
  EXPECT(ne.iErrorCode[FD_CONNECT_BIT] == WSAECONNREFUSED, "refused: error %d", ne.iErrorCode[FD_CONNECT_BIT]);
  closesocket(c);

  l = listener(&sa);
  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  WSAResetEvent(ev);
  WSAEventSelect(c, ev, FD_CONNECT | FD_WRITE | FD_CLOSE | FD_READ);
  connect(c, (struct sockaddr *)&sa, sizeof(sa));
  EXPECT(WSAWaitForMultipleEvents(1, &ev, FALSE, 5000, FALSE) == WSA_WAIT_EVENT_0, "accepted: event not signalled");
  memset(&ne, 0, sizeof(ne));
  WSAEnumNetworkEvents(c, ev, &ne);
  INFO("accepted: events=0x%lx connect_err=%d write_err=%d", ne.lNetworkEvents, ne.iErrorCode[FD_CONNECT_BIT], ne.iErrorCode[FD_WRITE_BIT]);
  EXPECT(ne.lNetworkEvents == (FD_CONNECT | FD_WRITE), "accepted: events 0x%lx want CONNECT|WRITE", ne.lNetworkEvents);
  EXPECT(ne.iErrorCode[FD_CONNECT_BIT] == 0, "accepted: connect error %d", ne.iErrorCode[FD_CONNECT_BIT]);
  memset(&ne, 0, sizeof(ne));
  WSAEnumNetworkEvents(c, ev, &ne);
  EXPECT(ne.lNetworkEvents == 0, "second enum events 0x%lx want 0", ne.lNetworkEvents);
  EXPECT(WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE) == WSA_WAIT_TIMEOUT, "event still signalled after enum");

  s = accept(l, NULL, NULL);
  closesocket(s);
  EXPECT(WSAWaitForMultipleEvents(1, &ev, FALSE, 5000, FALSE) == WSA_WAIT_EVENT_0, "FIN: event not signalled");
  memset(&ne, 0, sizeof(ne));
  WSAEnumNetworkEvents(c, ev, &ne);
  INFO("FIN: events=0x%lx close_err=%d", ne.lNetworkEvents, ne.iErrorCode[FD_CLOSE_BIT]);
  EXPECT((ne.lNetworkEvents & FD_CLOSE) && ne.iErrorCode[FD_CLOSE_BIT] == 0, "FIN: events 0x%lx close_err %d", ne.lNetworkEvents, ne.iErrorCode[FD_CLOSE_BIT]);
  closesocket(c);

  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  WSAResetEvent(ev);
  connect(c, (struct sockaddr *)&sa, sizeof(sa));
  s = accept(l, NULL, NULL);
  WSAEventSelect(c, ev, FD_CLOSE | FD_READ);
  setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
  closesocket(s);
  EXPECT(WSAWaitForMultipleEvents(1, &ev, FALSE, 5000, FALSE) == WSA_WAIT_EVENT_0, "RST: event not signalled");
  memset(&ne, 0, sizeof(ne));
  WSAEnumNetworkEvents(c, ev, &ne);
  INFO("RST: events=0x%lx close_err=%d read_err=%d", ne.lNetworkEvents, ne.iErrorCode[FD_CLOSE_BIT], ne.iErrorCode[FD_READ_BIT]);
  EXPECT((ne.lNetworkEvents & FD_CLOSE) && ne.iErrorCode[FD_CLOSE_BIT] == WSAECONNABORTED, "RST: events 0x%lx close_err %d want 10053", ne.lNetworkEvents, ne.iErrorCode[FD_CLOSE_BIT]);
  closesocket(c); closesocket(l);

  /* WSAEventSelect makes the socket non-blocking; cancelling does not restore blocking mode by itself */
  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  WSAEventSelect(c, ev, FD_READ);
  WSAEventSelect(c, NULL, 0);
  {
    u_long nb = 0;
    rc = ioctlsocket(c, FIONBIO, &nb);   /* sets blocking */
    EXPECT(rc == 0, "FIONBIO(0) after cancel rc=%d err=%d", rc, WSAGetLastError());
  }
  closesocket(c);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
