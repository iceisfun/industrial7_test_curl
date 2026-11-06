/*
 * Test: 16_wsapoll_edge_cases
 * Area: afd
 * Purpose: Corner cases curl's poll wrapper (lib/select.c Curl_poll, which
 *   sleeps when it has no sockets) depends on.
 * APIs: WSAPoll, closesocket.
 * Success means (Win10 22H2): WSAPoll(NULL, 0, 50) fails with WSAEINVAL
 *   (10022) and does not sleep; an INVALID_SOCKET entry or a closed-socket
 *   entry makes WSAPoll FAIL (-1, WSAENOTSOCK 10038) with revents ==
 *   POLLNVAL (unlike POSIX poll, which returns the count); a zero timeout on
 *   an idle socket returns 0 with revents 0; timeout -2 acts like infinite
 *   on a ready socket; an entry with events=0 on a peer-closed socket still
 *   reports POLLHUP.
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

#define TEST_NAME "16_wsapoll_edge_cases"

int main(void)
{
  WSADATA d;
  SOCKET c, s, dead;
  WSAPOLLFD p[2];
  int rc, e;
  DWORD t0;

  WSAStartup(MAKEWORD(2, 2), &d);
  t0 = GetTickCount();
  rc = WSAPoll(NULL, 0, 500);
  e = WSAGetLastError();
  INFO("WSAPoll(NULL,0) rc=%d err=%d after %lu ms", rc, e, GetTickCount() - t0);
  EXPECT(rc == SOCKET_ERROR && e == WSAEINVAL, "WSAPoll(NULL,0) rc=%d err=%d want -1, 10022", rc, e);
  EXPECT(GetTickCount() - t0 < 200, "WSAPoll(NULL,0) slept");

  memset(p, 0, sizeof(p)); p[0].fd = INVALID_SOCKET; p[0].events = POLLRDNORM;
  rc = WSAPoll(p, 1, 50); e = WSAGetLastError();
  INFO("WSAPoll(INVALID_SOCKET) rc=%d err=%d revents=0x%x", rc, e, (unsigned)p[0].revents);
  EXPECT(rc == SOCKET_ERROR && e == WSAENOTSOCK && p[0].revents == POLLNVAL, "INVALID_SOCKET entry: rc=%d err=%d revents=0x%x want -1, 10038, POLLNVAL", rc, e, (unsigned)p[0].revents);

  dead = socket(AF_INET, SOCK_STREAM, 0);
  closesocket(dead);
  memset(p, 0, sizeof(p)); p[0].fd = dead; p[0].events = POLLRDNORM;
  rc = WSAPoll(p, 1, 50); e = WSAGetLastError();
  INFO("WSAPoll(closed) rc=%d err=%d revents=0x%x", rc, e, (unsigned)p[0].revents);
  EXPECT(rc == SOCKET_ERROR && e == WSAENOTSOCK && p[0].revents == POLLNVAL, "closed socket: rc=%d err=%d revents=0x%x want -1, 10038, POLLNVAL", rc, e, (unsigned)p[0].revents);

  EXPECT(pair(&c, &s), "pair");
  memset(p, 0, sizeof(p)); p[0].fd = c; p[0].events = POLLRDNORM;
  rc = WSAPoll(p, 1, 0);
  EXPECT(rc == 0 && p[0].revents == 0, "idle zero-timeout rc=%d revents=0x%x", rc, (unsigned)p[0].revents);
  memset(p, 0, sizeof(p)); p[0].fd = c; p[0].events = POLLWRNORM;
  rc = WSAPoll(p, 1, -2);
  INFO("negative timeout -2 with ready socket rc=%d err=%d", rc, WSAGetLastError());
  EXPECT(rc == 1 && p[0].revents == POLLWRNORM, "timeout -2: rc=%d revents=0x%x", rc, (unsigned)p[0].revents);

  /* two entries: closed peer reports HUP even if events asks for nothing */
  closesocket(s);
  memset(p, 0, sizeof(p)); p[0].fd = c; p[0].events = 0;
  Sleep(100);
  rc = WSAPoll(p, 1, 200);
  INFO("peer closed, events=0: rc=%d revents=0x%x", rc, (unsigned)p[0].revents);
  EXPECT(rc == 1 && p[0].revents == POLLHUP, "events=0 on closed peer: rc=%d revents=0x%x want 1, POLLHUP", rc, (unsigned)p[0].revents);
  closesocket(c);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
