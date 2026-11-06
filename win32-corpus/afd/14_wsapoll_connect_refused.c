/*
 * Test: 14_wsapoll_connect_refused
 * Area: afd
 * Purpose: curl (lib/cf-socket.c, Curl_socket_check / WSAPoll path, and
 *   libuv-style users) waits on a non-blocking connect with WSAPoll. A refused
 *   connect must be reported as an event, otherwise the poll runs to its
 *   timeout. On pre-2004 Windows 10 WSAPoll never reported connect failure;
 *   Win10 22H2 (19045) does. Measures the exact bits.
 * APIs: WSAPoll, connect, getsockopt(SO_ERROR), ioctlsocket(FIONBIO).
 * Success means: non-blocking connect to a dead loopback port returns
 *   WSAEWOULDBLOCK; WSAPoll(POLLWRNORM) returns 1 within 5 s with revents
 *   including POLLERR|POLLHUP|POLLWRNORM (probed value, see INFO line); then
 *   SO_ERROR == WSAECONNREFUSED (10061), and a second SO_ERROR read still
 *   returns 10061 (not cleared on Win10 22H2). Poll completes in ~2.05 s
 *   (the loopback SYN retransmit), so the 5 s limit has margin.
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

#define TEST_NAME "14_wsapoll_connect_refused"

int main(void)
{
  WSADATA d;
  struct sockaddr_in sa;
  SOCKET c;
  WSAPOLLFD p;
  int rc, so = -1, sl = sizeof(so);
  DWORD t0;

  WSAStartup(MAKEWORD(2, 2), &d);
  dead_port(&sa);
  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  nonblock(c);
  rc = connect(c, (struct sockaddr *)&sa, sizeof(sa));
  EXPECT(rc == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK, "connect rc=%d err=%d", rc, WSAGetLastError());
  memset(&p, 0, sizeof(p)); p.fd = c; p.events = POLLWRNORM;
  t0 = GetTickCount();
  rc = WSAPoll(&p, 1, 5000);
  INFO("WSAPoll rc=%d revents=0x%x after %lu ms", rc, (unsigned)p.revents, GetTickCount() - t0);
  EXPECT(rc == 1, "WSAPoll rc=%d (refused connect not reported)", rc);
  EXPECT(p.revents == (POLLERR | POLLHUP | POLLWRNORM), "revents 0x%x want ERR|HUP|WRNORM 0x%x", (unsigned)p.revents,
         (unsigned)(POLLERR | POLLHUP | POLLWRNORM));
  getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&so, &sl);
  EXPECT(so == WSAECONNREFUSED, "SO_ERROR %d want 10061", so);
  /* Win10 22H2: SO_ERROR is sticky for a failed connect, a second read does NOT clear it. */
  getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&so, &sl);
  INFO("second SO_ERROR=%d", so);
  EXPECT(so == WSAECONNREFUSED, "second SO_ERROR read %d want 10061 (sticky)", so);
  closesocket(c);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
