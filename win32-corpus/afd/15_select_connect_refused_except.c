/*
 * Test: 15_select_connect_refused_except
 * Area: afd
 * Purpose: curl's default readiness check is select(); on Windows a failed
 *   non-blocking connect is signalled through the EXCEPT set (not the write
 *   set), which curl's Curl_socket_check passes as exceptfds and then reads
 *   SO_ERROR. Pin which fd_sets fire and when.
 * APIs: select, connect, getsockopt(SO_ERROR), FIONBIO.
 * Success means: refused non-blocking connect: select with read, write and
 *   except sets returns 1 with the socket in the EXCEPT set only (not write,
 *   not read); a successful connect (live listener) returns 1 with the socket
 *   in the WRITE set only; SO_ERROR is 10061 / 0 respectively; select with an
 *   empty set and a 50 ms timeout returns SOCKET_ERROR WSAEINVAL (10022).
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

#define TEST_NAME "15_select_connect_refused_except"

int main(void)
{
  WSADATA d;
  struct sockaddr_in sa;
  SOCKET c, l;
  fd_set r, w, x;
  struct timeval tv = { 5, 0 };
  int rc, so = -1, sl = sizeof(so);

  WSAStartup(MAKEWORD(2, 2), &d);
  dead_port(&sa);
  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  nonblock(c);
  connect(c, (struct sockaddr *)&sa, sizeof(sa));
  FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&x);
  FD_SET(c, &r); FD_SET(c, &w); FD_SET(c, &x);
  rc = select(0, &r, &w, &x, &tv);
  INFO("refused: rc=%d r=%d w=%d x=%d", rc, FD_ISSET(c, &r) ? 1 : 0, FD_ISSET(c, &w) ? 1 : 0, FD_ISSET(c, &x) ? 1 : 0);
  EXPECT(rc == 1, "select rc=%d want 1", rc);
  EXPECT(FD_ISSET(c, &x) && !FD_ISSET(c, &w) && !FD_ISSET(c, &r), "refused connect must be EXCEPT only");
  getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&so, &sl);
  EXPECT(so == WSAECONNREFUSED, "SO_ERROR %d", so);
  closesocket(c);

  l = listener(&sa);
  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  nonblock(c);
  connect(c, (struct sockaddr *)&sa, sizeof(sa));
  FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&x);
  FD_SET(c, &r); FD_SET(c, &w); FD_SET(c, &x);
  tv.tv_sec = 5;
  rc = select(0, &r, &w, &x, &tv);
  INFO("accepted: rc=%d r=%d w=%d x=%d", rc, FD_ISSET(c, &r) ? 1 : 0, FD_ISSET(c, &w) ? 1 : 0, FD_ISSET(c, &x) ? 1 : 0);
  EXPECT(rc == 1 && FD_ISSET(c, &w) && !FD_ISSET(c, &x) && !FD_ISSET(c, &r), "successful connect must be WRITE only");
  so = -1;
  getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&so, &sl);
  EXPECT(so == 0, "SO_ERROR %d", so);
  closesocket(c); closesocket(l);

  FD_ZERO(&r);
  tv.tv_sec = 0; tv.tv_usec = 50000;
  rc = select(0, &r, NULL, NULL, &tv);
  EXPECT(rc == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "empty select rc=%d err=%d want -1, 10022", rc, WSAGetLastError());
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
