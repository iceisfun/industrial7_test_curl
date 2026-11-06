/*
 * Test: 17_wsapoll_peer_close_modes
 * Area: afd
 * Purpose: How WSAPoll/select report each way a peer can end a connection,
 *   which decides curl's recv()==0 vs ECONNRESET handling and the
 *   "connection closed" vs "recv failure" messages.
 * APIs: WSAPoll, select, shutdown, closesocket, SO_LINGER, recv.
 * Success means (Win10 22H2, loopback):
 *   graceful close (FIN): WSAPoll(POLLRDNORM) revents == POLLHUP exactly
 *     (no POLLRDNORM, no POLLERR); recv returns 0.
 *   shutdown(SD_SEND) by peer: the same, revents == POLLHUP exactly; recv
 *     returns 0, our send still succeeds.
 *   abortive close (SO_LINGER 0 -> RST): POLLERR set; recv fails with
 *     WSAECONNRESET (10054); select puts the socket in the read set.
 *   After RST, a second recv also fails WSAECONNRESET? -- recorded.
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

#define TEST_NAME "17_wsapoll_peer_close_modes"

static SHORT poll_ev(SOCKET s, SHORT ev, int *rc)
{
  WSAPOLLFD p;
  memset(&p, 0, sizeof(p)); p.fd = s; p.events = ev;
  *rc = WSAPoll(&p, 1, 2000);
  return p.revents;
}

int main(void)
{
  WSADATA d;
  SOCKET c, s;
  char b[8];
  int rc, n, e;
  SHORT rv;
  struct linger lg = { 1, 0 };

  WSAStartup(MAKEWORD(2, 2), &d);

  /* graceful FIN */
  EXPECT(pair(&c, &s), "pair1");
  closesocket(s);
  rv = poll_ev(c, POLLRDNORM, &rc);
  INFO("FIN: poll rc=%d revents=0x%x", rc, (unsigned)rv);
  EXPECT(rc == 1 && rv == POLLHUP, "FIN revents 0x%x want exactly POLLHUP 0x%x", (unsigned)rv, (unsigned)POLLHUP);
  n = recv(c, b, sizeof(b), 0);
  EXPECT(n == 0, "recv after FIN = %d", n);
  closesocket(c);

  /* half close */
  EXPECT(pair(&c, &s), "pair2");
  shutdown(s, SD_SEND);
  rv = poll_ev(c, POLLRDNORM, &rc);
  INFO("half-close: poll rc=%d revents=0x%x", rc, (unsigned)rv);
  EXPECT(rc == 1 && rv == POLLHUP, "half-close revents 0x%x want exactly POLLHUP 0x%x", (unsigned)rv, (unsigned)POLLHUP);
  n = recv(c, b, sizeof(b), 0);
  EXPECT(n == 0, "recv after half close = %d", n);
  n = send(c, "x", 1, 0);
  EXPECT(n == 1, "send into half-closed connection = %d err=%d", n, WSAGetLastError());
  closesocket(c); closesocket(s);

  /* RST */
  EXPECT(pair(&c, &s), "pair3");
  setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
  closesocket(s);
  rv = poll_ev(c, POLLRDNORM, &rc);
  INFO("RST: poll rc=%d revents=0x%x", rc, (unsigned)rv);
  EXPECT(rc == 1 && (rv & POLLERR), "RST revents 0x%x lacks POLLERR", (unsigned)rv);
  {
    fd_set r;
    struct timeval tv = { 2, 0 };
    FD_ZERO(&r); FD_SET(c, &r);
    rc = select(0, &r, NULL, NULL, &tv);
    EXPECT(rc == 1 && FD_ISSET(c, &r), "select after RST rc=%d", rc);
  }
  n = recv(c, b, sizeof(b), 0);
  e = WSAGetLastError();
  INFO("RST: recv=%d err=%d", n, e);
  EXPECT(n == SOCKET_ERROR && e == WSAECONNRESET, "recv after RST n=%d err=%d want -1, 10054", n, e);
  n = recv(c, b, sizeof(b), 0);
  e = WSAGetLastError();
  INFO("RST second recv=%d err=%d", n, e);
  EXPECT(n == SOCKET_ERROR && e == WSAECONNRESET, "second recv after RST n=%d err=%d", n, e);
  n = send(c, "x", 1, 0);
  e = WSAGetLastError();
  INFO("RST send=%d err=%d", n, e);
  EXPECT(n == SOCKET_ERROR && e == WSAECONNRESET, "send after RST n=%d err=%d want -1, 10054", n, e);
  closesocket(c);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
