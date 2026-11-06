/*
 * Test: 14_wsapoll_semantics
 *
 * Purpose: WSAPoll behaviour that curl's Curl_poll / multi wait relies on
 *   (curl pre-checks with WSAPoll(timeout 0) before blocking). Every value
 *   was probed on Win10 22H2 (build 19045), std and adm identical.
 *
 * Success (loopback TCP):
 *   - listener with a pending connection: POLLIN request -> revents ==
 *     POLLRDNORM (0x100), one ready.
 *   - connected socket with an empty receive buffer: POLLIN -> 0 ready, revents 0;
 *     after the peer sends 2 bytes: POLLIN -> revents == POLLRDNORM (0x100).
 *   - POLLOUT on a connected socket: revents == POLLWRNORM (0x10).
 *   - peer shutdown(SD_SEND) (FIN): POLLIN, POLLRDNORM and events=0 requests
 *     all report revents == POLLHUP (0x2) with no POLLIN bit; recv then
 *     returns 0. A POLLOUT request reports POLLHUP|POLLWRNORM (0x12).
 *   - a socket reset by the peer (SO_LINGER 0, repeated 20 times, identical
 *     every time): POLLIN|POLLOUT -> 0x13 (POLLERR|POLLHUP|POLLWRNORM); a
 *     graceful FIN has no POLLERR.
 *   - a full send buffer: POLLOUT -> 0 ready.
 *   - WSAPoll with zero entries and NULL: SOCKET_ERROR, WSAEINVAL (10022).
 *   - POLLPRI requested: SOCKET_ERROR, WSAEINVAL (10022).
 *   - a single closed or INVALID_SOCKET entry: SOCKET_ERROR, WSAENOTSOCK (10038),
 *     revents == POLLNVAL (0x4).
 *   - the same invalid entry next to a valid idle socket: returns 0, the
 *     invalid entry has revents POLLNVAL (0x4) and the valid one 0.
 *   - timeout 300 ms on an idle socket: returns 0 after 280..700 ms.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "wsapoll_semantics"
#define CHECK(cond, ...) do { if(!(cond)) { snprintf(msg, msz, __VA_ARGS__); rc = 1; goto done; } } while(0)

static int make_listener(SOCKET *l, struct sockaddr_in *sa)
{
  int len = sizeof(*sa);
  *l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(*l == INVALID_SOCKET)
    return WSAGetLastError();
  memset(sa, 0, sizeof(*sa));
  sa->sin_family = AF_INET;
  sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(bind(*l, (struct sockaddr *)sa, sizeof(*sa)) || listen(*l, 4) ||
     getsockname(*l, (struct sockaddr *)sa, &len))
    return WSAGetLastError();
  return 0;
}

static int make_pair(SOCKET l, struct sockaddr_in *sa, SOCKET *c, SOCKET *a)
{
  *c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(*c == INVALID_SOCKET || connect(*c, (struct sockaddr *)sa, sizeof(*sa)))
    return WSAGetLastError();
  *a = accept(l, NULL, NULL);
  return *a == INVALID_SOCKET ? WSAGetLastError() : 0;
}

static int body(char *msg, size_t msz)
{
  WSADATA wd;
  SOCKET l = INVALID_SOCKET, c = INVALID_SOCKET, a = INVALID_SOCKET;
  SOCKET c2 = INVALID_SOCKET, a2 = INVALID_SOCKET, c3 = INVALID_SOCKET, a3 = INVALID_SOCKET;
  SOCKET closed = INVALID_SOCKET, pend = INVALID_SOCKET;
  struct sockaddr_in sa;
  WSAPOLLFD pf, pa[2];
  struct linger lg;
  u_long one = 1;
  static char blk[65536];
  char b[8];
  int rc = 0, e, n, tot;
  ULONGLONG t0;

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) { snprintf(msg, msz, "WSAStartup failed: %d", e); return 1; }
  e = make_listener(&l, &sa);
  CHECK(e == 0, "listener setup failed: %d", e);

  /* pending accept on the listener */
  pend = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  CHECK(connect(pend, (struct sockaddr *)&sa, sizeof(sa)) == 0, "connect failed %d", WSAGetLastError());
  pf.fd = l; pf.events = POLLIN; pf.revents = 0;
  n = WSAPoll(&pf, 1, 2000);
  CHECK(n == 1 && pf.revents == POLLRDNORM, "listener: n=%d revents=0x%x, expected 1/0x100", n, pf.revents);
  a2 = accept(l, NULL, NULL);
  CHECK(a2 != INVALID_SOCKET, "accept failed");

  e = make_pair(l, &sa, &c, &a);
  CHECK(e == 0, "pair failed: %d", e);

  pf.fd = a; pf.events = POLLIN; pf.revents = 0;
  n = WSAPoll(&pf, 1, 0);
  CHECK(n == 0 && pf.revents == 0, "idle POLLIN: n=%d revents=0x%x", n, pf.revents);
  CHECK(send(c, "hi", 2, 0) == 2, "send failed");
  pf.revents = 0;
  n = WSAPoll(&pf, 1, 2000);
  CHECK(n == 1 && pf.revents == POLLRDNORM, "data POLLIN: n=%d revents=0x%x, expected 1/0x100", n, pf.revents);
  CHECK(recv(a, b, sizeof(b), 0) == 2, "recv failed");

  pf.events = POLLOUT; pf.revents = 0;
  n = WSAPoll(&pf, 1, 0);
  CHECK(n == 1 && pf.revents == POLLWRNORM, "POLLOUT: n=%d revents=0x%x, expected 1/0x10", n, pf.revents);

  /* full send buffer */
  e = make_pair(l, &sa, &c3, &a3);
  CHECK(e == 0, "pair 3 failed: %d", e);
  ioctlsocket(c3, FIONBIO, &one);
  tot = 0;
  for(;;) {
    int s = send(c3, blk, sizeof(blk), 0);
    if(s < 0) { CHECK(WSAGetLastError() == WSAEWOULDBLOCK, "fill: error %d", WSAGetLastError()); break; }
    tot += s;
    CHECK(tot < (1 << 28), "send buffer never filled");
  }
  pf.fd = c3; pf.events = POLLOUT; pf.revents = 0;
  n = WSAPoll(&pf, 1, 200);
  CHECK(n == 0 && pf.revents == 0, "full buffer POLLOUT: n=%d revents=0x%x", n, pf.revents);

  /* FIN from the peer */
  CHECK(shutdown(c, SD_SEND) == 0, "shutdown failed");
  Sleep(50);
  {
    static const short evs[4] = { POLLIN, POLLRDNORM, 0, POLLOUT };
    static const short want[4] = { POLLHUP, POLLHUP, POLLHUP, POLLHUP | POLLWRNORM };
    int i;
    for(i = 0; i < 4; i++) {
      pf.fd = a; pf.events = evs[i]; pf.revents = 0;
      n = WSAPoll(&pf, 1, 1000);
      CHECK(n == 1 && pf.revents == want[i], "FIN events=0x%x: n=%d revents=0x%x, expected 0x%x",
            evs[i], n, pf.revents, want[i]);
    }
  }
  CHECK(recv(a, b, sizeof(b), 0) == 0, "recv after FIN != 0");

  /* RST from the peer */
  {
    int i;
    for(i = 0; i < 20; i++) {
      if(a2 != INVALID_SOCKET) { closesocket(a2); a2 = INVALID_SOCKET; }
      e = make_pair(l, &sa, &c2, &a2);
      CHECK(e == 0, "pair 2 failed: %d", e);
      lg.l_onoff = 1; lg.l_linger = 0;
      setsockopt(c2, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
      closesocket(c2); c2 = INVALID_SOCKET;
      Sleep(100);
      pf.fd = a2; pf.events = POLLIN | POLLOUT; pf.revents = 0;
      n = WSAPoll(&pf, 1, 2000);
      CHECK(n == 1 && pf.revents == (POLLERR | POLLHUP | POLLWRNORM),
            "RST round %d: n=%d revents=0x%x, expected 1/0x13", i, n, pf.revents);
    }
  }

  /* argument errors */
  WSASetLastError(0);
  n = WSAPoll(NULL, 0, 0);
  CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "zero entries: n=%d err=%d", n, WSAGetLastError());
  pf.fd = l; pf.events = POLLPRI; pf.revents = 0;
  WSASetLastError(0);
  n = WSAPoll(&pf, 1, 0);
  CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "POLLPRI: n=%d err=%d", n, WSAGetLastError());

  closed = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  closesocket(closed);
  pf.fd = closed; pf.events = POLLIN; pf.revents = 0;
  WSASetLastError(0);
  n = WSAPoll(&pf, 1, 0);
  CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK && pf.revents == POLLNVAL,
        "closed socket alone: n=%d err=%d revents=0x%x", n, WSAGetLastError(), pf.revents);
  pf.fd = INVALID_SOCKET; pf.events = POLLIN; pf.revents = 0;
  WSASetLastError(0);
  n = WSAPoll(&pf, 1, 0);
  CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK && pf.revents == POLLNVAL,
        "INVALID_SOCKET alone: n=%d err=%d revents=0x%x", n, WSAGetLastError(), pf.revents);
  pa[0].fd = INVALID_SOCKET; pa[0].events = POLLIN; pa[0].revents = 0x55;
  pa[1].fd = l; pa[1].events = POLLIN; pa[1].revents = 0x55;
  n = WSAPoll(pa, 2, 0);
  CHECK(n == 0 && pa[0].revents == POLLNVAL && pa[1].revents == 0,
        "invalid+idle: n=%d revents=0x%x/0x%x, expected 0/0x4/0", n, pa[0].revents, pa[1].revents);

  /* timeout accuracy */
  pf.fd = l; pf.events = POLLIN; pf.revents = 0;
  t0 = GetTickCount64();
  n = WSAPoll(&pf, 1, 300);
  t0 = GetTickCount64() - t0;
  CHECK(n == 0 && t0 >= 280 && t0 < 700, "timeout: n=%d after %llu ms", n, (unsigned long long)t0);

done:
  if(pend != INVALID_SOCKET) closesocket(pend);
  if(a2 != INVALID_SOCKET) closesocket(a2);
  if(c2 != INVALID_SOCKET) closesocket(c2);
  if(c3 != INVALID_SOCKET) closesocket(c3);
  if(a3 != INVALID_SOCKET) closesocket(a3);
  if(a != INVALID_SOCKET) closesocket(a);
  if(c != INVALID_SOCKET) closesocket(c);
  if(l != INVALID_SOCKET) closesocket(l);
  WSACleanup();
  return rc;
}

int main(void)
{
  char msg[512];
  int rc;

  msg[0] = '\0';
  rc = body(msg, sizeof(msg));
  if(rc == 0)
    printf("PASS %s\n", TEST_NAME);
  else
    printf("FAIL %s: %s\n", TEST_NAME, msg);
  return rc;
}
