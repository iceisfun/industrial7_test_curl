/*
 * Test: 16_socket_options_ioctls
 *
 * Purpose: the socket option and ioctl calls curl makes on every connection
 *   (curlx_nonblock, TCP_NODELAY, SO_KEEPALIVE + SIO_KEEPALIVE_VALS or the
 *   TCP_KEEP* options, FIONREAD, MSG_PEEK) with the return values and error
 *   codes probed on Win10 22H2 (build 19045), std and adm identical.
 *
 * Success (loopback TCP pair):
 *   - nonblocking recv on an empty socket: SOCKET_ERROR / WSAEWOULDBLOCK
 *     (10035); nonblocking accept on an idle listener: INVALID_SOCKET / 10035.
 *   - ioctlsocket(FIONBIO, 0) on a socket with an active WSAEventSelect
 *     association fails with WSAEINVAL (10022); after WSAEventSelect(s, NULL, 0)
 *     it succeeds.
 *   - FIONREAD returns 0 and the exact queued byte count (5); MSG_PEEK does
 *     not consume (FIONREAD still 5).
 *   - TCP_NODELAY and SO_KEEPALIVE set to 1 read back as 1 (getsockopt
 *     returns optlen 1 for TCP_NODELAY and SO_KEEPALIVE, a Windows quirk).
 *   - WSAIoctl(SIO_KEEPALIVE_VALS 1/30000/5000) and the off form succeed.
 *   - TCP_KEEPIDLE=7, TCP_KEEPCNT=4, TCP_KEEPINTVL=3 are accepted on Win10
 *     22H2 and read back as set (optlen 4); TCP_KEEPCNT 0 is accepted;
 *     TCP_KEEPIDLE 0 fails with WSAEINVAL (10022).
 *   - SO_SNDBUF default is 65536; SO_TYPE of a TCP socket is SOCK_STREAM;
 *     SO_CONNECT_TIME is 0 (or more, below 60) on a connected socket and
 *     0xFFFFFFFF on an unconnected one.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <mstcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "socket_options_ioctls"
#define CHECK(cond, ...) do { if(!(cond)) { snprintf(msg, msz, __VA_ARGS__); rc = 1; goto done; } } while(0)

static int body(char *msg, size_t msz)
{
  WSADATA wd;
  struct sockaddr_in sa;
  int len = sizeof(sa);
  SOCKET l = INVALID_SOCKET, c = INVALID_SOCKET, a = INVALID_SOCKET, u = INVALID_SOCKET, na;
  WSAEVENT ev = WSA_INVALID_EVENT;
  u_long z = 0, one = 1, av;
  char b[8];
  int rc = 0, e, n, g, gl, v;
  DWORD ret = 0;
  struct tcp_keepalive ka;

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) { snprintf(msg, msz, "WSAStartup failed: %d", e); return 1; }

  l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(bind(l, (struct sockaddr *)&sa, sizeof(sa)) == 0 && listen(l, 4) == 0 &&
        getsockname(l, (struct sockaddr *)&sa, &len) == 0, "listener setup failed %d", WSAGetLastError());
  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  CHECK(connect(c, (struct sockaddr *)&sa, sizeof(sa)) == 0, "connect failed %d", WSAGetLastError());
  a = accept(l, NULL, NULL);
  CHECK(a != INVALID_SOCKET, "accept failed %d", WSAGetLastError());

  /* nonblocking behaviour */
  CHECK(ioctlsocket(a, FIONBIO, &one) == 0, "FIONBIO 1 failed");
  n = recv(a, b, sizeof(b), 0);
  CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK, "nb recv: n=%d err=%d", n, WSAGetLastError());
  CHECK(ioctlsocket(l, FIONBIO, &one) == 0, "FIONBIO listener failed");
  na = accept(l, NULL, NULL);
  CHECK(na == INVALID_SOCKET && WSAGetLastError() == WSAEWOULDBLOCK, "nb accept: err=%d", WSAGetLastError());

  /* FIONBIO vs WSAEventSelect */
  ev = WSACreateEvent();
  CHECK(WSAEventSelect(a, ev, FD_READ) == 0, "WSAEventSelect failed");
  WSASetLastError(0);
  n = ioctlsocket(a, FIONBIO, &z);
  CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "FIONBIO 0 with event select: n=%d err=%d", n, WSAGetLastError());
  CHECK(WSAEventSelect(a, NULL, 0) == 0, "cancel WSAEventSelect failed");
  CHECK(ioctlsocket(a, FIONBIO, &z) == 0, "FIONBIO 0 after cancel failed %d", WSAGetLastError());

  /* FIONREAD / MSG_PEEK */
  CHECK(send(c, "hello", 5, 0) == 5, "send failed");
  av = 99;
  n = 0;
  while(n < 100) {   /* loopback delivery is asynchronous */
    ioctlsocket(a, FIONREAD, &av);
    if(av == 5) break;
    Sleep(10); n++;
  }
  CHECK(av == 5, "FIONREAD=%lu, expected 5", (unsigned long)av);
  CHECK(recv(a, b, 3, MSG_PEEK) == 3 && memcmp(b, "hel", 3) == 0, "MSG_PEEK failed");
  av = 99;
  ioctlsocket(a, FIONREAD, &av);
  CHECK(av == 5, "FIONREAD after peek=%lu, expected 5", (unsigned long)av);

  /* option set/get */
  v = 1;
  CHECK(setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&v, sizeof(v)) == 0, "TCP_NODELAY set failed");
  g = 0; gl = sizeof(g);
  CHECK(getsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&g, &gl) == 0 && g != 0 && gl == 1,
        "TCP_NODELAY get: g=%d len=%d, expected nonzero/1", g, gl);
  CHECK(setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, (char *)&v, sizeof(v)) == 0, "SO_KEEPALIVE set failed");
  g = 0; gl = sizeof(g);
  CHECK(getsockopt(c, SOL_SOCKET, SO_KEEPALIVE, (char *)&g, &gl) == 0 && g != 0 && gl == 1,
        "SO_KEEPALIVE get: g=%d len=%d, expected nonzero/1", g, gl);

  ka.onoff = 1; ka.keepalivetime = 30000; ka.keepaliveinterval = 5000;
  CHECK(WSAIoctl(c, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &ret, NULL, NULL) == 0,
        "SIO_KEEPALIVE_VALS on failed %d", WSAGetLastError());
  ka.onoff = 0; ka.keepalivetime = 0; ka.keepaliveinterval = 0;
  CHECK(WSAIoctl(c, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &ret, NULL, NULL) == 0,
        "SIO_KEEPALIVE_VALS off failed %d", WSAGetLastError());

  {
    static const struct { int opt; int val; } kv[3] = { { TCP_KEEPIDLE, 7 }, { TCP_KEEPCNT, 4 }, { TCP_KEEPINTVL, 3 } };
    int i;
    for(i = 0; i < 3; i++) {
      CHECK(setsockopt(c, IPPROTO_TCP, kv[i].opt, (char *)&kv[i].val, sizeof(int)) == 0,
            "TCP_KEEP option %d set failed %d", kv[i].opt, WSAGetLastError());
      g = 0; gl = sizeof(g);
      CHECK(getsockopt(c, IPPROTO_TCP, kv[i].opt, (char *)&g, &gl) == 0 && g == kv[i].val && gl == 4,
            "TCP_KEEP option %d get: g=%d len=%d, expected %d/4", kv[i].opt, g, gl, kv[i].val);
    }
  }
  v = 0;
  CHECK(setsockopt(c, IPPROTO_TCP, TCP_KEEPCNT, (char *)&v, sizeof(v)) == 0, "TCP_KEEPCNT 0 failed %d", WSAGetLastError());
  WSASetLastError(0);
  n = setsockopt(c, IPPROTO_TCP, TCP_KEEPIDLE, (char *)&v, sizeof(v));
  CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "TCP_KEEPIDLE 0: n=%d err=%d", n, WSAGetLastError());

  g = 0; gl = sizeof(g);
  CHECK(getsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *)&g, &gl) == 0 && g == 65536, "SO_SNDBUF=%d, expected 65536", g);
  g = 0; gl = sizeof(g);
  CHECK(getsockopt(c, SOL_SOCKET, SO_TYPE, (char *)&g, &gl) == 0 && g == SOCK_STREAM, "SO_TYPE=%d", g);
  g = -2; gl = sizeof(g);
  CHECK(getsockopt(c, SOL_SOCKET, SO_CONNECT_TIME, (char *)&g, &gl) == 0 && g >= 0 && g < 60, "SO_CONNECT_TIME connected=%d", g);
  u = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  g = 0; gl = sizeof(g);
  CHECK(getsockopt(u, SOL_SOCKET, SO_CONNECT_TIME, (char *)&g, &gl) == 0 && (unsigned)g == 0xFFFFFFFFu,
        "SO_CONNECT_TIME unconnected=%d, expected -1", g);

done:
  if(ev != WSA_INVALID_EVENT) WSACloseEvent(ev);
  if(u != INVALID_SOCKET) closesocket(u);
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
