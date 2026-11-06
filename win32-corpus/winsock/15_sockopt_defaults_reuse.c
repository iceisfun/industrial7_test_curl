/*
 * Test: 15_sockopt_defaults_reuse
 * Purpose: default socket option values and the address re-use rules curl and
 *          its test servers depend on on Windows (SO_REUSEADDR lets two
 *          sockets share a port; SO_EXCLUSIVEADDRUSE prevents it), plus the
 *          buffer-size and receive-timeout options.
 * APIs: setsockopt, getsockopt (SO_SNDBUF, SO_RCVBUF, SO_RCVTIMEO, SO_LINGER,
 *       SO_REUSEADDR, SO_EXCLUSIVEADDRUSE, SO_PROTOCOL_INFOW, TCP_FASTOPEN,
 *       TCP_MAXSEG), bind, recv, GetTickCount.
 * Success (probed on Win10 22H2, std and adm identical):
 *   - a new TCP socket has SO_SNDBUF = SO_RCVBUF = 65536, SO_RCVTIMEO 0, no
 *     linger, SO_REUSEADDR/SO_EXCLUSIVEADDRUSE/SO_KEEPALIVE/TCP_NODELAY 0;
 *   - SO_PROTOCOL_INFOW is 628 bytes: protocol 6, SOCK_STREAM, AF_INET, name
 *     "MSAFD Tcpip [TCP/IP]"; a 4 byte buffer fails WSAEFAULT;
 *   - TCP_FASTOPEN can be set on an unconnected socket (curl --tcp-fastopen)
 *     and reads back as 1; TCP_MAXSEG is not readable (WSAENOPROTOOPT 10042);
 *   - SO_SNDBUF 8192 reads back 8192, 0 reads back 0, SO_RCVBUF 262144 reads
 *     back 262144 (no doubling, unlike Linux);
 *   - SO_LINGER {1,0} reads back {1,0};
 *   - SO_RCVTIMEO is a DWORD in milliseconds: 1500 reads back 1500 and a recv on
 *     an idle connection fails WSAETIMEDOUT (10060) after 1400..2600 ms;
 *     a 8 byte struct timeval is also accepted by setsockopt;
 *   - two sockets that both set SO_REUSEADDR before bind can bind the same
 *     port; a third without it fails WSAEADDRINUSE (10048);
 *   - a socket with SO_EXCLUSIVEADDRUSE bound to a port: another socket with
 *     SO_REUSEADDR cannot bind it (WSAEACCES 10013); SO_REUSEADDR cannot be set
 *     after SO_EXCLUSIVEADDRUSE (WSAEINVAL 10022).
 * Source: lib/cf-socket.c (SO_SNDBUF handling for uploads, TCP_FASTOPEN),
 *         lib/socketpair.c (SO_REUSEADDR is deliberately not set on Windows).
 */
#define TEST_NAME "sockopt_defaults_reuse"
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
#include <stdlib.h>

static __attribute__((unused)) int g_fail;

#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); g_fail = 1; goto out; } while (0)

/* The call must fail (SOCKET_ERROR / INVALID_SOCKET / -1) with exactly the given WSA error, and
   GetLastError must report the same value (curl reads errno through WSAGetLastError). */
#define EXPECT_ERR(call, code, what) do { \
    int r_ = (int)(call); \
    int e_ = WSAGetLastError(); \
    if (r_ != SOCKET_ERROR || e_ != (code)) \
      FAILF("%s: result %d error %d, expected SOCKET_ERROR / %d", (what), r_, e_, (int)(code)); \
  } while (0)

static __attribute__((unused)) SOCKET tcp_listener(unsigned short *port) {
  struct sockaddr_in sa;
  int len = (int)sizeof(sa);
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return INVALID_SOCKET;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(s, (struct sockaddr *)&sa, (int)sizeof(sa)) == SOCKET_ERROR || listen(s, 8) == SOCKET_ERROR ||
      getsockname(s, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
    closesocket(s);
    return INVALID_SOCKET;
  }
  *port = ntohs(sa.sin_port);
  return s;
}

static __attribute__((unused)) struct sockaddr_in loop_addr(unsigned short port) {
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(port);
  return sa;
}

/* Connected loopback TCP pair: *cli connects, *srv is the accepted side. */
static __attribute__((unused)) int tcp_pair(SOCKET lis, unsigned short port, SOCKET *cli, SOCKET *srv) {
  struct sockaddr_in sa = loop_addr(port);
  *cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (*cli == INVALID_SOCKET) return -1;
  if (connect(*cli, (struct sockaddr *)&sa, (int)sizeof(sa)) == SOCKET_ERROR) return -1;
  *srv = accept(lis, NULL, NULL);
  return *srv == INVALID_SOCKET ? -1 : 0;
}


static int get_int(SOCKET s, int level, int opt, int *v) {
  int len = (int)sizeof(*v);
  *v = -1;
  return getsockopt(s, level, opt, (char *)v, &len);
}

static int body(void) {
  SOCKET lis = INVALID_SOCKET, c = INVALID_SOCKET, s = INVALID_SOCKET, a = INVALID_SOCKET, b1 = INVALID_SOCKET,
         b2 = INVALID_SOCKET, b3 = INVALID_SOCKET, b4 = INVALID_SOCKET, b5 = INVALID_SOCKET;
  unsigned short port = 0;
  int v, len, one = 1;
  struct linger lg;
  WSAPROTOCOL_INFOW pi;
  struct sockaddr_in z;
  DWORD t0, el, tmo;
  char buf[4];

  a = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (a == INVALID_SOCKET) FAILF("socket");
  if (get_int(a, SOL_SOCKET, SO_SNDBUF, &v) != 0 || v != 65536) FAILF("default SO_SNDBUF %d, expected 65536", v);
  if (get_int(a, SOL_SOCKET, SO_RCVBUF, &v) != 0 || v != 65536) FAILF("default SO_RCVBUF %d, expected 65536", v);
  if (get_int(a, SOL_SOCKET, SO_RCVTIMEO, &v) != 0 || v != 0) FAILF("default SO_RCVTIMEO %d, expected 0", v);
  len = (int)sizeof(lg);
  memset(&lg, 0x55, sizeof(lg));
  if (getsockopt(a, SOL_SOCKET, SO_LINGER, (char *)&lg, &len) != 0 || lg.l_onoff != 0 || lg.l_linger != 0)
    FAILF("default SO_LINGER {%d,%d}, expected {0,0}", lg.l_onoff, lg.l_linger);
  if (get_int(a, SOL_SOCKET, SO_REUSEADDR, &v) != 0 || v != 0) FAILF("default SO_REUSEADDR %d", v);
  if (get_int(a, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &v) != 0 || v != 0) FAILF("default SO_EXCLUSIVEADDRUSE %d", v);
  if (get_int(a, SOL_SOCKET, SO_KEEPALIVE, &v) != 0 || (v & 0xff) != 0) FAILF("default SO_KEEPALIVE %d", v);
  if (get_int(a, IPPROTO_TCP, TCP_NODELAY, &v) != 0 || (v & 0xff) != 0) FAILF("default TCP_NODELAY %d", v);

  len = (int)sizeof(v);
  EXPECT_ERR(getsockopt(a, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&v, &len), WSAEFAULT, "SO_PROTOCOL_INFOW with a 4 byte buffer");
  len = (int)sizeof(pi);
  memset(&pi, 0, sizeof(pi));
  if (getsockopt(a, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &len) != 0) FAILF("SO_PROTOCOL_INFOW error %d", WSAGetLastError());
  if (len != 628 || pi.iProtocol != IPPROTO_TCP || pi.iSocketType != SOCK_STREAM || pi.iAddressFamily != AF_INET ||
      wcscmp(pi.szProtocol, L"MSAFD Tcpip [TCP/IP]") != 0)
    FAILF("SO_PROTOCOL_INFOW len=%d proto=%d type=%d af=%d name=%ls", len, pi.iProtocol, pi.iSocketType, pi.iAddressFamily, pi.szProtocol);

  if (setsockopt(a, IPPROTO_TCP, TCP_FASTOPEN, (const char *)&one, (int)sizeof(one)) != 0) FAILF("set TCP_FASTOPEN error %d", WSAGetLastError());
  if (get_int(a, IPPROTO_TCP, TCP_FASTOPEN, &v) != 0 || (v & 0xff) != 1) FAILF("TCP_FASTOPEN reads back %d", v);
  len = (int)sizeof(v);
  EXPECT_ERR(getsockopt(a, IPPROTO_TCP, TCP_MAXSEG, (char *)&v, &len), WSAENOPROTOOPT, "TCP_MAXSEG");

  v = 8192;
  if (setsockopt(a, SOL_SOCKET, SO_SNDBUF, (const char *)&v, (int)sizeof(v)) != 0 || get_int(a, SOL_SOCKET, SO_SNDBUF, &v) != 0 || v != 8192)
    FAILF("SO_SNDBUF 8192 reads back %d", v);
  v = 0;
  if (setsockopt(a, SOL_SOCKET, SO_SNDBUF, (const char *)&v, (int)sizeof(v)) != 0 || get_int(a, SOL_SOCKET, SO_SNDBUF, &v) != 0 || v != 0)
    FAILF("SO_SNDBUF 0 reads back %d", v);
  v = 262144;
  if (setsockopt(a, SOL_SOCKET, SO_RCVBUF, (const char *)&v, (int)sizeof(v)) != 0 || get_int(a, SOL_SOCKET, SO_RCVBUF, &v) != 0 || v != 262144)
    FAILF("SO_RCVBUF 262144 reads back %d", v);
  lg.l_onoff = 1;
  lg.l_linger = 0;
  if (setsockopt(a, SOL_SOCKET, SO_LINGER, (const char *)&lg, (int)sizeof(lg)) != 0) FAILF("set SO_LINGER");
  memset(&lg, 0x55, sizeof(lg));
  len = (int)sizeof(lg);
  if (getsockopt(a, SOL_SOCKET, SO_LINGER, (char *)&lg, &len) != 0 || lg.l_onoff != 1 || lg.l_linger != 0) FAILF("SO_LINGER reads back {%d,%d}", lg.l_onoff, lg.l_linger);
  closesocket(a);
  a = INVALID_SOCKET;

  /* SO_RCVTIMEO */
  lis = tcp_listener(&port);
  if (lis == INVALID_SOCKET || tcp_pair(lis, port, &c, &s) != 0) FAILF("pair");
  tmo = 1500;
  if (setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, (int)sizeof(tmo)) != 0) FAILF("set SO_RCVTIMEO");
  if (get_int(c, SOL_SOCKET, SO_RCVTIMEO, &v) != 0 || v != 1500) FAILF("SO_RCVTIMEO reads back %d, expected 1500", v);
  t0 = GetTickCount();
  EXPECT_ERR(recv(c, buf, sizeof(buf), 0), WSAETIMEDOUT, "recv with SO_RCVTIMEO 1500");
  el = GetTickCount() - t0;
  if (el < 1400 || el > 2600) FAILF("recv timed out after %lu ms, expected 1400..2600", (unsigned long)el);
  {
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 500000;
    if (setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, (int)sizeof(tv)) != 0) FAILF("set SO_RCVTIMEO with struct timeval error %d", WSAGetLastError());
  }

  /* address re-use */
  b1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  b2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  b3 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  b4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  b5 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  setsockopt(b1, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, (int)sizeof(one));
  setsockopt(b2, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, (int)sizeof(one));
  z = loop_addr(0);
  if (bind(b1, (struct sockaddr *)&z, (int)sizeof(z)) != 0) FAILF("bind b1");
  len = (int)sizeof(z);
  getsockname(b1, (struct sockaddr *)&z, &len);
  if (bind(b2, (struct sockaddr *)&z, (int)sizeof(z)) != 0) FAILF("second bind with SO_REUSEADDR on both failed, error %d", WSAGetLastError());
  EXPECT_ERR(bind(b3, (struct sockaddr *)&z, (int)sizeof(z)), WSAEADDRINUSE, "bind without SO_REUSEADDR to a shared port");
  setsockopt(b4, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, (int)sizeof(one));
  z = loop_addr(0);
  if (bind(b4, (struct sockaddr *)&z, (int)sizeof(z)) != 0) FAILF("bind b4 exclusive");
  len = (int)sizeof(z);
  getsockname(b4, (struct sockaddr *)&z, &len);
  setsockopt(b5, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, (int)sizeof(one));
  EXPECT_ERR(bind(b5, (struct sockaddr *)&z, (int)sizeof(z)), WSAEACCES, "SO_REUSEADDR bind over an exclusive port");
  a = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  setsockopt(a, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, (int)sizeof(one));
  EXPECT_ERR(setsockopt(a, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, (int)sizeof(one)), WSAEINVAL, "SO_REUSEADDR after SO_EXCLUSIVEADDRUSE");

  printf("PASS %s\n", TEST_NAME);
  g_fail = 0;
  v = 0;
  goto cleanup;
out:
  v = 1;
cleanup:
  {
    SOCKET all[9];
    int i;
    all[0] = lis; all[1] = c; all[2] = s; all[3] = a; all[4] = b1; all[5] = b2; all[6] = b3; all[7] = b4; all[8] = b5;
    for (i = 0; i < 9; i++)
      if (all[i] != INVALID_SOCKET) closesocket(all[i]);
  }
  return v;
}

int main(void) {
  WSADATA wsa;
  int rc;

  memset(&wsa, 0, sizeof(wsa));
  rc = WSAStartup(MAKEWORD(2, 2), &wsa);
  if (rc != 0) {
    printf("FAIL %s: WSAStartup returned %d\n", TEST_NAME, rc);
    return 1;
  }
  rc = body();
  WSACleanup();
  fflush(stdout);
  return rc;
}

