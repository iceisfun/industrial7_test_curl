/*
 * Test: 14_socket_state_error_codes
 * Purpose: the error codes curl's socket layer branches on (lib/cf-socket.c,
 *          lib/connect.c, lib/select.c use SOCKERRNO = WSAGetLastError()) when a
 *          socket is used in the wrong state or after the peer went away.
 * APIs: socket, bind, listen, accept, connect, send, recv, shutdown,
 *       closesocket, getsockname, getpeername, getsockopt(SO_ERROR),
 *       ioctlsocket, setsockopt, select, WSAGetLastError, GetLastError.
 * Success (probed on Win10 22H2, std and adm identical):
 *   - getpeername/send/recv on an unconnected TCP socket: WSAENOTCONN (10057);
 *   - getsockname on an unbound socket, accept and listen on a socket that is
 *     not bound/listening: WSAEINVAL (10022); listen on a connected socket:
 *     WSAEISCONN (10056); connect on a connected socket: WSAEISCONN (10056);
 *   - after shutdown(SD_SEND): send fails WSAESHUTDOWN (10058), the peer sees
 *     recv == 0, data from the peer is still received, a repeated shutdown
 *     succeeds, shutdown(7) is WSAEINVAL; after shutdown(SD_RECEIVE): recv
 *     fails WSAESHUTDOWN;
 *   - a peer that closes with SO_LINGER {1,0} (RST): recv fails WSAECONNRESET
 *     (10054) and keeps failing with it, send fails 10054, SO_ERROR reads 0;
 *   - a peer that closes normally (FIN): recv returns 0, the first send
 *     succeeds, and once the peer's RST arrives send fails WSAECONNABORTED
 *     (10053) (20 repetitions);
 *   - closed / bogus handles: send, recv, ioctlsocket, setsockopt, select,
 *     closesocket (also a second close) fail WSAENOTSOCK (10038);
 *   - send of 0 bytes returns 0, send with length -1 is WSAEFAULT (10014),
 *     getsockname with a short buffer or NULL is WSAEFAULT;
 *   - GetLastError() equals WSAGetLastError() and the two are one variable.
 * Source: lib/cf-socket.c (SOCKERRNO uses, EINPROGRESS/EWOULDBLOCK handling),
 *         lib/connect.c (connect error classification).
 */
#define TEST_NAME "socket_state_error_codes"
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


static int body(void) {
  SOCKET lis = INVALID_SOCKET, c = INVALID_SOCKET, s = INVALID_SOCKET, u = INVALID_SOCKET;
  unsigned short port = 0;
  struct sockaddr_in sa, name;
  char buf[16];
  int i, len, v;
  u_long nb;
  fd_set rf;
  struct timeval tv;

  lis = tcp_listener(&port);
  if (lis == INVALID_SOCKET) FAILF("listener setup");

  /* unconnected / unbound / not listening */
  u = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  len = (int)sizeof(name);
  EXPECT_ERR(getpeername(u, (struct sockaddr *)&name, &len), WSAENOTCONN, "getpeername unconnected");
  EXPECT_ERR(send(u, "x", 1, 0), WSAENOTCONN, "send unconnected");
  EXPECT_ERR(recv(u, buf, sizeof(buf), 0), WSAENOTCONN, "recv unconnected");
  len = (int)sizeof(name);
  EXPECT_ERR(getsockname(u, (struct sockaddr *)&name, &len), WSAEINVAL, "getsockname unbound");
  EXPECT_ERR((accept(u, NULL, NULL) == INVALID_SOCKET) ? SOCKET_ERROR : 0, WSAEINVAL, "accept on a non-listening socket");
  EXPECT_ERR(listen(u, 5), WSAEINVAL, "listen unbound");
  if (GetLastError() != (DWORD)WSAGetLastError()) FAILF("GetLastError %lu != WSAGetLastError %d", (unsigned long)GetLastError(), WSAGetLastError());
  SetLastError(5);
  if (WSAGetLastError() != 5) FAILF("WSAGetLastError does not follow SetLastError");
  WSASetLastError(10000);
  if (GetLastError() != 10000) FAILF("GetLastError does not follow WSASetLastError");
  closesocket(u);
  u = INVALID_SOCKET;

  /* connected socket misuse */
  if (tcp_pair(lis, port, &c, &s) != 0) FAILF("connect/accept pair");
  sa = loop_addr(port);
  EXPECT_ERR(connect(c, (struct sockaddr *)&sa, (int)sizeof(sa)), WSAEISCONN, "connect on connected socket");
  EXPECT_ERR(listen(c, 5), WSAEISCONN, "listen on connected socket");
  if (send(c, NULL, 0, 0) != 0) FAILF("send of 0 bytes did not return 0");
  EXPECT_ERR(send(c, buf, -1, 0), WSAEFAULT, "send length -1");
  len = 2;
  EXPECT_ERR(getsockname(c, (struct sockaddr *)&name, &len), WSAEFAULT, "getsockname short buffer");
  len = (int)sizeof(name);
  EXPECT_ERR(getsockname(c, NULL, &len), WSAEFAULT, "getsockname NULL");

  /* shutdown semantics */
  if (shutdown(c, SD_SEND) != 0) FAILF("shutdown(SD_SEND) error %d", WSAGetLastError());
  EXPECT_ERR(send(c, "x", 1, 0), WSAESHUTDOWN, "send after SD_SEND");
  if (recv(s, buf, sizeof(buf), 0) != 0) FAILF("peer did not see EOF after SD_SEND");
  if (send(s, "hi", 2, 0) != 2 || recv(c, buf, sizeof(buf), 0) != 2) FAILF("data from peer after our SD_SEND");
  if (shutdown(c, SD_SEND) != 0) FAILF("repeated shutdown(SD_SEND) error %d", WSAGetLastError());
  EXPECT_ERR(shutdown(c, 7), WSAEINVAL, "shutdown(7)");
  if (shutdown(c, SD_RECEIVE) != 0) FAILF("shutdown(SD_RECEIVE) error %d", WSAGetLastError());
  EXPECT_ERR(recv(c, buf, sizeof(buf), 0), WSAESHUTDOWN, "recv after SD_RECEIVE");
  closesocket(c);
  closesocket(s);
  c = s = INVALID_SOCKET;

  /* RST: peer closes with SO_LINGER {1,0} */
  {
    struct linger lg;
    lg.l_onoff = 1;
    lg.l_linger = 0;
    if (tcp_pair(lis, port, &c, &s) != 0) FAILF("pair for RST");
    setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, (int)sizeof(lg));
    closesocket(s);
    s = INVALID_SOCKET;
    Sleep(100);
    EXPECT_ERR(recv(c, buf, sizeof(buf), 0), WSAECONNRESET, "recv after RST");
    EXPECT_ERR(recv(c, buf, sizeof(buf), 0), WSAECONNRESET, "second recv after RST (sticky)");
    EXPECT_ERR(send(c, "x", 1, 0), WSAECONNRESET, "send after RST");
    v = -1;
    len = (int)sizeof(v);
    if (getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&v, &len) != 0 || v != 0) FAILF("SO_ERROR after RST is %d, expected 0", v);
    closesocket(c);
    c = INVALID_SOCKET;
  }

  /* FIN then write: first send succeeds, later ones are WSAECONNABORTED */
  for (i = 0; i < 20; i++) {
    if (tcp_pair(lis, port, &c, &s) != 0) FAILF("pair for FIN");
    closesocket(s);
    s = INVALID_SOCKET;
    Sleep(50);
    if (recv(c, buf, sizeof(buf), 0) != 0) FAILF("iteration %d: recv after FIN is not 0", i);
    if (send(c, "x", 1, 0) != 1) FAILF("iteration %d: first send after FIN did not succeed (error %d)", i, WSAGetLastError());
    Sleep(50);
    EXPECT_ERR(send(c, "x", 1, 0), WSAECONNABORTED, "send after the RST that follows a write to a closed peer");
    EXPECT_ERR(send(c, "x", 1, 0), WSAECONNABORTED, "second send (sticky)");
    closesocket(c);
    c = INVALID_SOCKET;
  }

  /* closed and bogus handles */
  u = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  closesocket(u);
  EXPECT_ERR(send(u, "x", 1, 0), WSAENOTSOCK, "send on closed socket");
  EXPECT_ERR(recv(u, buf, sizeof(buf), 0), WSAENOTSOCK, "recv on closed socket");
  nb = 1;
  EXPECT_ERR(ioctlsocket(u, FIONBIO, &nb), WSAENOTSOCK, "ioctlsocket on closed socket");
  v = 1;
  EXPECT_ERR(setsockopt(u, SOL_SOCKET, SO_KEEPALIVE, (const char *)&v, (int)sizeof(v)), WSAENOTSOCK, "setsockopt on closed socket");
  FD_ZERO(&rf);
  FD_SET(u, &rf);
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  EXPECT_ERR(select(0, &rf, NULL, NULL, &tv), WSAENOTSOCK, "select with a closed socket");
  EXPECT_ERR(closesocket(u), WSAENOTSOCK, "second closesocket");
  EXPECT_ERR(closesocket((SOCKET)0x12345), WSAENOTSOCK, "closesocket(garbage)");
  u = INVALID_SOCKET;

  printf("PASS %s\n", TEST_NAME);
  g_fail = 0;
  return 0;
out:
  if (c != INVALID_SOCKET) closesocket(c);
  if (s != INVALID_SOCKET) closesocket(s);
  if (u != INVALID_SOCKET) closesocket(u);
  if (lis != INVALID_SOCKET) closesocket(lis);
  return 1;
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

