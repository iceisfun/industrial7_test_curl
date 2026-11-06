/*
 * Test: 16_udp_datagram_semantics
 * Purpose: UDP datagram behaviour that curl's DNS-over-UDP users (c-ares, the
 *          TFTP protocol in lib/tftp.c, QUIC in ngtcp2/quiche builds) rely on:
 *          message boundaries, truncation errors, FIONREAD, connected UDP.
 * APIs: socket(SOCK_DGRAM), bind, sendto, recvfrom, send, recv, connect,
 *       getpeername, getsockopt(SO_MAX_MSG_SIZE), ioctlsocket(FIONREAD,
 *       FIONBIO), listen, shutdown.
 * Success (probed on Win10 22H2, std and adm identical):
 *   - SO_MAX_MSG_SIZE is 65507 and the default SO_RCVBUF is 65536;
 *   - sendto of 10 bytes returns 10 and FIONREAD then reports 10 (one datagram);
 *   - recvfrom with a 4 byte buffer for a 10 byte datagram fails WSAEMSGSIZE
 *     (10040), fills the first 4 bytes, still reports the sender address, and
 *     DISCARDS the rest (FIONREAD 0 afterwards);
 *   - MSG_PEEK with a short buffer also fails WSAEMSGSIZE but keeps the
 *     datagram: a following full recvfrom returns all 10 bytes;
 *   - a zero byte datagram: sendto returns 0, FIONREAD reports 1 (sic),
 *     recvfrom returns 0 without an error;
 *   - sendto of 65508 bytes fails WSAEMSGSIZE; 65507 bytes succeeds and
 *     FIONREAD reports 65507;
 *   - nonblocking recvfrom on an empty socket: WSAEWOULDBLOCK (10035);
 *   - send on an unconnected UDP socket: WSAENOTCONN (10057); after connect
 *     send/recv work, sendto to another address on a connected UDP socket
 *     still succeeds, connect can be repeated, connect(AF_UNSPEC) disconnects
 *     (getpeername then WSAENOTCONN);
 *   - listen on UDP: WSAEOPNOTSUPP (10045); shutdown(SD_SEND) succeeds.
 * Source: lib/tftp.c (sendto/recvfrom), lib/cf-socket.c (UDP connect for QUIC).
 */
#define TEST_NAME "udp_datagram_semantics"
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
  SOCKET u = INVALID_SOCKET, c = INVALID_SOCKET;
  struct sockaddr_in a, from, other, pn, un;
  int len, v, e;
  DWORD ms;
  u_long n, nb;
  char buf[64];
  char *big = NULL;

  u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  c = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (u == INVALID_SOCKET || c == INVALID_SOCKET) FAILF("socket");
  a = loop_addr(0);
  if (bind(u, (struct sockaddr *)&a, (int)sizeof(a)) != 0) FAILF("bind");
  len = (int)sizeof(a);
  getsockname(u, (struct sockaddr *)&a, &len);

  len = (int)sizeof(ms);
  if (getsockopt(u, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&ms, &len) != 0 || ms != 65507) FAILF("SO_MAX_MSG_SIZE %lu, expected 65507", (unsigned long)ms);
  len = (int)sizeof(v);
  if (getsockopt(u, SOL_SOCKET, SO_RCVBUF, (char *)&v, &len) != 0 || v != 65536) FAILF("UDP SO_RCVBUF %d, expected 65536", v);

  if (sendto(c, "0123456789", 10, 0, (struct sockaddr *)&a, (int)sizeof(a)) != 10) FAILF("sendto 10 bytes");
  Sleep(50);
  n = 0;
  ioctlsocket(u, FIONREAD, &n);
  if (n != 10) FAILF("FIONREAD %lu, expected 10", (unsigned long)n);
  memset(buf, 'x', sizeof(buf));
  memset(&from, 0, sizeof(from));
  len = (int)sizeof(from);
  v = recvfrom(u, buf, 4, 0, (struct sockaddr *)&from, &len);
  e = WSAGetLastError();
  if (v != SOCKET_ERROR || e != WSAEMSGSIZE) FAILF("recvfrom 4 of 10: result %d error %d, expected SOCKET_ERROR / 10040", v, e);
  if (memcmp(buf, "0123", 4) != 0 || buf[4] != 'x') FAILF("truncated recvfrom did not fill exactly the first 4 bytes");
  if (from.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || from.sin_port == 0 || len != (int)sizeof(from)) FAILF("sender address not reported with the truncated datagram");
  n = 99;
  ioctlsocket(u, FIONREAD, &n);
  if (n != 0) FAILF("FIONREAD after truncated recvfrom %lu, expected 0 (rest discarded)", (unsigned long)n);

  sendto(c, "0123456789", 10, 0, (struct sockaddr *)&a, (int)sizeof(a));
  Sleep(50);
  EXPECT_ERR(recvfrom(u, buf, 4, MSG_PEEK, NULL, NULL), WSAEMSGSIZE, "MSG_PEEK with a short buffer");
  if (recvfrom(u, buf, sizeof(buf), 0, NULL, NULL) != 10) FAILF("full recvfrom after a short MSG_PEEK did not return 10 bytes");

  if (sendto(c, "", 0, 0, (struct sockaddr *)&a, (int)sizeof(a)) != 0) FAILF("sendto of 0 bytes");
  Sleep(50);
  n = 99;
  ioctlsocket(u, FIONREAD, &n);
  if (n != 1) FAILF("FIONREAD for a zero byte datagram %lu, expected 1", (unsigned long)n);
  v = recvfrom(u, buf, sizeof(buf), 0, NULL, NULL);
  if (v != 0) FAILF("recvfrom of a zero byte datagram returned %d (error %d)", v, WSAGetLastError());

  big = (char *)calloc(1, 70000);
  EXPECT_ERR(sendto(c, big, 65508, 0, (struct sockaddr *)&a, (int)sizeof(a)), WSAEMSGSIZE, "sendto 65508 bytes");
  if (sendto(c, big, 65507, 0, (struct sockaddr *)&a, (int)sizeof(a)) != 65507) FAILF("sendto 65507 bytes error %d", WSAGetLastError());
  Sleep(100);
  n = 0;
  ioctlsocket(u, FIONREAD, &n);
  if (n != 65507) FAILF("FIONREAD for 65507 bytes %lu", (unsigned long)n);
  nb = 1;
  ioctlsocket(u, FIONBIO, &nb);
  while (recvfrom(u, big, 70000, 0, NULL, NULL) > 0) {
  }
  EXPECT_ERR(recvfrom(u, buf, sizeof(buf), 0, NULL, NULL), WSAEWOULDBLOCK, "nonblocking recvfrom on an empty socket");

  EXPECT_ERR(send(c, "x", 1, 0), WSAENOTCONN, "send on unconnected UDP");
  if (connect(c, (struct sockaddr *)&a, (int)sizeof(a)) != 0) FAILF("UDP connect");
  if (send(c, "hello", 5, 0) != 5) FAILF("send on connected UDP");
  Sleep(50);
  if (recvfrom(u, buf, sizeof(buf), 0, NULL, NULL) != 5) FAILF("recv of the connected UDP datagram");
  other = loop_addr(1);
  if (sendto(c, "x", 1, 0, (struct sockaddr *)&other, (int)sizeof(other)) != 1) FAILF("sendto another address on connected UDP, error %d", WSAGetLastError());
  if (connect(c, (struct sockaddr *)&other, (int)sizeof(other)) != 0) FAILF("UDP reconnect");
  len = (int)sizeof(pn);
  if (getpeername(c, (struct sockaddr *)&pn, &len) != 0 || ntohs(pn.sin_port) != 1) FAILF("getpeername after reconnect");
  memset(&un, 0, sizeof(un));
  un.sin_family = AF_UNSPEC;
  if (connect(c, (struct sockaddr *)&un, (int)sizeof(un)) != 0) FAILF("connect(AF_UNSPEC) error %d", WSAGetLastError());
  len = (int)sizeof(pn);
  EXPECT_ERR(getpeername(c, (struct sockaddr *)&pn, &len), WSAENOTCONN, "getpeername after AF_UNSPEC disconnect");
  EXPECT_ERR(listen(c, 1), WSAEOPNOTSUPP, "listen on UDP");
  if (shutdown(c, SD_SEND) != 0) FAILF("UDP shutdown(SD_SEND) error %d", WSAGetLastError());

  printf("PASS %s\n", TEST_NAME);
  free(big);
  closesocket(u);
  closesocket(c);
  return 0;
out:
  free(big);
  if (u != INVALID_SOCKET) closesocket(u);
  if (c != INVALID_SOCKET) closesocket(c);
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

