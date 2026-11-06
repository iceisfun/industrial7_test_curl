/*
 * Test: 18_address_and_socket_creation_errors
 * Purpose: error codes for bad addresses and bad socket parameters, as seen by
 *          curl's connect loop (lib/connect.c tries each resolved address and
 *          classifies the error) and Curl_socket_open.
 * APIs: socket, connect, bind, WSAGetLastError.
 * Success (probed on Win10 22H2, std and adm identical):
 *   - connect to 0.0.0.0:80, to 127.0.0.1:0 and to 255.255.255.255:80:
 *     WSAEADDRNOTAVAIL (10049) (unlike Linux, 0.0.0.0 does not mean localhost);
 *   - connect with sin_family AF_INET6 or 0 on an AF_INET socket:
 *     WSAEAFNOSUPPORT (10047); with an address length shorter than the structure
 *     or a NULL address: WSAEFAULT (10014);
 *   - bind to a non-local address (8.8.8.8): WSAEADDRNOTAVAIL; with a short
 *     length: WSAEFAULT; a second bind on a bound socket: WSAEINVAL (10022);
 *   - socket(99, ...): WSAEAFNOSUPPORT (10047); SOCK_STREAM with IPPROTO_UDP:
 *     WSAEPROTONOSUPPORT (10043); an invalid type 77: WSAESOCKTNOSUPPORT (10044).
 * Source: lib/connect.c (trying each address), lib/cf-socket.c
 *         (Curl_socket_open / socket creation failures are skipped per address).
 */
#define TEST_NAME "address_and_socket_creation_errors"
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
  SOCKET s = INVALID_SOCKET, b = INVALID_SOCKET;
  struct sockaddr_in a;

  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) FAILF("socket");
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(80);
  EXPECT_ERR(connect(s, (struct sockaddr *)&a, (int)sizeof(a)), WSAEADDRNOTAVAIL, "connect 0.0.0.0:80");
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = 0;
  EXPECT_ERR(connect(s, (struct sockaddr *)&a, (int)sizeof(a)), WSAEADDRNOTAVAIL, "connect 127.0.0.1:0");
  a.sin_addr.s_addr = 0xFFFFFFFFu;
  a.sin_port = htons(80);
  EXPECT_ERR(connect(s, (struct sockaddr *)&a, (int)sizeof(a)), WSAEADDRNOTAVAIL, "connect 255.255.255.255:80");
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_ERR(connect(s, (struct sockaddr *)&a, (int)sizeof(a) - 4), WSAEFAULT, "connect with a short address length");
  EXPECT_ERR(connect(s, NULL, 16), WSAEFAULT, "connect with a NULL address");
  a.sin_family = AF_INET6;
  EXPECT_ERR(connect(s, (struct sockaddr *)&a, (int)sizeof(a)), WSAEAFNOSUPPORT, "connect with AF_INET6 on an AF_INET socket");
  a.sin_family = 0;
  EXPECT_ERR(connect(s, (struct sockaddr *)&a, (int)sizeof(a)), WSAEAFNOSUPPORT, "connect with family 0");
  closesocket(s);
  s = INVALID_SOCKET;

  b = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = inet_addr("8.8.8.8");
  EXPECT_ERR(bind(b, (struct sockaddr *)&a, (int)sizeof(a)), WSAEADDRNOTAVAIL, "bind to a non-local address");
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_ERR(bind(b, (struct sockaddr *)&a, (int)sizeof(a) - 4), WSAEFAULT, "bind with a short address length");
  if (bind(b, (struct sockaddr *)&a, (int)sizeof(a)) != 0) FAILF("bind 127.0.0.1:0 error %d", WSAGetLastError());
  EXPECT_ERR(bind(b, (struct sockaddr *)&a, (int)sizeof(a)), WSAEINVAL, "second bind on a bound socket");

  EXPECT_ERR(socket(99, SOCK_STREAM, 0) == INVALID_SOCKET ? SOCKET_ERROR : 0, WSAEAFNOSUPPORT, "socket(99)");
  EXPECT_ERR(socket(AF_INET, SOCK_STREAM, IPPROTO_UDP) == INVALID_SOCKET ? SOCKET_ERROR : 0, WSAEPROTONOSUPPORT, "SOCK_STREAM + IPPROTO_UDP");
  EXPECT_ERR(socket(AF_INET, 77, 0) == INVALID_SOCKET ? SOCKET_ERROR : 0, WSAESOCKTNOSUPPORT, "socket type 77");

  printf("PASS %s\n", TEST_NAME);
  closesocket(b);
  return 0;
out:
  if (s != INVALID_SOCKET) closesocket(s);
  if (b != INVALID_SOCKET) closesocket(b);
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

