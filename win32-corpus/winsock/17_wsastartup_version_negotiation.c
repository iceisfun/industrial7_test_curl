/*
 * Test: 17_wsastartup_version_negotiation
 * Purpose: WSAStartup version negotiation and the pre-startup error contract.
 *          curl asks for 2.2 (lib/easy.c) and treats anything else as failure;
 *          this pins what Windows returns for other requests so that a
 *          replacement implementation can be compared exactly.
 * APIs: WSAStartup, WSACleanup, socket, WSAGetLastError.
 * Success (probed on Win10 22H2, std and adm identical). Request -> wVersion
 *   (wHighVersion is always 0x0202):
 *     0x0101 -> 0x0101 (iMaxSockets 32767, iMaxUdpDg 65467)
 *     0x0001 -> 0x0001 (32767 / 65467)     0x0201 -> 0x0101 (32767 / 65467)
 *     0x0002 -> 0x0002   0x0202 -> 0x0202  (iMaxSockets 0 and iMaxUdpDg 0 for 2.x)
 *     0x0203 -> 0x0202   0x0302 -> 0x0202  0x0A0A -> 0x0202
 *     0x0000 and 0x0100 -> WSAVERNOTSUPPORTED (10092); the failed call still fills
 *                          wVersion and wHighVersion with 0x0202
 *   szDescription is "WinSock 2.0" and szSystemStatus "Running".
 *   WSAStartup(2.2, NULL) fails with WSAEFAULT (10014). An unmatched WSACleanup
 *   fails WSANOTINITIALISED (10093), and socket() before any startup fails with
 *   WSANOTINITIALISED. Startups are reference counted: three WSAStartup calls
 *   need three WSACleanup calls before socket() fails again.
 * Source: lib/easy.c:167 (WSAStartup(MAKEWORD(2, 2), &wsa)).
 */
#define TEST_NAME "wsastartup_version_negotiation"
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


typedef struct {
  WORD req;
  int rc;
  WORD ver;
  int maxsock, maxudp;
} row_t;

static const row_t T[] = {
  {0x0101, 0, 0x0101, 32767, 65467}, {0x0001, 0, 0x0001, 32767, 65467}, {0x0201, 0, 0x0101, 32767, 65467},
  {0x0002, 0, 0x0002, 0, 0},         {0x0202, 0, 0x0202, 0, 0},         {0x0203, 0, 0x0202, 0, 0},
  {0x0302, 0, 0x0202, 0, 0},         {0x0A0A, 0, 0x0202, 0, 0},         {0x0000, WSAVERNOTSUPPORTED, 0, 0, 0},
  {0x0100, WSAVERNOTSUPPORTED, 0, 0, 0},
};

static int body(void) {
  WSADATA w;
  size_t i;
  int rc;
  SOCKET s;

  /* main() already holds one reference; drop it so the process starts uninitialised. */
  if (WSACleanup() != 0) FAILF("initial WSACleanup error %d", WSAGetLastError());
  EXPECT_ERR(WSACleanup(), WSANOTINITIALISED, "WSACleanup without WSAStartup");
  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  EXPECT_ERR(s == INVALID_SOCKET ? SOCKET_ERROR : 0, WSANOTINITIALISED, "socket before WSAStartup");
  if (WSAStartup(MAKEWORD(2, 2), NULL) != WSAEFAULT) FAILF("WSAStartup(2.2, NULL) did not return WSAEFAULT");

  for (i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
    memset(&w, 0, sizeof(w));
    rc = WSAStartup(T[i].req, &w);
    if (rc != T[i].rc) FAILF("WSAStartup(0x%04x) returned %d, expected %d", T[i].req, rc, T[i].rc);
    if (rc == 0) {
      if (w.wVersion != T[i].ver || w.wHighVersion != 0x0202 || w.iMaxSockets != T[i].maxsock || w.iMaxUdpDg != T[i].maxudp)
        FAILF("WSAStartup(0x%04x): wVersion 0x%04x wHighVersion 0x%04x iMaxSockets %u iMaxUdpDg %u, expected 0x%04x / 0x0202 / %d / %d",
              T[i].req, w.wVersion, w.wHighVersion, (unsigned)w.iMaxSockets, (unsigned)w.iMaxUdpDg, T[i].ver, T[i].maxsock, T[i].maxudp);
      if (strcmp(w.szDescription, "WinSock 2.0") != 0 || strcmp(w.szSystemStatus, "Running") != 0)
        FAILF("WSAStartup(0x%04x): description \"%s\" status \"%s\"", T[i].req, w.szDescription, w.szSystemStatus);
      if (WSACleanup() != 0) FAILF("WSACleanup after 0x%04x", T[i].req);
    } else if (w.wVersion != 0x0202 || w.wHighVersion != 0x0202) {
      FAILF("failed WSAStartup(0x%04x) left wVersion 0x%04x wHighVersion 0x%04x, expected 0x0202 / 0x0202", T[i].req,
            w.wVersion, w.wHighVersion);
    }
  }

  /* reference counting */
  for (i = 0; i < 3; i++)
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) FAILF("WSAStartup #%u", (unsigned)i);
  for (i = 0; i < 3; i++) {
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) FAILF("socket failed with %u startups left", (unsigned)(3 - i));
    closesocket(s);
    if (WSACleanup() != 0) FAILF("WSACleanup #%u", (unsigned)i);
  }
  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  EXPECT_ERR(s == INVALID_SOCKET ? SOCKET_ERROR : 0, WSANOTINITIALISED, "socket after the last WSACleanup");

  /* restore the reference main() expects to release */
  if (WSAStartup(MAKEWORD(2, 2), &w) != 0) FAILF("final WSAStartup");
  printf("PASS %s\n", TEST_NAME);
  return 0;
out:
  WSAStartup(MAKEWORD(2, 2), &w);
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

