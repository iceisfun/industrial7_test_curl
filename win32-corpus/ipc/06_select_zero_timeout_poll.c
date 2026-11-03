/*
 * Test: select_zero_timeout_poll
 *
 * Purpose: use select() with a zero timeval as a non-blocking poll, which is
 *   how curl's select-based fallback checks readiness before deciding to wait.
 *   Covers read readiness on a loopback socket, write readiness on a
 *   connected socket, and the no-block guarantee of a zero timeout.
 *
 * APIs: select (Winsock), FD_ZERO, FD_SET, FD_ISSET, struct timeval,
 *       send, recv, socket/bind/listen/connect/accept, GetTickCount64.
 *
 * Success means:
 *   - select(..., &{0,0}) with an empty peer buffer returns 0 and the socket
 *     is not in the returned read set.
 *   - After the peer sends a byte, select with a zero timeout returns 1 and
 *     FD_ISSET is true for the read set.
 *   - A connected socket in the write set is reported writable with a zero
 *     timeout (returns 1).
 *   - 200 zero-timeout polls on a quiet socket finish in under 2000 ms,
 *     so the poll does not block.
 *
 * Source: curl lib/select.c:51-68 (our_select wraps select() with
 *   curlx_mstotv, so a 0 ms timeout becomes a zero timeval), and
 *   lib/select.c:199-208 (Curl_poll, polled with timeout 0 in
 *   the curl_multi_wait pre-check path).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "select_zero_timeout_poll"

#define CHECK(c, ...)                                  \
  do {                                                 \
    if(!(c)) {                                         \
      snprintf(msg, msz, __VA_ARGS__);                 \
      rc = 1;                                          \
      goto done;                                       \
    }                                                  \
  } while(0)

static int make_pair(SOCKET *srv, SOCKET *cli)
{
  struct sockaddr_in sa;
  int salen = sizeof(sa);
  SOCKET l, c, a;
  int e;

  l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(l == INVALID_SOCKET)
    return WSAGetLastError();
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(bind(l, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR ||
     listen(l, 4) == SOCKET_ERROR ||
     getsockname(l, (struct sockaddr *)&sa, &salen) == SOCKET_ERROR) {
    e = WSAGetLastError();
    closesocket(l);
    return e;
  }
  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(c == INVALID_SOCKET) {
    e = WSAGetLastError();
    closesocket(l);
    return e;
  }
  if(connect(c, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
    e = WSAGetLastError();
    closesocket(c);
    closesocket(l);
    return e;
  }
  a = accept(l, NULL, NULL);
  closesocket(l);
  if(a == INVALID_SOCKET) {
    e = WSAGetLastError();
    closesocket(c);
    return e;
  }
  *srv = a;
  *cli = c;
  return 0;
}

static int is_absent(int e)
{
  return e == WSAENETDOWN || e == WSAEAFNOSUPPORT || e == WSAEPROTONOSUPPORT;
}

static int body(char *msg, size_t msz)
{
  WSADATA wd;
  SOCKET srv = INVALID_SOCKET, cli = INVALID_SOCKET;
  fd_set rd, wr;
  struct timeval tv;
  ULONGLONG t0, t1;
  int i, n, e, rc = 0;
  char b = 'q';
  char buf[4];

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) {
    snprintf(msg, msz, "WSAStartup failed: %d", e);
    return 1;
  }

  e = make_pair(&srv, &cli);
  if(e) {
    WSACleanup();
    if(is_absent(e)) {
      snprintf(msg, msz, "no loopback TCP (err %d)", e);
      return 77;
    }
    snprintf(msg, msz, "loopback pair setup failed: %d", e);
    return 1;
  }

  /* (a) quiet socket: zero-timeout poll reports nothing. */
  FD_ZERO(&rd);
  FD_SET(srv, &rd);
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  n = select(0, &rd, NULL, NULL, &tv);
  CHECK(n == 0, "quiet socket: select returned %d, expected 0 (err=%d)", n,
        WSAGetLastError());
  CHECK(!FD_ISSET(srv, &rd), "quiet socket: FD_ISSET true after timeout");

  /* (b) timing: many polls must not block. */
  t0 = GetTickCount64();
  for(i = 0; i < 200; i++) {
    FD_ZERO(&rd);
    FD_SET(srv, &rd);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    n = select(0, &rd, NULL, NULL, &tv);
    CHECK(n == 0, "poll %d returned %d, expected 0", i, n);
  }
  t1 = GetTickCount64();
  CHECK(t1 - t0 < 2000, "200 zero-timeout polls took %llu ms",
        (unsigned long long)(t1 - t0));

  /* (c) peer writes: read readiness appears with zero timeout. */
  CHECK(send(cli, &b, 1, 0) == 1, "send failed: %d", WSAGetLastError());
  /* Give the loopback stack a moment to deliver the byte. */
  Sleep(50);
  FD_ZERO(&rd);
  FD_SET(srv, &rd);
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  n = select(0, &rd, NULL, NULL, &tv);
  CHECK(n == 1, "readable socket: select returned %d, expected 1", n);
  CHECK(FD_ISSET(srv, &rd), "readable socket: FD_ISSET false");
  CHECK(recv(srv, buf, sizeof(buf), 0) == 1 && buf[0] == 'q',
        "recv after poll did not return the byte");

  /* (d) connected socket is writable: write set reports it with 0 timeout. */
  FD_ZERO(&wr);
  FD_SET(cli, &wr);
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  n = select(0, NULL, &wr, NULL, &tv);
  CHECK(n == 1, "writable socket: select returned %d, expected 1", n);
  CHECK(FD_ISSET(cli, &wr), "writable socket: FD_ISSET false");

done:
  if(cli != INVALID_SOCKET)
    closesocket(cli);
  if(srv != INVALID_SOCKET)
    closesocket(srv);
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
  else if(rc == 77)
    printf("SKIP %s: %s\n", TEST_NAME, msg);
  else
    printf("FAIL %s: %s\n", TEST_NAME, msg);
  return rc;
}
