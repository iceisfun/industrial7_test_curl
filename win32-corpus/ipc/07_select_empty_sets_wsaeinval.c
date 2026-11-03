/*
 * Test: select_empty_sets_wsaeinval
 *
 * Purpose: document the Winsock select() restriction that curl works around:
 *   select() fails with WSAEINVAL when no fd_set has any socket, and also
 *   when a non-NULL fd_set has fd_count == 0 and nothing else is supplied.
 *   curl therefore sleeps instead of calling select() for empty sets and
 *   passes NULL for empty sets. This test checks both failure forms, and the
 *   working form that curl relies on (NULL for an empty set).
 *
 * APIs: select (Winsock), FD_ZERO, FD_SET, struct timeval, socket/bind/
 *       listen/connect/accept, WSAGetLastError.
 *
 * Success means:
 *   (a) select(0, NULL, NULL, NULL, &tv) returns SOCKET_ERROR with
 *       WSAEINVAL.
 *   (b) select(0, &emptyset, NULL, NULL, &tv) with fd_count 0 returns
 *       SOCKET_ERROR with WSAEINVAL.
 *   (c) select(0, NULL, NULL, NULL, ...) is replaced by a timed Sleep and the
 *       sleep actually waits (elapsed >= 40 ms for a 50 ms wait).
 *   (d) select(0, &nonempty, NULL, NULL, &zero) with a quiet socket returns 0
 *       (control case: non-empty set is accepted).
 *
 * Source: curl lib/select.c:61-66 (empty fd_sets short-circuit to
 *   curlx_wait_ms because Winsock select() cannot handle zero events),
 *   lib/select.c:73-88 (the NULL-substitution comment explaining WSAEINVAL).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "select_empty_sets_wsaeinval"

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
  fd_set empty, rd;
  struct timeval tv;
  ULONGLONG t0, t1;
  int n, e, rc = 0;

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) {
    snprintf(msg, msz, "WSAStartup failed: %d", e);
    return 1;
  }

  /* (a) no fd_set at all. */
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  n = select(0, NULL, NULL, NULL, &tv);
  CHECK(n == SOCKET_ERROR, "all-NULL select returned %d, expected SOCKET_ERROR",
        n);
  CHECK(WSAGetLastError() == WSAEINVAL,
        "all-NULL select: WSAGetLastError=%d, expected WSAEINVAL (%d)",
        WSAGetLastError(), WSAEINVAL);

  /* (b) an fd_set that contains zero sockets. */
  FD_ZERO(&empty);
  CHECK(empty.fd_count == 0, "FD_ZERO left fd_count=%u", empty.fd_count);
  n = select(0, &empty, NULL, NULL, &tv);
  CHECK(n == SOCKET_ERROR, "empty fd_set select returned %d, expected SOCKET_ERROR",
        n);
  CHECK(WSAGetLastError() == WSAEINVAL,
        "empty fd_set select: WSAGetLastError=%d, expected WSAEINVAL (%d)",
        WSAGetLastError(), WSAEINVAL);

  /* (c) curl's workaround: an empty wait is a plain timed sleep. */
  t0 = GetTickCount64();
  Sleep(50);
  t1 = GetTickCount64();
  CHECK(t1 - t0 >= 40, "Sleep(50) returned after %llu ms",
        (unsigned long long)(t1 - t0));

  /* (d) control: a non-empty read set with a quiet socket is accepted. */
  e = make_pair(&srv, &cli);
  if(e) {
    if(is_absent(e)) {
      snprintf(msg, msz, "no loopback TCP (err %d)", e);
      rc = 77;
      goto done;
    }
    CHECK(0, "loopback pair setup failed: %d", e);
  }
  FD_ZERO(&rd);
  FD_SET(srv, &rd);
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  n = select(0, &rd, NULL, NULL, &tv);
  CHECK(n == 0, "non-empty quiet set: select returned %d, expected 0 (err=%d)",
        n, WSAGetLastError());

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
