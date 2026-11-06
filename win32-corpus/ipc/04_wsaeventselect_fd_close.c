/*
 * Test: wsaeventselect_fd_close
 *
 * Purpose: verify that FD_CLOSE is delivered through WSAEventSelect when the
 *   peer closes a connection, so that curl's multi wait wakes up and the
 *   subsequent recv() observes EOF. Phase A: graceful close by the peer
 *   (FD_READ|FD_CLOSE association, expect FD_CLOSE with no error and recv
 *   returning 0). Phase B (failure path): abortive close via SO_LINGER(0),
 *   expect FD_CLOSE and recv failing with a reset error.
 *
 * APIs: socket, bind, listen, getsockname, connect, accept, setsockopt
 *       (SO_LINGER), send, recv, closesocket, WSACreateEvent,
 *       WSAEventSelect, WSAEnumNetworkEvents, WSAWaitForMultipleEvents,
 *       WSACloseEvent.
 *
 * Success means:
 *   Phase A: no event before the peer closes; after closesocket on the
 *     peer the event is signaled within 2 s; FD_CLOSE is reported with
 *     iErrorCode 0; recv on the server socket returns 0 (EOF).
 *   Phase B: FD_CLOSE is reported with iErrorCode WSAECONNABORTED (10053,
 *     probed on Win10 22H2); recv then returns SOCKET_ERROR with
 *     WSAECONNRESET (10054), never a silent 0-byte EOF.
 *
 * Source: curl lib/multi.c:1385-1389 (POLLIN maps FD_CLOSE into the mask so
 *   a peer close wakes curl_multi_poll), lib/multi.c:1424-1426 (FD_CLOSE is
 *   read back as CURL_WAIT_POLLIN in the WSAEnumNetworkEvents loop).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "wsaeventselect_fd_close"

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
  WSAEVENT ev = WSA_INVALID_EVENT;
  WSANETWORKEVENTS ne;
  struct linger lg;
  DWORD w;
  int e, n, rc = 0;
  char buf[8];

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) {
    snprintf(msg, msz, "WSAStartup failed: %d", e);
    return 1;
  }

  /* ---- Phase A: graceful peer close ---- */
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

  ev = WSACreateEvent();
  CHECK(ev != WSA_INVALID_EVENT, "WSACreateEvent failed: %d", WSAGetLastError());
  CHECK(WSAEventSelect(srv, ev, FD_READ | FD_CLOSE) == 0,
        "WSAEventSelect failed: %d", WSAGetLastError());

  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT,
        "connection open, no data: expected WSA_WAIT_TIMEOUT, got %lu",
        (unsigned long)w);

  CHECK(closesocket(cli) == 0, "closesocket(peer) failed: %d",
        WSAGetLastError());
  cli = INVALID_SOCKET;

  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 2000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0,
        "after peer close: expected WSA_WAIT_EVENT_0, got %lu",
        (unsigned long)w);

  memset(&ne, 0, sizeof(ne));
  CHECK(WSAEnumNetworkEvents(srv, ev, &ne) == 0,
        "WSAEnumNetworkEvents failed: %d", WSAGetLastError());
  CHECK(ne.lNetworkEvents & FD_CLOSE,
        "lNetworkEvents=0x%lx lacks FD_CLOSE",
        (unsigned long)ne.lNetworkEvents);
  CHECK(ne.iErrorCode[FD_CLOSE_BIT] == 0,
        "graceful FD_CLOSE iErrorCode=%d, expected 0",
        ne.iErrorCode[FD_CLOSE_BIT]);

  n = recv(srv, buf, sizeof(buf), 0);
  CHECK(n == 0, "recv after graceful close: expected 0 (EOF), got %d (err=%d)",
        n, WSAGetLastError());

  CHECK(WSAEventSelect(srv, ev, 0) == 0, "WSAEventSelect(0) failed: %d",
        WSAGetLastError());
  closesocket(srv);
  srv = INVALID_SOCKET;
  WSACloseEvent(ev);
  ev = WSA_INVALID_EVENT;

  /* ---- Phase B: abortive close (RST) ---- */
  e = make_pair(&srv, &cli);
  CHECK(e == 0, "second loopback pair failed: %d", e);

  ev = WSACreateEvent();
  CHECK(ev != WSA_INVALID_EVENT, "WSACreateEvent(B) failed");
  CHECK(WSAEventSelect(srv, ev, FD_READ | FD_CLOSE) == 0,
        "WSAEventSelect(B) failed: %d", WSAGetLastError());

  memset(&lg, 0, sizeof(lg));
  lg.l_onoff = 1;
  lg.l_linger = 0;
  CHECK(setsockopt(cli, SOL_SOCKET, SO_LINGER, (const char *)&lg,
                   sizeof(lg)) == 0,
        "setsockopt(SO_LINGER) failed: %d", WSAGetLastError());
  closesocket(cli);
  cli = INVALID_SOCKET;

  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 2000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0,
        "after RST: expected WSA_WAIT_EVENT_0, got %lu", (unsigned long)w);

  memset(&ne, 0, sizeof(ne));
  CHECK(WSAEnumNetworkEvents(srv, ev, &ne) == 0,
        "WSAEnumNetworkEvents(B) failed: %d", WSAGetLastError());
  CHECK(ne.lNetworkEvents & FD_CLOSE, "RST: lacks FD_CLOSE");
  /* An abortive close is never a clean EOF. Probed on Win10 22H2
     (20 runs, std and adm identical): the FD_CLOSE event carries
     WSAECONNABORTED while the following recv() fails with WSAECONNRESET. */
  e = ne.iErrorCode[FD_CLOSE_BIT];
  CHECK(e == WSAECONNABORTED,
        "RST: FD_CLOSE iErrorCode=%d, expected WSAECONNABORTED (%d)",
        e, WSAECONNABORTED);

  n = recv(srv, buf, sizeof(buf), 0);
  CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET,
        "recv after RST: expected SOCKET_ERROR with WSAECONNRESET, "
        "got n=%d err=%d", n, WSAGetLastError());

done:
  if(cli != INVALID_SOCKET)
    closesocket(cli);
  if(srv != INVALID_SOCKET)
    closesocket(srv);
  if(ev != WSA_INVALID_EVENT)
    WSACloseEvent(ev);
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
