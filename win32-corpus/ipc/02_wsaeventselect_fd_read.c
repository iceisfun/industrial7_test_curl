/*
 * Test: wsaeventselect_fd_read
 *
 * Purpose: verify that WSAEventSelect(FD_READ|FD_CLOSE) signals a WSA event
 *   when data arrives on a loopback TCP socket, that WSAEnumNetworkEvents
 *   reports FD_READ and resets the event, and that cancelling the association
 *   with WSAEventSelect(s, ev, 0) stops further signals. This is the POLLIN
 *   half of curl's multi wait.
 *
 * APIs: socket, bind, listen, getsockname, connect, accept, send, recv,
 *       WSACreateEvent, WSAEventSelect, WSAEnumNetworkEvents,
 *       WSAWaitForMultipleEvents, WSAGetLastError, closesocket, WSACloseEvent.
 *
 * Success means:
 *   - Before any data, a zero-timeout wait times out.
 *   - After the peer sends 4 bytes the event is signaled within 2 s.
 *   - WSAEnumNetworkEvents reports FD_READ with iErrorCode 0.
 *   - recv returns the 4 bytes; a second recv fails with WSAEWOULDBLOCK
 *     (the socket is nonblocking once associated).
 *   - After the enumeration the event is no longer signaled.
 *   - After WSAEventSelect(s, ev, 0) new data does not signal the event,
 *     and the pending data is still readable.
 *
 * Source: curl lib/multi.c:1389 (WSAEventSelect with
 *   FD_READ|FD_ACCEPT|FD_CLOSE for POLLIN), lib/multi.c:1423-1433
 *   (WSAEnumNetworkEvents then WSAEventSelect(s, ev, 0)),
 *   lib/telnet.c:1271 (WSAEventSelect with FD_READ|FD_CLOSE).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "wsaeventselect_fd_read"

#define CHECK(c, ...)                                  \
  do {                                                 \
    if(!(c)) {                                         \
      snprintf(msg, msz, __VA_ARGS__);                 \
      rc = 1;                                          \
      goto done;                                       \
    }                                                  \
  } while(0)

/* Create a connected loopback TCP pair. *srv is the accepted side,
   *cli the connecting side. Returns 0 or a Winsock error code. */
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
  sa.sin_port = 0;
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
  DWORD w;
  int n, e, rc = 0;
  char buf[16];

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) {
    snprintf(msg, msz, "WSAStartup failed: %d", e);
    return 1;
  }

  e = make_pair(&srv, &cli);
  if(e) {
    if(is_absent(e)) {
      snprintf(msg, msz, "no loopback TCP (err %d)", e);
      WSACleanup();
      return 77;
    }
    snprintf(msg, msz, "loopback pair setup failed: %d", e);
    WSACleanup();
    return 1;
  }

  ev = WSACreateEvent();
  CHECK(ev != WSA_INVALID_EVENT, "WSACreateEvent failed: %d", WSAGetLastError());

  CHECK(WSAEventSelect(srv, ev, FD_READ | FD_CLOSE) == 0,
        "WSAEventSelect(FD_READ|FD_CLOSE) failed: %d", WSAGetLastError());

  /* No data yet: must not be signaled. */
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT,
        "no data yet: expected WSA_WAIT_TIMEOUT, got %lu", (unsigned long)w);

  CHECK(send(cli, "ping", 4, 0) == 4, "send failed: %d", WSAGetLastError());

  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 2000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0,
        "after data: expected WSA_WAIT_EVENT_0, got %lu (WSAGetLastError=%d)",
        (unsigned long)w, WSAGetLastError());

  memset(&ne, 0, sizeof(ne));
  CHECK(WSAEnumNetworkEvents(srv, ev, &ne) == 0,
        "WSAEnumNetworkEvents failed: %d", WSAGetLastError());
  CHECK(ne.lNetworkEvents & FD_READ, "lNetworkEvents=0x%lx lacks FD_READ",
        (unsigned long)ne.lNetworkEvents);
  CHECK(ne.iErrorCode[FD_READ_BIT] == 0,
        "FD_READ iErrorCode=%d, expected 0", ne.iErrorCode[FD_READ_BIT]);

  /* Socket is nonblocking after association; read the 4 bytes. */
  n = recv(srv, buf, sizeof(buf), 0);
  CHECK(n == 4 && memcmp(buf, "ping", 4) == 0,
        "recv returned %d (expected 4 bytes 'ping')", n);

  n = recv(srv, buf, sizeof(buf), 0);
  CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK,
        "second recv: expected WSAEWOULDBLOCK, got n=%d err=%d", n,
        WSAGetLastError());

  /* Enumeration reset the event: nothing pending now. */
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT,
        "after enumerate+drain: expected WSA_WAIT_TIMEOUT, got %lu",
        (unsigned long)w);

  /* Cancel the association, then send more data: no signal expected. */
  CHECK(WSAEventSelect(srv, ev, 0) == 0,
        "WSAEventSelect(ev, 0) failed: %d", WSAGetLastError());
  CHECK(send(cli, "pong", 4, 0) == 4, "second send failed: %d",
        WSAGetLastError());
  Sleep(200);
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT,
        "after cancel: event must not be signaled, got %lu",
        (unsigned long)w);

  /* The data is still there and readable. */
  n = recv(srv, buf, sizeof(buf), 0);
  CHECK(n == 4 && memcmp(buf, "pong", 4) == 0,
        "post-cancel recv returned %d (expected 'pong')", n);

done:
  if(ev != WSA_INVALID_EVENT)
    WSACloseEvent(ev);
  if(srv != INVALID_SOCKET)
    closesocket(srv);
  if(cli != INVALID_SOCKET)
    closesocket(cli);
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
