/*
 * Test: wsagetoverlappedresult
 *
 * Purpose: drive overlapped WSARecv on a loopback TCP socket and collect the
 *   result with WSAGetOverlappedResult, using the OVERLAPPED.hEvent as the
 *   completion signal in a WSAWaitForMultipleEvents wait. This is the
 *   completion-collection pattern used by overlapped Winsock code paths, and
 *   it must report incomplete, complete, and blocking-complete states
 *   correctly. Covers the graceful-EOF completion (0 bytes) as the failure
 *   path.
 *
 * APIs: WSASocketW (WSA_FLAG_OVERLAPPED), bind, listen, getsockname, connect,
 *       accept, WSARecv, WSASend/send, WSAGetOverlappedResult,
 *       WSACreateEvent, WSAWaitForMultipleEvents, WSACloseEvent.
 *
 * Success means:
 *   - WSARecv with no data pending returns SOCKET_ERROR/WSA_IO_PENDING.
 *   - WSAGetOverlappedResult(fWait=FALSE) before data arrives returns FALSE
 *     with WSAGetLastError() == WSA_IO_INCOMPLETE.
 *   - After the peer sends "hello" the hEvent is signaled and
 *     WSAGetOverlappedResult(fWait=FALSE) returns TRUE with 5 bytes.
 *   - A second overlapped receive completed with WSAGetOverlappedResult
 *     (fWait=TRUE) returns the 5 bytes "world".
 *   - After the peer closes, a receive completes with 0 bytes (graceful EOF)
 *     and WSAGetOverlappedResult reports TRUE with cbTransfer 0.
 *
 * Source: none in curl. curl's multi wait (lib/multi.c:1369-1466) uses
 *   WSAEventSelect/WSAEnumNetworkEvents and never posts overlapped WSARecv, so
 *   this test covers the Winsock overlapped completion API on its own, not a
 *   curl call path.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "wsagetoverlappedresult"

#define CHECK(c, ...)                                  \
  do {                                                 \
    if(!(c)) {                                         \
      snprintf(msg, msz, __VA_ARGS__);                 \
      rc = 1;                                          \
      goto done;                                       \
    }                                                  \
  } while(0)

static int is_absent(int e)
{
  return e == WSAENETDOWN || e == WSAEAFNOSUPPORT || e == WSAEPROTONOSUPPORT;
}

/* Overlapped loopback pair. srv is the accepted socket. */
static int make_pair_ov(SOCKET *srv, SOCKET *cli)
{
  struct sockaddr_in sa;
  int salen = sizeof(sa);
  SOCKET l, c, a;
  int e;

  l = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                 WSA_FLAG_OVERLAPPED);
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
  c = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                 WSA_FLAG_OVERLAPPED);
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

static int body(char *msg, size_t msz)
{
  WSADATA wd;
  SOCKET srv = INVALID_SOCKET, cli = INVALID_SOCKET;
  OVERLAPPED ov1, ov2, ov3;
  WSABUF wb;
  char buf1[16], buf2[16], buf3[16];
  DWORD n = 0, flags = 0, w;
  int e, rc = 0, r;

  memset(&ov1, 0, sizeof(ov1));
  memset(&ov2, 0, sizeof(ov2));
  memset(&ov3, 0, sizeof(ov3));

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) {
    snprintf(msg, msz, "WSAStartup failed: %d", e);
    return 1;
  }

  e = make_pair_ov(&srv, &cli);
  if(e) {
    WSACleanup();
    if(is_absent(e)) {
      snprintf(msg, msz, "no loopback TCP (err %d)", e);
      return 77;
    }
    snprintf(msg, msz, "overlapped loopback pair setup failed: %d", e);
    return 1;
  }

  /* ---- Op 1: receive "hello" with a completion event. ---- */
  ov1.hEvent = WSACreateEvent();
  CHECK(ov1.hEvent != WSA_INVALID_EVENT, "WSACreateEvent(1) failed");
  wb.len = sizeof(buf1);
  wb.buf = buf1;
  r = WSARecv(srv, &wb, 1, &n, &flags, &ov1, NULL);
  CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING,
        "op1: WSARecv with no data: expected WSA_IO_PENDING, got rc=%d err=%d n=%lu",
        r, WSAGetLastError(), (unsigned long)n);

  flags = 0;
  n = 0;
  CHECK(WSAGetOverlappedResult(srv, &ov1, &n, FALSE, &flags) == FALSE,
        "op1: WSAGetOverlappedResult returned TRUE before data");
  CHECK(WSAGetLastError() == WSA_IO_INCOMPLETE,
        "op1: expected WSA_IO_INCOMPLETE, got %d", WSAGetLastError());

  CHECK(send(cli, "hello", 5, 0) == 5, "send(hello) failed: %d",
        WSAGetLastError());

  w = WSAWaitForMultipleEvents(1, &ov1.hEvent, FALSE, 2000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0, "op1: completion event not signaled (%lu)",
        (unsigned long)w);

  n = 0;
  flags = 0;
  CHECK(WSAGetOverlappedResult(srv, &ov1, &n, FALSE, &flags) == TRUE,
        "op1: WSAGetOverlappedResult failed: %d", WSAGetLastError());
  CHECK(n == 5, "op1: cbTransfer=%lu, expected 5", (unsigned long)n);
  CHECK(memcmp(buf1, "hello", 5) == 0, "op1: buffer does not contain 'hello'");

  /* ---- Op 2: receive "world" and collect with fWait=TRUE. ---- */
  ov2.hEvent = WSACreateEvent();
  CHECK(ov2.hEvent != WSA_INVALID_EVENT, "WSACreateEvent(2) failed");
  wb.len = sizeof(buf2);
  wb.buf = buf2;
  flags = 0;
  r = WSARecv(srv, &wb, 1, &n, &flags, &ov2, NULL);
  CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING,
        "op2: expected WSA_IO_PENDING, got rc=%d err=%d", r, WSAGetLastError());

  CHECK(send(cli, "world", 5, 0) == 5, "send(world) failed: %d",
        WSAGetLastError());
  n = 0;
  flags = 0;
  CHECK(WSAGetOverlappedResult(srv, &ov2, &n, TRUE, &flags) == TRUE,
        "op2: blocking WSAGetOverlappedResult failed: %d", WSAGetLastError());
  CHECK(n == 5 && memcmp(buf2, "world", 5) == 0,
        "op2: got %lu bytes, expected 'world'", (unsigned long)n);

  /* ---- Op 3 (failure path): peer closes, receive completes with 0 bytes. */
  ov3.hEvent = WSACreateEvent();
  CHECK(ov3.hEvent != WSA_INVALID_EVENT, "WSACreateEvent(3) failed");
  wb.len = sizeof(buf3);
  wb.buf = buf3;
  flags = 0;
  n = 0;
  closesocket(cli);
  cli = INVALID_SOCKET;
  r = WSARecv(srv, &wb, 1, &n, &flags, &ov3, NULL);
  if(r == SOCKET_ERROR) {
    CHECK(WSAGetLastError() == WSA_IO_PENDING,
          "op3: WSARecv after peer close: err=%d", WSAGetLastError());
    n = 0;
    flags = 0;
    CHECK(WSAGetOverlappedResult(srv, &ov3, &n, TRUE, &flags) == TRUE,
          "op3: WSAGetOverlappedResult(EOF) failed: %d", WSAGetLastError());
  }
  CHECK(n == 0, "op3: EOF completion reported %lu bytes, expected 0",
        (unsigned long)n);

done:
  if(ov1.hEvent && ov1.hEvent != WSA_INVALID_EVENT)
    WSACloseEvent(ov1.hEvent);
  if(ov2.hEvent && ov2.hEvent != WSA_INVALID_EVENT)
    WSACloseEvent(ov2.hEvent);
  if(ov3.hEvent && ov3.hEvent != WSA_INVALID_EVENT)
    WSACloseEvent(ov3.hEvent);
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
