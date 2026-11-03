/*
 * Test: wsawait_timeout
 *
 * Purpose: verify the timeout semantics of WSAWaitForMultipleEvents as used
 *   by curl's multi wait: a wait with no signaled event returns
 *   WSA_WAIT_TIMEOUT after roughly the requested time, a zero timeout returns
 *   immediately, and a socket event that has not fired does not end the wait
 *   early. Also the failure path: waiting on a closed event handle returns
 *   WSA_WAIT_FAILED with ERROR_INVALID_HANDLE.
 *
 * APIs: WSACreateEvent, WSACloseEvent, WSAEventSelect, WSAWaitForMultipleEvents,
 *       GetTickCount64, socket/bind/listen/connect/accept, WSAGetLastError.
 *
 * Success means:
 *   - Zero timeout on an unsignaled event returns WSA_WAIT_TIMEOUT within
 *     200 ms.
 *   - A 300 ms timeout returns WSA_WAIT_TIMEOUT and elapsed time is at least
 *     250 ms (tolerance for timer granularity).
 *   - A socket associated with FD_READ that has no data also times out at
 *     300 ms.
 *   - Waiting on a closed event handle returns WSA_WAIT_FAILED and
 *     WSAGetLastError() == ERROR_INVALID_HANDLE (6).
 *
 * Source: curl lib/multi.c:1409-1410 (WSAWaitForMultipleEvents with the
 *   caller's timeout_ms; a timeout is not an error here and must fall
 *   through to the WSAEnumNetworkEvents loop).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "wsawait_timeout"

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
  WSAEVENT ev = WSA_INVALID_EVENT, dead;
  SOCKET srv = INVALID_SOCKET, cli = INVALID_SOCKET;
  ULONGLONG t0, t1;
  DWORD w;
  int e, rc = 0;

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) {
    snprintf(msg, msz, "WSAStartup failed: %d", e);
    return 1;
  }

  ev = WSACreateEvent();
  CHECK(ev != WSA_INVALID_EVENT, "WSACreateEvent failed: %d", WSAGetLastError());

  /* (a) zero timeout returns immediately. */
  t0 = GetTickCount64();
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  t1 = GetTickCount64();
  CHECK(w == WSA_WAIT_TIMEOUT, "zero timeout: expected WSA_WAIT_TIMEOUT, got %lu",
        (unsigned long)w);
  CHECK(t1 - t0 < 200, "zero timeout took %llu ms", (unsigned long long)(t1 - t0));

  /* (b) a 300 ms timeout must actually wait about that long. */
  t0 = GetTickCount64();
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 300, FALSE);
  t1 = GetTickCount64();
  CHECK(w == WSA_WAIT_TIMEOUT, "300 ms wait: expected WSA_WAIT_TIMEOUT, got %lu",
        (unsigned long)w);
  CHECK(t1 - t0 >= 250, "300 ms wait returned after only %llu ms",
        (unsigned long long)(t1 - t0));

  /* (c) a socket event with no data does not end the wait early. */
  e = make_pair(&srv, &cli);
  if(e) {
    if(is_absent(e)) {
      snprintf(msg, msz, "no loopback TCP (err %d)", e);
      rc = 77;
      goto done;
    }
    CHECK(0, "loopback pair setup failed: %d", e);
  }
  CHECK(WSAEventSelect(srv, ev, FD_READ | FD_CLOSE) == 0,
        "WSAEventSelect failed: %d", WSAGetLastError());
  t0 = GetTickCount64();
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 300, FALSE);
  t1 = GetTickCount64();
  CHECK(w == WSA_WAIT_TIMEOUT,
        "socket with no data: expected WSA_WAIT_TIMEOUT, got %lu",
        (unsigned long)w);
  CHECK(t1 - t0 >= 250, "socket wait returned after only %llu ms",
        (unsigned long long)(t1 - t0));
  CHECK(WSAEventSelect(srv, ev, 0) == 0, "WSAEventSelect(0) failed");

  /* (d) failure path: a closed event handle is rejected. */
  dead = WSACreateEvent();
  CHECK(dead != WSA_INVALID_EVENT, "WSACreateEvent(dead) failed");
  CHECK(WSACloseEvent(dead), "WSACloseEvent(dead) failed");
  w = WSAWaitForMultipleEvents(1, &dead, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_FAILED, "closed handle: expected WSA_WAIT_FAILED, got %lu",
        (unsigned long)w);
  CHECK(WSAGetLastError() == ERROR_INVALID_HANDLE,
        "closed handle: WSAGetLastError=%d, expected ERROR_INVALID_HANDLE (6)",
        WSAGetLastError());

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
