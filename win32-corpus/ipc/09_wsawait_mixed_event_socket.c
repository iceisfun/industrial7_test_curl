/*
 * Test: wsawait_mixed_event_socket
 *
 * Purpose: put an ordinary kernel waitable event (CreateEvent) and a socket
 *   WSA event in one wait set, the way a curl embedder combines its own
 *   wakeup object with curl's socket events. Verifies index mapping, the
 *   lowest-index rule when several handles are signaled, fWaitAll semantics,
 *   and that a socket event stays signaled until WSAEnumNetworkEvents.
 *
 * APIs: CreateEventW, SetEvent, ResetEvent, CloseHandle, WSACreateEvent,
 *       WSAEventSelect, WSAEnumNetworkEvents, WSAWaitForMultipleEvents,
 *       socket/bind/listen/connect/accept, send, recv.
 *
 * Success means:
 *   P1 nothing signaled: zero-timeout wait -> WSA_WAIT_TIMEOUT.
 *   P2 only the kernel event set: wait -> WSA_WAIT_EVENT_0 (index 0).
 *   P3 only socket data pending: wait -> WSA_WAIT_EVENT_0 + 1, and
 *      enumeration reports FD_READ.
 *   P4 both signaled: wait -> WSA_WAIT_EVENT_0 (lowest index wins). After
 *      resetting the kernel event and without enumerating, the socket index
 *      is still reported (WSA_WAIT_EVENT_0 + 1).
 *   P5 fWaitAll=TRUE: returns WSA_WAIT_TIMEOUT while only one handle is set
 *      and WSA_WAIT_EVENT_0 once both are set.
 *
 * Source: curl lib/multi.c:1409 (WSA wait set holds only curl's wsa_event;
 *   embedders with their own handle combine it the same way),
 *   lib/multi.c:1423-1433 and 1454-1460 (enumeration consumes the socket
 *   event before the next wait).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "wsawait_mixed_event_socket"

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
  HANDLE kev = NULL;
  WSAEVENT sev = WSA_INVALID_EVENT;
  WSAEVENT handles[2];
  WSANETWORKEVENTS ne;
  DWORD w;
  char c = 'a';
  int e, rc = 0;

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

  kev = CreateEventW(NULL, TRUE, FALSE, NULL); /* manual reset */
  CHECK(kev != NULL, "CreateEventW failed: %lu", (unsigned long)GetLastError());
  sev = WSACreateEvent();
  CHECK(sev != WSA_INVALID_EVENT, "WSACreateEvent failed: %d", WSAGetLastError());
  CHECK(WSAEventSelect(srv, sev, FD_READ | FD_CLOSE) == 0,
        "WSAEventSelect failed: %d", WSAGetLastError());

  handles[0] = (WSAEVENT)kev;
  handles[1] = sev;

  /* P1: nothing signaled. */
  w = WSAWaitForMultipleEvents(2, handles, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT, "P1: expected WSA_WAIT_TIMEOUT, got %lu",
        (unsigned long)w);

  /* P2: kernel event only -> index 0. */
  CHECK(SetEvent(kev), "SetEvent failed: %lu", (unsigned long)GetLastError());
  w = WSAWaitForMultipleEvents(2, handles, FALSE, 1000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0, "P2: expected index 0, got %lu",
        (unsigned long)w);
  CHECK(ResetEvent(kev), "ResetEvent failed");

  /* P3: socket data only -> index 1. */
  CHECK(send(cli, &c, 1, 0) == 1, "send failed: %d", WSAGetLastError());
  w = WSAWaitForMultipleEvents(2, handles, FALSE, 2000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0 + 1,
        "P3: expected index 1 (socket), got %lu (err=%d)", (unsigned long)w,
        WSAGetLastError());
  memset(&ne, 0, sizeof(ne));
  CHECK(WSAEnumNetworkEvents(srv, sev, &ne) == 0,
        "P3: WSAEnumNetworkEvents failed: %d", WSAGetLastError());
  CHECK(ne.lNetworkEvents & FD_READ, "P3: lNetworkEvents lacks FD_READ");
  {
    char got = 0;
    CHECK(recv(srv, &got, 1, 0) == 1 && got == 'a',
          "P3: recv did not return the byte");
  }

  /* P4: both signaled -> lowest index (kernel event) wins. The socket still
     has a fresh byte and its event is not enumerated, so it stays set. */
  c = 'b';
  CHECK(send(cli, &c, 1, 0) == 1, "send(P4) failed: %d", WSAGetLastError());
  Sleep(50);
  CHECK(SetEvent(kev), "SetEvent(P4) failed");
  w = WSAWaitForMultipleEvents(2, handles, FALSE, 2000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0, "P4: expected index 0 (lowest), got %lu",
        (unsigned long)w);
  CHECK(ResetEvent(kev), "ResetEvent(P4) failed");
  w = WSAWaitForMultipleEvents(2, handles, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0 + 1,
        "P4: socket event should still be signaled, got %lu", (unsigned long)w);
  memset(&ne, 0, sizeof(ne));
  CHECK(WSAEnumNetworkEvents(srv, sev, &ne) == 0, "P4: enumerate failed");
  {
    char got = 0;
    CHECK(recv(srv, &got, 1, 0) == 1 && got == 'b',
          "P4: recv did not return 'b'");
  }

  /* P5: fWaitAll=TRUE needs both handles signaled at once. */
  c = 'c';
  CHECK(send(cli, &c, 1, 0) == 1, "send(P5) failed: %d", WSAGetLastError());
  w = WSAWaitForMultipleEvents(1, &sev, FALSE, 2000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0, "P5: socket did not signal (%lu)",
        (unsigned long)w);
  w = WSAWaitForMultipleEvents(2, handles, TRUE, 300, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT,
        "P5: fWaitAll with one handle set: expected WSA_WAIT_TIMEOUT, got %lu",
        (unsigned long)w);
  CHECK(SetEvent(kev), "SetEvent(P5) failed");
  w = WSAWaitForMultipleEvents(2, handles, TRUE, 2000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0,
        "P5: fWaitAll with both set: expected WSA_WAIT_EVENT_0, got %lu",
        (unsigned long)w);
  CHECK(ResetEvent(kev), "ResetEvent(P5) failed");

done:
  if(cli != INVALID_SOCKET)
    closesocket(cli);
  if(srv != INVALID_SOCKET)
    closesocket(srv);
  if(sev != WSA_INVALID_EVENT)
    WSACloseEvent(sev);
  if(kev)
    CloseHandle(kev);
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
