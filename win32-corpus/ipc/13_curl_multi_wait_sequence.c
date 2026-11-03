/*
 * Test: curl_multi_wait_sequence
 *
 * Purpose: run the exact Winsock event sequence of curl's multi_winsock_select()
 *   over real loopback sockets, round by round, and check the nevents and
 *   per-socket network event results curl derives from it:
 *     1. associate sockets with WSAEventSelect (POLLIN -> FD_READ|FD_ACCEPT|
 *        FD_CLOSE, POLLOUT -> FD_WRITE|FD_CONNECT|FD_CLOSE),
 *     2. pre-check with WSAPoll(timeout 0); if nothing is ready, block in
 *        WSAWaitForMultipleEvents(timeout),
 *     3. for every socket WSAEnumNetworkEvents then WSAEventSelect(s, ev, 0),
 *     4. WSAResetEvent on the shared event.
 *   Rounds: writable socket ready at once (pre-check path); quiet socket times
 *   out (no events); data arrives during the wait (wait path); peer close
 *   (FD_CLOSE mapped to POLLIN). Each round must leave the shared event
 *   unsignaled afterwards.
 *
 * APIs: socket, bind, listen, getsockname, connect, accept, send, recv,
 *       closesocket, WSACreateEvent, WSAEventSelect, WSAPoll,
 *       WSAWaitForMultipleEvents, WSAEnumNetworkEvents, WSAResetEvent,
 *       WSACloseEvent, CreateThread, WaitForSingleObject, GetTickCount64.
 *
 * Success means:
 *   R1 (pre-check): WSAPoll returns 1 (only the writable socket), nevents==1,
 *      netev for the writable socket has FD_WRITE, the read socket has 0.
 *   R2 (timeout): quiet read socket, 100 ms: nevents==0, no events, and the
 *      wait took at least 80 ms.
 *   R3 (pre-check after data): byte already queued: nevents==1 and FD_READ
 *      reported for the read socket.
 *   R4 (wait path): byte sent 100 ms later by another thread: nevents==1,
 *      FD_READ reported, and the wait took at least 80 ms.
 *   R5 (quiet again): nevents==0 with a 100 ms timeout.
 *   R6 (failure path): peer closes: nevents==1 and FD_CLOSE reported.
 *   After every round WSAWaitForMultipleEvents(0) on the shared event times
 *   out (the shared event was reset).
 *
 * Source: curl lib/multi.c:1369-1466 (multi_winsock_select: the WSAEventSelect
 *   mask at 1384-1389 with reset_socket_fdwrite() at 1387, the Curl_poll
 *   pre-check at 1398-1404, the WSAWaitForMultipleEvents wait at 1409-1410,
 *   enumeration at 1423 and 1454, WSAEventSelect(s, ev, 0) at 1433 and 1458,
 *   WSAResetEvent at 1460). WSAPoll is called directly here as the pre-check
 *   primitive; curl reaches it through Curl_poll (lib/select.c:199), whose
 *   Windows mapping to WSAPoll is not shown in lib/ and is not tested here.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "curl_multi_wait_sequence"

#define CHECK(c, ...)                                  \
  do {                                                 \
    if(!(c)) {                                         \
      snprintf(msg, msz, __VA_ARGS__);                 \
      rc = 1;                                          \
      goto done;                                       \
    }                                                  \
  } while(0)

struct sender_arg {
  SOCKET s;
  DWORD delay_ms;
  char byte;
};

static DWORD WINAPI sender_thread(LPVOID p)
{
  struct sender_arg *a = (struct sender_arg *)p;
  Sleep(a->delay_ms);
  return send(a->s, &a->byte, 1, 0) == 1 ? 0 : 1;
}

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

/* Mirror of curl's multi_winsock_select() for n sockets. pev holds POLLIN or
   POLLOUT per socket. Returns 0 on success, negative on an API failure. */
static int curl_wait(WSAEVENT ev, const SOCKET *socks, const short *pev, int n,
                     DWORD timeout_ms, int *nevents, long *netev)
{
  WSAPOLLFD pf[4];
  WSANETWORKEVENTS wne;
  int i, pollrc;

  for(i = 0; i < n; i++) {
    long mask = 0;
    pf[i].fd = socks[i];
    pf[i].events = pev[i];
    pf[i].revents = 0;
    if(pev[i] & POLLIN)
      mask |= FD_READ | FD_ACCEPT | FD_CLOSE;
    if(pev[i] & POLLOUT) {
      mask |= FD_WRITE | FD_CONNECT | FD_CLOSE;
      /* curl's reset_socket_fdwrite() (lib/multi.c:1354-1359): a zero-byte
         send() on a TCP socket, run before WSAEventSelect. */
      send(socks[i], NULL, 0, 0);
    }
    if(mask && WSAEventSelect(socks[i], ev, mask) == SOCKET_ERROR)
      return -1;
  }

  pollrc = WSAPoll(pf, (ULONG)n, 0);
  if(pollrc < 0)
    return -2;
  *nevents = pollrc;

  if(!pollrc) {
    DWORD w = WSAWaitForMultipleEvents(1, &ev, FALSE, timeout_ms, FALSE);
    if(w == WSA_WAIT_FAILED)
      return -3;
  }

  for(i = 0; i < n; i++) {
    netev[i] = 0;
    memset(&wne, 0, sizeof(wne));
    if(WSAEnumNetworkEvents(socks[i], NULL, &wne) == 0) {
      netev[i] = wne.lNetworkEvents;
      if(!pollrc && wne.lNetworkEvents)
        (*nevents)++;
    }
    WSAEventSelect(socks[i], ev, 0);
  }
  WSAResetEvent(ev);
  return 0;
}

static int body(char *msg, size_t msz)
{
  WSADATA wd;
  SOCKET a_srv = INVALID_SOCKET, a_cli = INVALID_SOCKET;
  SOCKET b_srv = INVALID_SOCKET, b_cli = INVALID_SOCKET;
  WSAEVENT ev = WSA_INVALID_EVENT;
  SOCKET socks[2];
  short pev[2];
  long netev[2];
  struct sender_arg sa;
  HANDLE th = NULL;
  DWORD w, code = 99;
  ULONGLONG t0, t1;
  char buf[4];
  int e, n, rc = 0;

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) {
    snprintf(msg, msz, "WSAStartup failed: %d", e);
    return 1;
  }

  e = make_pair(&a_srv, &a_cli);
  if(!e)
    e = make_pair(&b_srv, &b_cli);
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

  /* R1: pre-check path. A is quiet (POLLIN), B is writable (POLLOUT). */
  socks[0] = a_srv; pev[0] = POLLIN;
  socks[1] = b_srv; pev[1] = POLLOUT;
  n = curl_wait(ev, socks, pev, 2, 0, &e, netev);
  CHECK(n == 0, "R1: curl_wait failed with %d", n);
  CHECK(e == 1, "R1: nevents=%d, expected 1 (writable socket only)", e);
  CHECK(netev[0] == 0, "R1: read socket reported 0x%lx, expected none",
        netev[0]);
  CHECK(netev[1] & FD_WRITE, "R1: writable socket lacks FD_WRITE (0x%lx)",
        netev[1]);
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT, "R1: shared event still signaled after reset");

  /* R2: quiet read socket, real wait, nothing arrives. */
  socks[0] = a_srv; pev[0] = POLLIN;
  t0 = GetTickCount64();
  n = curl_wait(ev, socks, pev, 1, 100, &e, netev);
  t1 = GetTickCount64();
  CHECK(n == 0, "R2: curl_wait failed with %d", n);
  CHECK(e == 0, "R2: nevents=%d, expected 0", e);
  CHECK(netev[0] == 0, "R2: quiet socket reported 0x%lx", netev[0]);
  CHECK(t1 - t0 >= 80, "R2: wait returned after %llu ms, expected ~100",
        (unsigned long long)(t1 - t0));

  /* R3: byte already queued, so the pre-check reports readiness. */
  CHECK(send(a_cli, "a", 1, 0) == 1, "R3: send failed: %d", WSAGetLastError());
  Sleep(50);
  n = curl_wait(ev, socks, pev, 1, 2000, &e, netev);
  CHECK(n == 0, "R3: curl_wait failed with %d", n);
  CHECK(e == 1, "R3: nevents=%d, expected 1", e);
  CHECK(netev[0] & FD_READ, "R3: read socket lacks FD_READ (0x%lx)", netev[0]);
  CHECK(recv(a_srv, buf, sizeof(buf), 0) == 1 && buf[0] == 'a',
        "R3: recv did not return 'a'");

  /* R4: wait path. The byte is sent 100 ms after the wait starts. */
  sa.s = a_cli;
  sa.delay_ms = 100;
  sa.byte = 'b';
  th = CreateThread(NULL, 0, sender_thread, &sa, 0, NULL);
  CHECK(th != NULL, "R4: CreateThread failed: %lu", (unsigned long)GetLastError());
  t0 = GetTickCount64();
  n = curl_wait(ev, socks, pev, 1, 3000, &e, netev);
  t1 = GetTickCount64();
  CHECK(n == 0, "R4: curl_wait failed with %d", n);
  CHECK(e == 1, "R4: nevents=%d, expected 1", e);
  CHECK(netev[0] & FD_READ, "R4: read socket lacks FD_READ (0x%lx)", netev[0]);
  CHECK(t1 - t0 >= 80, "R4: returned after %llu ms, expected to wait for ~100",
        (unsigned long long)(t1 - t0));
  CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0, "R4: sender hung");
  CHECK(GetExitCodeThread(th, &code) && code == 0, "R4: sender failed");
  CloseHandle(th);
  th = NULL;
  CHECK(recv(a_srv, buf, sizeof(buf), 0) == 1 && buf[0] == 'b',
        "R4: recv did not return 'b'");

  /* R5: quiet again after the drain. */
  n = curl_wait(ev, socks, pev, 1, 100, &e, netev);
  CHECK(n == 0, "R5: curl_wait failed with %d", n);
  CHECK(e == 0 && netev[0] == 0, "R5: expected quiet (nevents=%d, ev=0x%lx)",
        e, netev[0]);

  /* R6 (failure path): the peer closes; FD_CLOSE maps to POLLIN. */
  CHECK(closesocket(a_cli) == 0, "R6: closesocket(peer) failed");
  a_cli = INVALID_SOCKET;
  n = curl_wait(ev, socks, pev, 1, 2000, &e, netev);
  CHECK(n == 0, "R6: curl_wait failed with %d", n);
  CHECK(e == 1, "R6: nevents=%d, expected 1 for peer close", e);
  CHECK(netev[0] & FD_CLOSE, "R6: read socket lacks FD_CLOSE (0x%lx)", netev[0]);
  CHECK(recv(a_srv, buf, sizeof(buf), 0) == 0, "R6: recv after close was not EOF");

done:
  if(th)
    CloseHandle(th);
  if(ev != WSA_INVALID_EVENT)
    WSACloseEvent(ev);
  if(a_srv != INVALID_SOCKET)
    closesocket(a_srv);
  if(a_cli != INVALID_SOCKET)
    closesocket(a_cli);
  if(b_srv != INVALID_SOCKET)
    closesocket(b_srv);
  if(b_cli != INVALID_SOCKET)
    closesocket(b_cli);
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
