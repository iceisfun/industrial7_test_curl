/*
 * Test: wsaeventselect_fd_write_connect
 *
 * Purpose: verify the connect-completion and writability notifications that
 *   curl's multi wait relies on for POLLOUT. Phase A: a nonblocking connect
 *   to a live loopback listener, associated with FD_WRITE|FD_CONNECT|FD_CLOSE
 *   (the exact mask curl uses), signals FD_CONNECT with no error, and FD_WRITE
 *   is re-posted after a WSAEWOULDBLOCK send is drained. Phase B (failure path):
 *   a nonblocking connect to a loopback port with no listener signals
 *   FD_CONNECT with iErrorCode == WSAECONNREFUSED.
 *
 * APIs: socket, bind, listen, getsockname, connect (nonblocking after
 *       association), accept, send, WSACreateEvent, WSAEventSelect,
 *       WSAEnumNetworkEvents, WSAWaitForMultipleEvents, WSACloseEvent.
 *
 * Success means:
 *   Phase A: connect returns SOCKET_ERROR/WSAEWOULDBLOCK (or 0 if it
 *     completes synchronously); the event is signaled within 3 s; the
 *     enumeration is exactly FD_CONNECT|FD_WRITE with FD_CONNECT error 0. Probed on Win10 22H2: a
 *     zero-byte send (curl's reset_socket_fdwrite) followed by re-association
 *     with FD_WRITE|FD_CLOSE does NOT re-post a consumed FD_WRITE (three
 *     rounds time out). FD_WRITE is re-posted only after send() hit
 *     WSAEWOULDBLOCK and the peer drained the buffer; the enumeration then
 *     yields exactly FD_WRITE with error 0. Then send() of 1 byte works.
 *   Phase B: the event is signaled and FD_CONNECT carries
 *     iErrorCode == WSAECONNREFUSED (10061).
 *
 * Source: curl lib/multi.c:1384-1389 (POLLOUT maps to
 *   FD_WRITE|FD_CONNECT|FD_CLOSE), lib/multi.c:1387 (reset_socket_fdwrite
 *   runs before WSAEventSelect), lib/multi.c:1354-1359 (reset_socket_fdwrite
 *   itself: a zero-byte send(), which is what re-arms FD_WRITE).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "wsaeventselect_fd_write_connect"

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

/* Bind a loopback listener on an ephemeral port and return its address. */
static int make_listener(SOCKET *l, struct sockaddr_in *sa)
{
  int salen = sizeof(*sa), e;

  *l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(*l == INVALID_SOCKET)
    return WSAGetLastError();
  memset(sa, 0, sizeof(*sa));
  sa->sin_family = AF_INET;
  sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa->sin_port = 0;
  if(bind(*l, (struct sockaddr *)sa, sizeof(*sa)) == SOCKET_ERROR ||
     listen(*l, 4) == SOCKET_ERROR ||
     getsockname(*l, (struct sockaddr *)sa, &salen) == SOCKET_ERROR) {
    e = WSAGetLastError();
    closesocket(*l);
    *l = INVALID_SOCKET;
    return e;
  }
  return 0;
}

static int body(char *msg, size_t msz)
{
  WSADATA wd;
  SOCKET l = INVALID_SOCKET, c = INVALID_SOCKET, a = INVALID_SOCKET;
  struct sockaddr_in sa;
  WSAEVENT ev = WSA_INVALID_EVENT;
  WSANETWORKEVENTS ne;
  DWORD w;
  int e, rc = 0, cr;
  SOCKET dead = INVALID_SOCKET;
  struct sockaddr_in dsa;
  int dsalen = sizeof(dsa);

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) {
    snprintf(msg, msz, "WSAStartup failed: %d", e);
    return 1;
  }

  e = make_listener(&l, &sa);
  if(e) {
    WSACleanup();
    if(is_absent(e)) {
      snprintf(msg, msz, "no loopback TCP (err %d)", e);
      return 77;
    }
    snprintf(msg, msz, "listener setup failed: %d", e);
    return 1;
  }

  /* ---- Phase A: successful nonblocking connect ---- */
  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  CHECK(c != INVALID_SOCKET, "socket failed: %d", WSAGetLastError());

  ev = WSACreateEvent();
  CHECK(ev != WSA_INVALID_EVENT, "WSACreateEvent failed: %d", WSAGetLastError());

  /* curl associates FD_WRITE|FD_CONNECT|FD_CLOSE for POLLOUT. */
  CHECK(WSAEventSelect(c, ev, FD_WRITE | FD_CONNECT | FD_CLOSE) == 0,
        "WSAEventSelect(connect mask) failed: %d", WSAGetLastError());

  cr = connect(c, (struct sockaddr *)&sa, sizeof(sa));
  if(cr == SOCKET_ERROR) {
    CHECK(WSAGetLastError() == WSAEWOULDBLOCK,
          "nonblocking connect: expected WSAEWOULDBLOCK, got %d",
          WSAGetLastError());
  }

  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 3000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0,
        "connect completion: expected WSA_WAIT_EVENT_0, got %lu (err=%d)",
        (unsigned long)w, WSAGetLastError());

  memset(&ne, 0, sizeof(ne));
  CHECK(WSAEnumNetworkEvents(c, ev, &ne) == 0,
        "WSAEnumNetworkEvents failed: %d", WSAGetLastError());
  CHECK(ne.lNetworkEvents & FD_CONNECT,
        "lNetworkEvents=0x%lx lacks FD_CONNECT",
        (unsigned long)ne.lNetworkEvents);
  CHECK(ne.iErrorCode[FD_CONNECT_BIT] == 0,
        "FD_CONNECT iErrorCode=%d, expected 0",
        ne.iErrorCode[FD_CONNECT_BIT]);

  a = accept(l, NULL, NULL);
  CHECK(a != INVALID_SOCKET, "accept failed: %d", WSAGetLastError());

  /* Probed on Win10 22H2 (build 19045, 20 runs x 6 variants): neither a
     zero-byte send() nor re-calling WSAEventSelect on a writable socket
     re-posts FD_WRITE once it was consumed. FD_WRITE is re-posted only after
     a send() hit WSAEWOULDBLOCK and buffer space returns. */
  /* FD_WRITE is delivered together with FD_CONNECT in the same enumeration
     (lNetworkEvents == FD_CONNECT|FD_WRITE, 0x12, every run). */
  CHECK(ne.lNetworkEvents == (FD_CONNECT | FD_WRITE),
        "connect enumeration lNetworkEvents=0x%lx, expected FD_CONNECT|FD_WRITE (0x12)",
        (unsigned long)ne.lNetworkEvents);
  {
    int i;
    WSAResetEvent(ev);
    CHECK(WSAEventSelect(c, ev, FD_WRITE | FD_CLOSE) == 0,
          "WSAEventSelect(FD_WRITE|FD_CLOSE) failed: %d", WSAGetLastError());
    w = WSAWaitForMultipleEvents(1, &ev, FALSE, 300, FALSE);
    CHECK(w == WSA_WAIT_TIMEOUT,
          "FD_WRITE already consumed by the connect enumeration must not be pending: wait=%lu",
          (unsigned long)w);
    for(i = 0; i < 3; i++) {
      CHECK(send(c, NULL, 0, 0) == 0, "zero-byte send (reset_socket_fdwrite) failed: %d",
            WSAGetLastError());
      CHECK(WSAEventSelect(c, ev, FD_WRITE | FD_CLOSE) == 0,
            "re-arm WSAEventSelect failed: %d", WSAGetLastError());
      w = WSAWaitForMultipleEvents(1, &ev, FALSE, 300, FALSE);
      CHECK(w == WSA_WAIT_TIMEOUT,
            "consumed FD_WRITE must not be re-posted by zero-byte send + "
            "WSAEventSelect (round %d): got wait=%lu", i, (unsigned long)w);
    }
  }
  /* The real re-arm: fill the send buffer until WSAEWOULDBLOCK, then let the
     peer drain it; FD_WRITE must be posted once space returns. */
  {
    static char blk[16384];
    unsigned long sent = 0;
    int n, wouldblock = 0;
    memset(blk, 'x', sizeof(blk));
    for(n = 0; n < 4096; n++) {
      int r = send(c, blk, sizeof(blk), 0);
      if(r == SOCKET_ERROR) {
        wouldblock = (WSAGetLastError() == WSAEWOULDBLOCK);
        CHECK(wouldblock, "fill: send failed with %d, expected WSAEWOULDBLOCK", WSAGetLastError());
        break;
      }
      sent += (unsigned long)r;
    }
    CHECK(wouldblock, "send buffer never filled after %lu bytes", sent);
    CHECK(sent > 0, "nothing sent before WSAEWOULDBLOCK");
    WSAResetEvent(ev);
    {
      unsigned long got = 0;
      static char rb[65536];
      DWORD t0 = GetTickCount();
      while(got < sent && GetTickCount() - t0 < 10000) {
        fd_set rs; struct timeval tv = {0, 200000};
        FD_ZERO(&rs); FD_SET(a, &rs);
        if(select(0, &rs, NULL, NULL, &tv) > 0) {
          int r = recv(a, rb, sizeof(rb), 0);
          if(r <= 0) break;
          got += (unsigned long)r;
        }
      }
      CHECK(got == sent, "peer drained %lu of %lu bytes", got, sent);
    }
    w = WSAWaitForMultipleEvents(1, &ev, FALSE, 3000, FALSE);
    CHECK(w == WSA_WAIT_EVENT_0,
          "FD_WRITE after WSAEWOULDBLOCK and drain: expected event, got %lu (err=%d)",
          (unsigned long)w, WSAGetLastError());
    memset(&ne, 0, sizeof(ne));
    CHECK(WSAEnumNetworkEvents(c, ev, &ne) == 0, "WSAEnumNetworkEvents(2) failed: %d", WSAGetLastError());
    CHECK(ne.lNetworkEvents == FD_WRITE, "lNetworkEvents=0x%lx, expected exactly FD_WRITE",
          (unsigned long)ne.lNetworkEvents);
    CHECK(ne.iErrorCode[FD_WRITE_BIT] == 0, "FD_WRITE iErrorCode=%d", ne.iErrorCode[FD_WRITE_BIT]);
  }

  CHECK(WSAEventSelect(c, ev, 0) == 0, "cancel association failed: %d",
        WSAGetLastError());
  CHECK(send(c, "x", 1, 0) == 1, "send after connect failed: %d",
        WSAGetLastError());
  closesocket(a);
  a = INVALID_SOCKET;
  closesocket(c);
  c = INVALID_SOCKET;
  WSACloseEvent(ev);
  ev = WSA_INVALID_EVENT;

  /* ---- Phase B: connect to a port with no listener (failure path) ---- */
  /* Learn a free loopback port by binding then closing a listener. */
  CHECK(make_listener(&dead, &dsa) == 0, "could not allocate dead port");
  getsockname(dead, (struct sockaddr *)&dsa, &dsalen);
  closesocket(dead);
  dead = INVALID_SOCKET;

  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  CHECK(c != INVALID_SOCKET, "socket(B) failed: %d", WSAGetLastError());
  ev = WSACreateEvent();
  CHECK(ev != WSA_INVALID_EVENT, "WSACreateEvent(B) failed");
  CHECK(WSAEventSelect(c, ev, FD_WRITE | FD_CONNECT | FD_CLOSE) == 0,
        "WSAEventSelect(B) failed: %d", WSAGetLastError());
  cr = connect(c, (struct sockaddr *)&dsa, sizeof(dsa));
  if(cr == SOCKET_ERROR) {
    CHECK(WSAGetLastError() == WSAEWOULDBLOCK,
          "refused connect: expected WSAEWOULDBLOCK, got %d",
          WSAGetLastError());
  }
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 3000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0,
        "refused connect: expected event, got %lu", (unsigned long)w);
  memset(&ne, 0, sizeof(ne));
  CHECK(WSAEnumNetworkEvents(c, ev, &ne) == 0,
        "WSAEnumNetworkEvents(B) failed: %d", WSAGetLastError());
  CHECK(ne.lNetworkEvents & FD_CONNECT, "refused: lacks FD_CONNECT");
  CHECK(ne.iErrorCode[FD_CONNECT_BIT] == WSAECONNREFUSED,
        "refused: FD_CONNECT iErrorCode=%d, expected WSAECONNREFUSED (%d)",
        ne.iErrorCode[FD_CONNECT_BIT], WSAECONNREFUSED);

done:
  if(a != INVALID_SOCKET)
    closesocket(a);
  if(c != INVALID_SOCKET)
    closesocket(c);
  if(l != INVALID_SOCKET)
    closesocket(l);
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
