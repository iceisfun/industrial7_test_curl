/*
 * Test: socketpair_wakeup_thread
 *
 * Purpose: emulate curl's socket-based wakeup pair. A loopback TCP "socketpair"
 *   (listener, connect, accept) is built, the read end is registered with
 *   WSAEventSelect(FD_READ|FD_CLOSE), and a second thread writes one byte per
 *   wakeup into the write end. The waiting thread must be woken once per byte
 *   and never miss one, across many rounds, and must not see spurious wakeups
 *   after the pipe is drained. This exercises re-arming of FD_READ after
 *   WSAEnumNetworkEvents and drain-to-EWOULDBLOCK.
 *
 * APIs: socket, bind, listen, getsockname, connect, accept, setsockopt
 *       (TCP_NODELAY), send, recv, WSACreateEvent, WSAEventSelect,
 *       WSAEnumNetworkEvents, WSAWaitForMultipleEvents, WSAResetEvent,
 *       CreateThread, WaitForSingleObject, GetExitCodeThread, CloseHandle.
 *
 * Success means:
 *   - Every wait for the wakeup returns WSA_WAIT_EVENT_0 within 5 s, until all
 *     N=25 bytes have been drained (a wait may cover several bytes, so the
 *     number of waits is at most 4*N and is not checked exactly).
 *   - Each wakeup that enumerates FD_READ has iErrorCode 0, and at least one
 *     wakeup reports FD_READ.
 *   - Draining with recv until WSAEWOULDBLOCK yields exactly N bytes in the
 *     order sent.
 *   - After the final drain, a 100 ms wait times out (no spurious wakeup).
 *   - The writer thread reports that all sends succeeded.
 *
 * Source: curl lib/socketpair.c:293-302 (Curl_wakeup_init). On Windows
 *   HAVE_SOCKETPAIR is not defined, so the wakeup pair comes from wakeup_inet()
 *   (lib/socketpair.c:302, loopback TCP built at lib/socketpair.c:160), which is
 *   the pair this test models. lib/socketpair.c:320 (Curl_wakeup_signal writes
 *   one byte to wake a poll), lib/multi.c:1697 (curl_multi_wakeup signals the
 *   WSA event; this test models the byte-write path, not that call).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "socketpair_wakeup_thread"
#define NWAKE 25

#define CHECK(c, ...)                                  \
  do {                                                 \
    if(!(c)) {                                         \
      snprintf(msg, msz, __VA_ARGS__);                 \
      rc = 1;                                          \
      goto done;                                       \
    }                                                  \
  } while(0)

struct writer_arg {
  SOCKET w;
  int count;
};

static DWORD WINAPI writer_thread(LPVOID p)
{
  struct writer_arg *a = (struct writer_arg *)p;
  int i;
  for(i = 0; i < a->count; i++) {
    char b = (char)('A' + (i % 26));
    Sleep(8);
    if(send(a->w, &b, 1, 0) != 1)
      return 1;
  }
  return 0;
}

static int make_pair(SOCKET *srv, SOCKET *cli)
{
  struct sockaddr_in sa;
  int salen = sizeof(sa);
  BOOL on = TRUE;
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
  setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(on));
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
  setsockopt(a, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(on));
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
  SOCKET rd = INVALID_SOCKET, wr = INVALID_SOCKET;
  WSAEVENT ev = WSA_INVALID_EVENT;
  WSANETWORKEVENTS ne;
  struct writer_arg wa;
  HANDLE th = NULL;
  DWORD w, code = 99;
  char buf[64];
  int e, n, total = 0, fdread_seen = 0, rc = 0, i;

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) {
    snprintf(msg, msz, "WSAStartup failed: %d", e);
    return 1;
  }

  e = make_pair(&rd, &wr);
  if(e) {
    WSACleanup();
    if(is_absent(e)) {
      snprintf(msg, msz, "no loopback TCP (err %d)", e);
      return 77;
    }
    snprintf(msg, msz, "wakeup socketpair setup failed: %d", e);
    return 1;
  }

  ev = WSACreateEvent();
  CHECK(ev != WSA_INVALID_EVENT, "WSACreateEvent failed: %d", WSAGetLastError());
  CHECK(WSAEventSelect(rd, ev, FD_READ | FD_CLOSE) == 0,
        "WSAEventSelect(read end) failed: %d", WSAGetLastError());

  wa.w = wr;
  wa.count = NWAKE;
  th = CreateThread(NULL, 0, writer_thread, &wa, 0, NULL);
  CHECK(th != NULL, "CreateThread failed: %lu", (unsigned long)GetLastError());

  /* Wake once per byte; drain fully each time. */
  for(i = 0; total < NWAKE && i < NWAKE * 4; i++) {
    w = WSAWaitForMultipleEvents(1, &ev, FALSE, 5000, FALSE);
    CHECK(w == WSA_WAIT_EVENT_0,
          "wakeup after %d bytes: expected WSA_WAIT_EVENT_0, got %lu (err=%d)",
          total, (unsigned long)w, WSAGetLastError());

    memset(&ne, 0, sizeof(ne));
    CHECK(WSAEnumNetworkEvents(rd, ev, &ne) == 0,
          "WSAEnumNetworkEvents failed: %d", WSAGetLastError());
    if(ne.lNetworkEvents & FD_READ) {
      CHECK(ne.iErrorCode[FD_READ_BIT] == 0,
            "wakeup %d: FD_READ iErrorCode=%d", total,
            ne.iErrorCode[FD_READ_BIT]);
      fdread_seen++;
    }

    /* Drain everything that is available. A wakeup can be a leftover from
       bytes that the previous drain already consumed; that yields got == 0
       and simply costs one loop iteration. Totals are checked at the end. */
    for(;;) {
      n = recv(rd, buf, sizeof(buf), 0);
      if(n == SOCKET_ERROR) {
        CHECK(WSAGetLastError() == WSAEWOULDBLOCK,
              "drain: recv failed with %d", WSAGetLastError());
        break;
      }
      CHECK(n > 0, "drain: unexpected EOF on wakeup pipe (n=%d)", n);
      {
        int j;
        for(j = 0; j < n; j++) {
          char want = (char)('A' + ((total + j) % 26));
          CHECK(buf[j] == want, "byte %d: got '%c', expected '%c'",
                total + j, buf[j], want);
        }
      }
      total += n;
    }
  }

  CHECK(total == NWAKE, "received %d wakeup bytes, expected %d", total, NWAKE);
  CHECK(fdread_seen > 0, "no wakeup ever reported FD_READ");

  /* No spurious wakeup once drained (the writer has finished). */
  CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0,
        "writer thread did not finish");
  CHECK(GetExitCodeThread(th, &code) && code == 0,
        "writer thread failed (exit %lu)", (unsigned long)code);
  CloseHandle(th);
  th = NULL;

  /* The last byte may have re-set the event while the drain was running;
     clear it the way curl does (WSAEnumNetworkEvents) and then require that
     nothing else signals it. */
  memset(&ne, 0, sizeof(ne));
  CHECK(WSAEnumNetworkEvents(rd, ev, &ne) == 0,
        "final WSAEnumNetworkEvents failed: %d", WSAGetLastError());
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 100, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT,
        "after drain: expected WSA_WAIT_TIMEOUT (no spurious wakeup), got %lu",
        (unsigned long)w);

done:
  if(th)
    CloseHandle(th);
  if(ev != WSA_INVALID_EVENT)
    WSACloseEvent(ev);
  if(rd != INVALID_SOCKET)
    closesocket(rd);
  if(wr != INVALID_SOCKET)
    closesocket(wr);
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
