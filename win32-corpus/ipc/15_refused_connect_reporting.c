/*
 * Test: 15_refused_connect_reporting
 *
 * Purpose: how a nonblocking connect to a closed loopback port is reported
 *   through the readiness APIs curl uses (select exceptfds, WSAPoll,
 *   SO_ERROR). On Win10 22H2 the failure is NOT immediate: the stack retries
 *   and the failure is reported after about 2 s (probed over 20 runs, std
 *   and adm: 2015 .. 2609 ms, always 2.0 s or more), with the same result in
 *   every run. A caller's connect-poll timeout shorter than ~2.1 s therefore
 *   never sees the refusal (the cause of the old curlsupport/14 failure).
 *
 * Success, for each of select() and WSAPoll(), 3 rounds each:
 *   - connect returns SOCKET_ERROR / WSAEWOULDBLOCK (10035).
 *   - select with a 200 ms timeout: 0 ready (nothing is reported early);
 *     then select with a 6 s timeout: 1 ready, the socket is in exceptfds
 *     and NOT in writefds, after 1.9 .. 4.5 s.
 *   - WSAPoll(POLLOUT, 200 ms): 0 ready; then WSAPoll(6 s): 1 ready with
 *     revents == POLLERR|POLLHUP|POLLWRNORM (0x13), after 1.9 .. 4.5 s.
 *   - SO_ERROR is then WSAECONNREFUSED (10061); a second read still gives 10061
 *     (a failed connect's SO_ERROR is not cleared by reading it on Windows).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "refused_connect_reporting"
#define CHECK(cond, ...) do { if(!(cond)) { snprintf(msg, msz, __VA_ARGS__); rc = 1; goto done; } } while(0)

static int dead_port(struct sockaddr_in *sa)
{
  int len = sizeof(*sa);
  SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(l == INVALID_SOCKET)
    return WSAGetLastError();
  memset(sa, 0, sizeof(*sa));
  sa->sin_family = AF_INET;
  sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(bind(l, (struct sockaddr *)sa, sizeof(*sa)) || getsockname(l, (struct sockaddr *)sa, &len)) {
    int e = WSAGetLastError();
    closesocket(l);
    return e;
  }
  closesocket(l);
  return 0;
}

static int body(char *msg, size_t msz)
{
  WSADATA wd;
  struct sockaddr_in sa;
  SOCKET c = INVALID_SOCKET;
  int rc = 0, e, r, round, mode, so, sl;
  u_long one = 1;
  ULONGLONG t0, dt;
  fd_set w, x;
  struct timeval tv;
  WSAPOLLFD pf;

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) { snprintf(msg, msz, "WSAStartup failed: %d", e); return 1; }

  for(mode = 0; mode < 2; mode++) {
    for(round = 0; round < 3; round++) {
      e = dead_port(&sa);
      CHECK(e == 0, "dead port setup failed: %d", e);
      c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      CHECK(c != INVALID_SOCKET, "socket failed %d", WSAGetLastError());
      ioctlsocket(c, FIONBIO, &one);
      r = connect(c, (struct sockaddr *)&sa, sizeof(sa));
      CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK,
            "connect: r=%d err=%d, expected WSAEWOULDBLOCK", r, WSAGetLastError());

      if(mode == 0) {
        FD_ZERO(&w); FD_ZERO(&x); FD_SET(c, &w); FD_SET(c, &x);
        tv.tv_sec = 0; tv.tv_usec = 200000;
        r = select(0, NULL, &w, &x, &tv);
        CHECK(r == 0, "select(200 ms) reported %d early", r);
        FD_ZERO(&w); FD_ZERO(&x); FD_SET(c, &w); FD_SET(c, &x);
        tv.tv_sec = 6; tv.tv_usec = 0;
        t0 = GetTickCount64();
        r = select(0, NULL, &w, &x, &tv);
        dt = GetTickCount64() - t0;
        CHECK(r == 1 && FD_ISSET(c, &x) && !FD_ISSET(c, &w),
              "select: r=%d except=%d write=%d", r, FD_ISSET(c, &x) != 0, FD_ISSET(c, &w) != 0);
      }
      else {
        pf.fd = c; pf.events = POLLOUT; pf.revents = 0;
        r = WSAPoll(&pf, 1, 200);
        CHECK(r == 0, "WSAPoll(200 ms) reported %d early (revents 0x%x)", r, pf.revents);
        t0 = GetTickCount64();
        r = WSAPoll(&pf, 1, 6000);
        dt = GetTickCount64() - t0;
        CHECK(r == 1 && pf.revents == (POLLERR | POLLHUP | POLLWRNORM),
              "WSAPoll: r=%d revents=0x%x, expected 1/0x13", r, pf.revents);
      }
      /* the first 200 ms were already spent: the total is 2.0 s+ */
      CHECK(dt + 200 >= 1900 && dt < 4500, "refusal reported after %llu ms (+200), expected 1.9..4.5 s",
            (unsigned long long)dt);

      so = -1; sl = sizeof(so);
      CHECK(getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&so, &sl) == 0 && so == WSAECONNREFUSED,
            "SO_ERROR=%d, expected WSAECONNREFUSED", so);
      so = -1; sl = sizeof(so);
      getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&so, &sl);
      CHECK(so == WSAECONNREFUSED, "SO_ERROR second read=%d, expected 10061 (sticky)", so);
      closesocket(c);
      c = INVALID_SOCKET;
    }
  }

done:
  if(c != INVALID_SOCKET) closesocket(c);
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
  else
    printf("FAIL %s: %s\n", TEST_NAME, msg);
  return rc;
}
