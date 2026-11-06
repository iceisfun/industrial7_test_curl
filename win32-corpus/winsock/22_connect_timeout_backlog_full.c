/*
 * Test: 22_connect_timeout_backlog_full
 * Purpose: curl's connect timeout (CURLOPT_CONNECTTIMEOUT_MS) is a
 *          non-blocking connect() plus select/WSAPoll with a deadline. A
 *          deterministic way to get a connect that neither succeeds nor is
 *          refused, without any network: a loopback listener with backlog 1
 *          that never accepts. Once the queue is full the SYN is dropped and
 *          the next connect stays in progress.
 * APIs: connect (non-blocking), select, WSAPoll, SO_CONNECT_TIME, closesocket, accept.
 * Success: some connect attempt stays pending for the whole wait window; select
 *          returns 0 after about the timeout; WSAPoll returns 0 with revents 0;
 *          SO_CONNECT_TIME is 0xFFFFFFFF (not connected); the pending socket
 *          can be closed; after the listener accepts, a fresh connect succeeds.
 * Source: lib/connect.c, lib/cf-socket.c (connect timeout, Curl_socket_check).
 */
#define TEST_NAME "22_connect_timeout_backlog_full"
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define INFO(...) do { printf("INFO "); printf(__VA_ARGS__); printf("\n"); } while (0)
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); g_fail = 1; goto out; } while (0)
static __attribute__((unused)) int g_fail;
static __attribute__((unused)) SOCKET lis_loop(int backlog, unsigned short *port) {
  struct sockaddr_in a;
  int l = sizeof(a);
  SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == INVALID_SOCKET) return s;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(s, (struct sockaddr *)&a, sizeof(a)) || listen(s, backlog) || getsockname(s, (struct sockaddr *)&a, &l)) {
    closesocket(s);
    return INVALID_SOCKET;
  }
  *port = ntohs(a.sin_port);
  return s;
}
static __attribute__((unused)) struct sockaddr_in loop_addr(unsigned short port) {
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  return a;
}

static double now_ms(void) {
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
}

int main(void) {
  WSADATA wd;
  SOCKET ls = INVALID_SOCKET, s[16], pend = INVALID_SOCKET, fresh = INVALID_SOCKET;
  unsigned short port;
  struct sockaddr_in sa;
  unsigned long nb = 1;
  int i, r, e, n = 0, pend_idx = -1;
  double t0, dt;
  fd_set ws_, es_;
  struct timeval tv;
  WSAPOLLFD pfd;
  DWORD ct;
  int ol = sizeof(ct);

  for (i = 0; i < 16; i++) s[i] = INVALID_SOCKET;
  if (WSAStartup(MAKEWORD(2, 2), &wd)) { printf("FAIL %s: WSAStartup\n", TEST_NAME); return 1; }
  ls = lis_loop(1, &port);
  if (ls == INVALID_SOCKET) FAILF("listener");
  sa = loop_addr(port);
  for (i = 0; i < 16; i++) {
    s[i] = socket(AF_INET, SOCK_STREAM, 0);
    ioctlsocket(s[i], FIONBIO, &nb);
    r = connect(s[i], (struct sockaddr *)&sa, sizeof(sa));
    e = WSAGetLastError();
    if (r == 0) { INFO("connect %d completed at once", i); n++; continue; }
    if (e != WSAEWOULDBLOCK) FAILF("connect %d err %d", i, e);
    FD_ZERO(&ws_); FD_ZERO(&es_); FD_SET(s[i], &ws_); FD_SET(s[i], &es_);
    tv.tv_sec = 0; tv.tv_usec = 300000;
    r = select(0, NULL, &ws_, &es_, &tv);
    if (r == 0) { pend_idx = i; INFO("connect %d still pending after 300 ms (after %d completed)", i, n); break; }
    INFO("connect %d: select r=%d writable=%d except=%d", i, r, FD_ISSET(s[i], &ws_) ? 1 : 0, FD_ISSET(s[i], &es_) ? 1 : 0);
    n++;
  }
  if (pend_idx < 0) FAILF("no connect stayed pending with a full backlog (16 tried)");
  pend = s[pend_idx];

  /* deadline wait */
  FD_ZERO(&ws_); FD_ZERO(&es_); FD_SET(pend, &ws_); FD_SET(pend, &es_);
  tv.tv_sec = 0; tv.tv_usec = 600000;
  t0 = now_ms();
  r = select(0, NULL, &ws_, &es_, &tv);
  dt = now_ms() - t0;
  INFO("select 600 ms on pending connect: r=%d %.0f ms", r, dt);
  if (r != 0) FAILF("select returned %d", r);
  if (dt < 550.0 || dt > 1500.0) FAILF("select took %.0f ms", dt);
  pfd.fd = pend; pfd.events = POLLWRNORM; pfd.revents = 0;
  t0 = now_ms();
  r = WSAPoll(&pfd, 1, 400);
  dt = now_ms() - t0;
  INFO("WSAPoll 400 ms: r=%d revents=0x%x %.0f ms", r, pfd.revents, dt);
  if (r != 0 || pfd.revents != 0) FAILF("WSAPoll r=%d revents=0x%x", r, pfd.revents);
  if (dt < 350.0 || dt > 1500.0) FAILF("WSAPoll took %.0f ms", dt);
  ct = 0; r = getsockopt(pend, SOL_SOCKET, SO_CONNECT_TIME, (char *)&ct, &ol);
  INFO("SO_CONNECT_TIME on pending: r=%d value=0x%lx", r, (unsigned long)ct);
  if (r || ct != 0xFFFFFFFF) FAILF("SO_CONNECT_TIME r=%d ct=0x%lx", r, (unsigned long)ct);
  {
    int soerr = 0; ol = sizeof(soerr);
    r = getsockopt(pend, SOL_SOCKET, SO_ERROR, (char *)&soerr, &ol);
    INFO("SO_ERROR on pending: r=%d value=%d", r, soerr);
    if (r || soerr != 0) FAILF("SO_ERROR r=%d value=%d", r, soerr);
  }
  /* abandon it like curl does on timeout */
  r = closesocket(pend); s[pend_idx] = INVALID_SOCKET;
  if (r) FAILF("closesocket pending %d", WSAGetLastError());
  /* free the queue: accept what is established, then a new connect completes */
  for (;;) {
    fd_set rs;
    SOCKET a;
    FD_ZERO(&rs); FD_SET(ls, &rs);
    tv.tv_sec = 0; tv.tv_usec = 100000;
    if (select(0, &rs, NULL, NULL, &tv) <= 0) break;
    a = accept(ls, NULL, NULL);
    if (a == INVALID_SOCKET) break;
    closesocket(a);
  }
  fresh = socket(AF_INET, SOCK_STREAM, 0);
  ioctlsocket(fresh, FIONBIO, &nb);
  r = connect(fresh, (struct sockaddr *)&sa, sizeof(sa));
  e = WSAGetLastError();
  if (r != 0 && e != WSAEWOULDBLOCK) FAILF("fresh connect %d", e);
  FD_ZERO(&ws_); FD_SET(fresh, &ws_);
  tv.tv_sec = 5; tv.tv_usec = 0;
  r = select(0, NULL, &ws_, NULL, &tv);
  INFO("fresh connect after draining: select r=%d", r);
  if (r != 1) FAILF("fresh connect did not complete (select %d)", r);
  printf("PASS %s\n", TEST_NAME);
out:
  for (i = 0; i < 16; i++) if (s[i] != INVALID_SOCKET) closesocket(s[i]);
  if (fresh != INVALID_SOCKET) closesocket(fresh);
  if (ls != INVALID_SOCKET) closesocket(ls);
  WSACleanup();
  return g_fail;
}
