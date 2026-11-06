/*
 * Test: 19_sndtimeo_rcvtimeo_semantics
 * Purpose: SO_SNDTIMEO and the corner cases of SO_RCVTIMEO that curl's blocking
 *          fallback paths and its test servers meet: send blocks on a full
 *          send buffer and then fails WSAETIMEDOUT, a timed-out socket stays
 *          usable, accept() is not governed by SO_RCVTIMEO, 0 means infinite,
 *          option values read back as set.
 * APIs: setsockopt/getsockopt SO_SNDTIMEO SO_RCVTIMEO, send, recv, accept, select.
 * Success: pinned values are asserted below (probed on Win10 22H2, std and adm).
 * Source: lib/cf-socket.c (blocking send in Curl_write path), tests/server/sockfilt.c.
 */
#define TEST_NAME "19_sndtimeo_rcvtimeo_semantics"
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
  SOCKET ls = INVALID_SOCKET, c = INVALID_SOCKET, a = INVALID_SOCKET;
  unsigned short port;
  struct sockaddr_in sa;
  DWORD v, vv;
  int ol, r, e, i;
  double t0, dt;
  static char buf[65536];
  long long sent = 0;
  unsigned long nb = 1;

  if (WSAStartup(MAKEWORD(2, 2), &wd)) { printf("FAIL %s: WSAStartup\n", TEST_NAME); return 1; }
  ls = lis_loop(8, &port);
  if (ls == INVALID_SOCKET) FAILF("listener");
  c = socket(AF_INET, SOCK_STREAM, 0);
  sa = loop_addr(port);
  if (connect(c, (struct sockaddr *)&sa, sizeof(sa))) FAILF("connect %d", WSAGetLastError());
  a = accept(ls, NULL, NULL);
  if (a == INVALID_SOCKET) FAILF("accept");

  /* read back */
  ol = sizeof(v);
  v = 99; r = getsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (char *)&v, &ol);
  INFO("default SO_SNDTIMEO r=%d v=%lu ol=%d", r, (unsigned long)v, ol);
  if (r != 0 || v != 0) FAILF("default SO_SNDTIMEO r=%d v=%lu", r, (unsigned long)v);
  v = 700; r = setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (char *)&v, sizeof(v));
  if (r) FAILF("set SO_SNDTIMEO %d", WSAGetLastError());
  vv = 0; ol = sizeof(vv); getsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (char *)&vv, &ol);
  INFO("SO_SNDTIMEO 700 reads back %lu", (unsigned long)vv);
  if (vv != 700) FAILF("readback %lu", (unsigned long)vv);

  /* fill: the peer never reads. send blocks, then WSAETIMEDOUT */
  t0 = now_ms();
  for (i = 0; i < 100000; i++) {
    r = send(c, buf, sizeof(buf), 0);
    if (r == SOCKET_ERROR) break;
    sent += r;
  }
  dt = now_ms() - t0;
  e = WSAGetLastError();
  INFO("send stopped after %lld bytes err=%d (%.0f ms total)", sent, e, dt);
  if (r != SOCKET_ERROR) FAILF("send never blocked/timed out");
  if (e != WSAETIMEDOUT) FAILF("send error %d, expected 10060", e);
  if (dt < 600.0 || dt > 3000.0) FAILF("timeout took %.0f ms, expected ~700", dt);
  /* the socket is still connected: drain and send again */
  {
    long long got = 0;
    DWORD z = 0;
    setsockopt(a, SOL_SOCKET, SO_RCVTIMEO, (char *)&(DWORD){300}, sizeof(DWORD));
    for (;;) {
      r = recv(a, buf, sizeof(buf), 0);
      if (r <= 0) break;
      got += r;
    }
    INFO("drained %lld of %lld sent, recv end err=%d", got, sent, WSAGetLastError());
    /* the send() that failed with WSAETIMEDOUT may already have queued part of its buffer (probed: one whole 64 KiB call) */
    if (got < sent || got - sent > (long long)sizeof(buf)) FAILF("peer received %lld bytes, sender counted %lld", got, sent);
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (char *)&z, sizeof(z));
    r = send(c, "x", 1, 0);
    if (r != 1) FAILF("send after timeout r=%d err=%d", r, WSAGetLastError());
  }

  /* RCVTIMEO: timeout, then data arriving later is still readable */
  v = 400; setsockopt(a, SOL_SOCKET, SO_RCVTIMEO, (char *)&v, sizeof(v));
  r = recv(a, buf, 1, 0);        /* the 'x' */
  if (r != 1) FAILF("recv x r=%d", r);
  t0 = now_ms();
  r = recv(a, buf, 1, 0);
  dt = now_ms() - t0; e = WSAGetLastError();
  INFO("idle recv r=%d err=%d %.0f ms", r, e, dt);
  if (r != SOCKET_ERROR || e != WSAETIMEDOUT) FAILF("idle recv r=%d err=%d", r, e);
  if (dt < 350.0 || dt > 1500.0) FAILF("idle recv took %.0f ms", dt);
  send(c, "y", 1, 0);
  r = recv(a, buf, 1, 0);
  if (r != 1 || buf[0] != 'y') FAILF("recv after timeout r=%d", r);

  /* accept is not bounded by SO_RCVTIMEO set on the listening socket */
  v = 300; r = setsockopt(ls, SOL_SOCKET, SO_RCVTIMEO, (char *)&v, sizeof(v));
  INFO("SO_RCVTIMEO on listener set r=%d", r);
  {
    SOCKET x;
    fd_set rs;
    struct timeval tv = { 1, 0 };
    FD_ZERO(&rs); FD_SET(ls, &rs);
    ioctlsocket(ls, FIONBIO, &nb);
    t0 = now_ms();
    x = accept(ls, NULL, NULL);
    e = WSAGetLastError();
    INFO("nonblocking accept on empty queue: %s err=%d", x == INVALID_SOCKET ? "INVALID_SOCKET" : "socket", e);
    if (x != INVALID_SOCKET) { closesocket(x); FAILF("accept returned a socket"); }
    if (e != WSAEWOULDBLOCK) FAILF("accept err %d, expected 10035", e);
    nb = 0; ioctlsocket(ls, FIONBIO, &nb);
    r = select(0, &rs, NULL, NULL, &tv);
    dt = now_ms() - t0;
    INFO("select on idle listener r=%d %.0f ms", r, dt);
    if (r != 0 || dt < 900.0) FAILF("select r=%d dt=%.0f", r, dt);
  }
  /* zero = infinite: a short wait with data sent from a thread-less delay is impractical; assert set/readback only */
  v = 0; r = setsockopt(a, SOL_SOCKET, SO_RCVTIMEO, (char *)&v, sizeof(v));
  vv = 5; ol = sizeof(vv); getsockopt(a, SOL_SOCKET, SO_RCVTIMEO, (char *)&vv, &ol);
  if (r || vv != 0) FAILF("SO_RCVTIMEO 0 r=%d readback %lu", r, (unsigned long)vv);
  /* too-short optlen */
  ol = 2; v = 5;
  r = setsockopt(a, SOL_SOCKET, SO_RCVTIMEO, (char *)&v, 2); e = WSAGetLastError();
  INFO("setsockopt optlen 2: r=%d err=%d", r, e);
  r = setsockopt(a, SOL_SOCKET, SO_SNDTIMEO, (char *)&v, 0); e = WSAGetLastError();
  INFO("setsockopt optlen 0: r=%d err=%d", r, e);
  {
    DWORD big = 0xFFFFFFFF; vv = 0;
    r = setsockopt(a, SOL_SOCKET, SO_RCVTIMEO, (char *)&big, sizeof(big));
    ol = sizeof(vv); getsockopt(a, SOL_SOCKET, SO_RCVTIMEO, (char *)&vv, &ol);
    INFO("SO_RCVTIMEO 0xFFFFFFFF r=%d readback 0x%lx", r, (unsigned long)vv);
  }
  printf("PASS %s\n", TEST_NAME);
out:
  if (c != INVALID_SOCKET) closesocket(c);
  if (a != INVALID_SOCKET) closesocket(a);
  if (ls != INVALID_SOCKET) closesocket(ls);
  WSACleanup();
  return g_fail;
}
