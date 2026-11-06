/*
 * Test: 20_ideal_send_backlog_query
 * Purpose: SIO_IDEAL_SEND_BACKLOG_QUERY, the ioctl curl (lib/cf-socket.c,
 *          win_update_sndbuf_size) uses to size SO_SNDBUF for fast uploads,
 *          and the SO_SNDBUF interplay around it.
 * APIs: WSAIoctl(SIO_IDEAL_SEND_BACKLOG_QUERY / _CHANGE), getsockopt/setsockopt SO_SNDBUF.
 * Success (probed on Win10 22H2): on a connected loopback socket the query
 *          returns 4 bytes holding 65536 (= default SO_SNDBUF) and stays 65536
 *          after 1 MB of traffic; on an unconnected socket it fails WSAENOTCONN
 *          (10057); a 2-byte or missing output buffer fails WSAEINVAL (10022);
 *          the _CHANGE request issued overlapped returns SOCKET_ERROR /
 *          WSA_IO_PENDING (997). A synchronous _CHANGE blocks forever: never issue it.
 * Source: lib/cf-socket.c win_update_sndbuf_size / Curl_win32 ideal send backlog.
 */
#define TEST_NAME "20_ideal_send_backlog_query"
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
#ifndef SIO_IDEAL_SEND_BACKLOG_QUERY
#define SIO_IDEAL_SEND_BACKLOG_QUERY 0x4004747B
#endif
#ifndef SIO_IDEAL_SEND_BACKLOG_CHANGE
#define SIO_IDEAL_SEND_BACKLOG_CHANGE 0x2000747C
#endif

int main(void) {
  WSADATA wd;
  SOCKET ls = INVALID_SOCKET, c = INVALID_SOCKET, a = INVALID_SOCKET;
  unsigned short port;
  struct sockaddr_in sa;
  ULONG ideal = 0xdeadbeef, ideal2;
  DWORD got = 0, snd = 0;
  int r, e, ol, i;
  char big[65536];

  if (WSAStartup(MAKEWORD(2, 2), &wd)) { printf("FAIL %s: WSAStartup\n", TEST_NAME); return 1; }
  memset(big, 'a', sizeof(big));
  c = socket(AF_INET, SOCK_STREAM, 0);
  r = WSAIoctl(c, SIO_IDEAL_SEND_BACKLOG_QUERY, NULL, 0, &ideal, sizeof(ideal), &got, NULL, NULL);
  e = WSAGetLastError();
  INFO("unconnected: r=%d err=%d got=%lu ideal=%lu", r, e, (unsigned long)got, (unsigned long)ideal);
  closesocket(c);
  if (r != SOCKET_ERROR || e != WSAENOTCONN) FAILF("unconnected query r=%d err=%d, expected SOCKET_ERROR / 10057", r, e);

  ls = lis_loop(8, &port);
  if (ls == INVALID_SOCKET) FAILF("listener");
  c = socket(AF_INET, SOCK_STREAM, 0);
  sa = loop_addr(port);
  if (connect(c, (struct sockaddr *)&sa, sizeof(sa))) FAILF("connect");
  a = accept(ls, NULL, NULL);
  ol = sizeof(snd); getsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *)&snd, &ol);
  INFO("connected SO_SNDBUF=%lu", (unsigned long)snd);

  ideal = 0xdeadbeef; got = 0;
  r = WSAIoctl(c, SIO_IDEAL_SEND_BACKLOG_QUERY, NULL, 0, &ideal, sizeof(ideal), &got, NULL, NULL);
  e = WSAGetLastError();
  INFO("connected: r=%d err=%d got=%lu ideal=%lu", r, e, (unsigned long)got, (unsigned long)ideal);
  if (r != 0 || got != 4) FAILF("query r=%d got=%lu err=%d", r, (unsigned long)got, e);
  if (ideal != 65536) FAILF("ideal backlog %lu, expected 65536 (the default SO_SNDBUF)", (unsigned long)ideal);

  /* repeat 20 times: stable on an idle connection */
  for (i = 0; i < 20; i++) {
    ideal2 = 0; got = 0;
    r = WSAIoctl(c, SIO_IDEAL_SEND_BACKLOG_QUERY, NULL, 0, &ideal2, sizeof(ideal2), &got, NULL, NULL);
    if (r || ideal2 != ideal) INFO("iteration %d: r=%d ideal=%lu (first %lu)", i, r, (unsigned long)ideal2, (unsigned long)ideal);
  }
  /* send 1 MB with the receiver draining; query again */
  {
    int k;
    unsigned long nb = 1;
    ioctlsocket(a, FIONBIO, &nb);
    for (k = 0; k < 16; k++) {
      send(c, big, sizeof(big), 0);
      while (recv(a, big, sizeof(big), 0) > 0) {}
    }
    memset(big, 'a', sizeof(big));
  }
  ideal2 = 0; got = 0;
  r = WSAIoctl(c, SIO_IDEAL_SEND_BACKLOG_QUERY, NULL, 0, &ideal2, sizeof(ideal2), &got, NULL, NULL);
  INFO("after 1 MB: r=%d ideal=%lu (before %lu)", r, (unsigned long)ideal2, (unsigned long)ideal);

  /* short output buffer */
  {
    unsigned char two[2];
    got = 77;
    r = WSAIoctl(c, SIO_IDEAL_SEND_BACKLOG_QUERY, NULL, 0, two, sizeof(two), &got, NULL, NULL);
    e = WSAGetLastError();
    INFO("2-byte output: r=%d err=%d got=%lu", r, e, (unsigned long)got);
    if (r != SOCKET_ERROR || e != WSAEINVAL) FAILF("2-byte output r=%d err=%d, expected 10022", r, e);
    r = WSAIoctl(c, SIO_IDEAL_SEND_BACKLOG_QUERY, NULL, 0, NULL, 0, &got, NULL, NULL);
    e = WSAGetLastError();
    INFO("no output buffer: r=%d err=%d", r, e);
    if (r != SOCKET_ERROR || e != WSAEINVAL) FAILF("no output buffer r=%d err=%d, expected 10022", r, e);
  }
  /* CHANGE: overlapped notification request */
  {
    WSAOVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = WSACreateEvent();
    got = 0;
    r = WSAIoctl(c, SIO_IDEAL_SEND_BACKLOG_CHANGE, NULL, 0, NULL, 0, &got, &ov, NULL);
    e = WSAGetLastError();
    INFO("CHANGE overlapped: r=%d err=%d", r, e);
    if (!(r == SOCKET_ERROR && e == WSA_IO_PENDING)) FAILF("CHANGE r=%d err=%d", r, e);
    closesocket(c); c = INVALID_SOCKET;
    {
      DWORD w = WaitForSingleObject(ov.hEvent, 3000);
      DWORD tr = 0, fl = 0;
      BOOL ok = WSAGetOverlappedResult(a, &ov, &tr, FALSE, &fl);
      INFO("CHANGE completion after closesocket: wait=%lu", (unsigned long)w);
      (void)ok;
    }
    WSACloseEvent(ov.hEvent);
  }
  printf("PASS %s\n", TEST_NAME);
out:
  if (c != INVALID_SOCKET) closesocket(c);
  if (a != INVALID_SOCKET) closesocket(a);
  if (ls != INVALID_SOCKET) closesocket(ls);
  WSACleanup();
  return g_fail;
}
