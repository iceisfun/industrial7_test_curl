/*
 * Test: 17_peer_close_and_reset
 * Purpose: The receive/send error codes curl maps to "connection closed" and
 *   "connection reset" on Windows (cf-socket.c nw_in_read / send paths).
 * APIs: send, recv, shutdown, closesocket, setsockopt(SO_LINGER), select,
 *   ioctlsocket(FIONBIO), WSAGetLastError
 * Success (probed on Windows 10 22H2): after the peer closes gracefully,
 *   select reports readable and recv returns 0 (twice, never an error); data
 *   sent before the close is still delivered first. Sending to a gracefully
 *   closed peer succeeds once and the next send fails with WSAECONNABORTED
 *   (10053). After the peer closes with SO_LINGER {1,0} (abortive), select
 *   reports readable and recv, a second recv and a send all fail with
 *   WSAECONNRESET (10054).
 */
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
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if(!(cond)) {                                                          \
      printf("FAIL %s: ", TEST_NAME);                                      \
      printf(__VA_ARGS__);                                                 \
      printf(" [line %d, WSAGetLastError=%d]\n", __LINE__,                 \
             WSAGetLastError());                                           \
      rc = 1;                                                              \
      goto out;                                                            \
    }                                                                      \
  } while(0)

__attribute__((unused)) static SOCKET tcp_listener(struct sockaddr_in *sa)
{
  int len = (int)sizeof(*sa);
  SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(l == INVALID_SOCKET)
    return l;
  memset(sa, 0, sizeof(*sa));
  sa->sin_family = AF_INET;
  sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(bind(l, (struct sockaddr *)sa, (int)sizeof(*sa)) ||
     getsockname(l, (struct sockaddr *)sa, &len) || listen(l, 4)) {
    closesocket(l);
    return INVALID_SOCKET;
  }
  return l;
}

/* blocking connected loopback pair; returns 0 on success */
__attribute__((unused)) static int tcp_pair(SOCKET *c, SOCKET *a)
{
  struct sockaddr_in sa;
  SOCKET l = tcp_listener(&sa);
  *c = *a = INVALID_SOCKET;
  if(l == INVALID_SOCKET)
    return -1;
  *c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(*c == INVALID_SOCKET || connect(*c, (struct sockaddr *)&sa, sizeof(sa))) {
    closesocket(l);
    return -1;
  }
  *a = accept(l, NULL, NULL);
  closesocket(l);
  return *a == INVALID_SOCKET ? -1 : 0;
}

__attribute__((unused)) static unsigned long ms_now(void)
{
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (unsigned long)((c.QuadPart * 1000) / f.QuadPart);
}

__attribute__((unused)) static int is_wine(void)
{
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  return nt && GetProcAddress(nt, "wine_get_version") != NULL;
}

#define TEST_NAME "17_peer_close_and_reset"

static int readable(SOCKET s, int ms)
{
  fd_set rd;
  struct timeval tv;
  FD_ZERO(&rd); FD_SET(s, &rd);
  tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
  return select(0, &rd, NULL, NULL, &tv) == 1 && FD_ISSET(s, &rd);
}

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  WSADATA wsa;
  SOCKET c, a;
  int rc = 0, n, e, i;
  char buf[16];
  struct linger lg;

  if(WSAStartup(MAKEWORD(2, 2), &wsa))
    return 1;

  /* graceful close with pending data */
  CHECK(tcp_pair(&c, &a) == 0, "pair");
  CHECK(send(a, "hello", 5, 0) == 5, "send");
  closesocket(a);
  CHECK(readable(c, 3000), "not readable after peer close");
  n = recv(c, buf, sizeof(buf), 0);
  CHECK(n == 5 && memcmp(buf, "hello", 5) == 0, "first recv %d", n);
  CHECK(readable(c, 3000), "EOF not reported readable");
  n = recv(c, buf, sizeof(buf), 0);
  CHECK(n == 0, "EOF recv returned %d (err %d)", n, WSAGetLastError());
  n = recv(c, buf, sizeof(buf), 0);
  CHECK(n == 0, "second EOF recv returned %d", n);
  /* writing to a closed peer: first send ok, then an error appears */
  n = send(c, "x", 1, 0);
  e = 0;
  for(i = 0; i < 20 && n >= 0; i++) {
    Sleep(50);
    n = send(c, "x", 1, 0);
  }
  e = WSAGetLastError();
  printf("INFO send to closed peer: n=%d err=%d after %d extra sends\n", n, e, i);
  CHECK(n == SOCKET_ERROR, "send to closed peer never failed");
  CHECK(e == WSAECONNABORTED, "send error %d, expected 10053", e);
  closesocket(c);

  /* abortive close */
  CHECK(tcp_pair(&c, &a) == 0, "pair(2)");
  lg.l_onoff = 1; lg.l_linger = 0;
  CHECK(setsockopt(a, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg)) == 0,
        "SO_LINGER");
  closesocket(a);
  CHECK(readable(c, 3000), "not readable after RST");
  n = recv(c, buf, sizeof(buf), 0);
  e = WSAGetLastError();
  CHECK(n == SOCKET_ERROR && e == WSAECONNRESET, "RST recv n=%d err=%d", n, e);
  n = recv(c, buf, sizeof(buf), 0);
  e = WSAGetLastError();
  printf("INFO second recv after RST: n=%d err=%d\n", n, e);
  CHECK(n == SOCKET_ERROR && e == WSAECONNRESET, "second recv n=%d err=%d", n, e);
  n = send(c, "x", 1, 0);
  e = WSAGetLastError();
  printf("INFO send after RST: n=%d err=%d\n", n, e);
  CHECK(n == SOCKET_ERROR && e == WSAECONNRESET, "send after RST n=%d err=%d", n, e);
  closesocket(c);

  printf("PASS %s\n", TEST_NAME);
out:
  WSACleanup();
  return rc;
}
