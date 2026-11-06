/*
 * Test: 22_select_edge_cases
 * Purpose: Winsock select() quirks that make curl avoid select() for sleeping
 *   and cap its fd sets (lib/select.c: Curl_wait_ms uses Sleep, Curl_poll
 *   uses WSAPoll; FD_SETSIZE 64 on Windows).
 * APIs: select, FD_SET, WSAPoll
 * Success (probed on Windows 10 22H2): select(0, NULL, NULL, NULL, &tv) with
 *   three empty sets returns SOCKET_ERROR with WSAEINVAL (10022) at once
 *   (it cannot be used as a sleep); FD_SET on a full set (64) silently
 *   ignores the 65th socket (fd_count stays 64); FD_SET of the same socket
 *   twice counts once; select on a closed socket fails with WSAENOTSOCK
 *   (10038); WSAPoll with zero entries fails with WSAEINVAL (10022); WSAPoll
 *   of a closed socket sets POLLNVAL in revents but returns SOCKET_ERROR
 *   with WSAENOTSOCK (10038).
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

#define TEST_NAME "22_select_edge_cases"

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  WSADATA wsa;
  SOCKET s[FD_SETSIZE + 1], x = INVALID_SOCKET;
  int rc = 0, i, r, e;
  fd_set a, b, c;
  struct timeval tv;
  WSAPOLLFD pfd;
  unsigned long t0, ms;

  if(WSAStartup(MAKEWORD(2, 2), &wsa))
    return 1;
  for(i = 0; i < FD_SETSIZE + 1; i++)
    s[i] = INVALID_SOCKET;

  FD_ZERO(&a); FD_ZERO(&b); FD_ZERO(&c);
  tv.tv_sec = 1; tv.tv_usec = 0;
  t0 = ms_now();
  r = select(0, &a, &b, &c, &tv);
  e = WSAGetLastError();
  ms = ms_now() - t0;
  printf("INFO empty select r=%d err=%d after %lu ms\n", r, e, ms);
  CHECK(r == SOCKET_ERROR && e == WSAEINVAL, "empty select r=%d err=%d", r, e);
  CHECK(ms < 500, "empty select took %lu ms", ms);
  r = select(0, NULL, NULL, NULL, &tv);
  e = WSAGetLastError();
  CHECK(r == SOCKET_ERROR && e == WSAEINVAL, "NULL select r=%d err=%d", r, e);

  for(i = 0; i < FD_SETSIZE + 1; i++) {
    s[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(s[i] != INVALID_SOCKET, "socket %d", i);
  }
  FD_ZERO(&a);
  for(i = 0; i < FD_SETSIZE + 1; i++)
    FD_SET(s[i], &a);
  printf("INFO fd_count after 65 FD_SET = %u\n", (unsigned)a.fd_count);
  CHECK(a.fd_count == FD_SETSIZE, "fd_count %u, expected 64", (unsigned)a.fd_count);
  FD_ZERO(&a);
  FD_SET(s[0], &a); FD_SET(s[0], &a);
  CHECK(a.fd_count == 1, "duplicate FD_SET count %u", (unsigned)a.fd_count);

  x = s[1];
  closesocket(x);
  FD_ZERO(&a); FD_SET(x, &a);
  tv.tv_sec = 0; tv.tv_usec = 0;
  r = select(0, &a, NULL, NULL, &tv);
  e = WSAGetLastError();
  printf("INFO select on closed socket r=%d err=%d\n", r, e);
  CHECK(r == SOCKET_ERROR && e == WSAENOTSOCK, "closed select r=%d err=%d", r, e);

  r = WSAPoll(&pfd, 0, 0);
  e = WSAGetLastError();
  printf("INFO WSAPoll(0 entries) r=%d err=%d\n", r, e);
  CHECK(r == SOCKET_ERROR && e == WSAEINVAL, "poll(0) r=%d err=%d", r, e);
  pfd.fd = x; pfd.events = POLLRDNORM; pfd.revents = 0;
  r = WSAPoll(&pfd, 1, 0);
  printf("INFO WSAPoll(closed) r=%d revents=0x%x\n", r, (unsigned)pfd.revents);
  CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK &&
        pfd.revents == POLLNVAL, "poll closed r=%d err=%d revents=0x%x",
        r, WSAGetLastError(), (unsigned)pfd.revents);

  printf("PASS %s\n", TEST_NAME);
out:
  for(i = 0; i < FD_SETSIZE + 1; i++)
    if(s[i] != INVALID_SOCKET && s[i] != x)
      closesocket(s[i]);
  WSACleanup();
  return rc;
}
