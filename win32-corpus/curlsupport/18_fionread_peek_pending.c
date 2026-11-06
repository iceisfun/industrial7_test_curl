/*
 * Test: 18_fionread_peek_pending
 * Purpose: How curl asks "is data pending on this socket" without consuming
 *   it (FIONREAD / MSG_PEEK) and what an empty non-blocking recv returns.
 * APIs: ioctlsocket(FIONREAD), recv(MSG_PEEK), send, select
 * Success (probed on Windows 10 22H2): FIONREAD is 0 on an idle socket; after
 *   the peer sends 100 bytes (waiting for readability) it reports 100;
 *   MSG_PEEK returns the same bytes twice without consuming them;
 *   a peek with a 10 byte buffer returns 10 and FIONREAD stays 100; a normal
 *   recv drains them and FIONREAD returns to 0; a non-blocking recv on the
 *   empty socket returns SOCKET_ERROR/WSAEWOULDBLOCK.
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

#define TEST_NAME "18_fionread_peek_pending"

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  WSADATA wsa;
  SOCKET c, a;
  int rc = 0, n, i;
  u_long nb = 1, avail = 99;
  char out[100], in[200], in2[200];
  fd_set rd;
  struct timeval tv;

  if(WSAStartup(MAKEWORD(2, 2), &wsa))
    return 1;
  CHECK(tcp_pair(&c, &a) == 0, "pair");
  for(i = 0; i < 100; i++)
    out[i] = (char)('A' + (i % 26));

  CHECK(ioctlsocket(c, FIONREAD, &avail) == 0 && avail == 0,
        "idle FIONREAD %lu", (unsigned long)avail);
  CHECK(send(a, out, 100, 0) == 100, "send");
  FD_ZERO(&rd); FD_SET(c, &rd);
  tv.tv_sec = 5; tv.tv_usec = 0;
  CHECK(select(0, &rd, NULL, NULL, &tv) == 1, "readable");
  CHECK(ioctlsocket(c, FIONREAD, &avail) == 0 && avail == 100,
        "FIONREAD %lu, expected 100", (unsigned long)avail);
  n = recv(c, in, sizeof(in), MSG_PEEK);
  CHECK(n == 100 && memcmp(in, out, 100) == 0, "peek n=%d", n);
  n = recv(c, in2, sizeof(in2), MSG_PEEK);
  CHECK(n == 100 && memcmp(in2, out, 100) == 0, "second peek n=%d", n);
  n = recv(c, in, 10, MSG_PEEK);
  CHECK(n == 10, "short peek n=%d", n);
  CHECK(ioctlsocket(c, FIONREAD, &avail) == 0 && avail == 100,
        "FIONREAD after peeks %lu", (unsigned long)avail);
  n = recv(c, in, sizeof(in), 0);
  CHECK(n == 100 && memcmp(in, out, 100) == 0, "recv n=%d", n);
  CHECK(ioctlsocket(c, FIONREAD, &avail) == 0 && avail == 0,
        "FIONREAD after drain %lu", (unsigned long)avail);
  CHECK(ioctlsocket(c, FIONBIO, &nb) == 0, "FIONBIO");
  n = recv(c, in, sizeof(in), 0);
  CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK,
        "empty recv n=%d err=%d", n, WSAGetLastError());
  n = recv(c, in, sizeof(in), MSG_PEEK);
  CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK,
        "empty peek n=%d err=%d", n, WSAGetLastError());

  printf("PASS %s\n", TEST_NAME);
out:
  WSACleanup();
  return rc;
}
