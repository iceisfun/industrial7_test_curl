/*
 * Test: 20_tcp_keepalive_sockopts
 * Purpose: curl's keep-alive setup on Windows 10 1709+: SO_KEEPALIVE plus the
 *   per-socket TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT options
 *   (cf-socket.c tcpkeepalive), with SIO_KEEPALIVE_VALS as the older path.
 * APIs: setsockopt/getsockopt(SO_KEEPALIVE, TCP_KEEPIDLE, TCP_KEEPINTVL,
 *   TCP_KEEPCNT), WSAIoctl(SIO_KEEPALIVE_VALS)
 * Success (probed on Windows 10 22H2): setting SO_KEEPALIVE=1 reads back
 *   nonzero; TCP_KEEPIDLE=60, TCP_KEEPINTVL=30, TCP_KEEPCNT=5 are accepted
 *   and read back as set (seconds); SIO_KEEPALIVE_VALS onoff=1,
 *   time=45000 ms, interval=15000 ms is accepted afterwards and TCP_KEEPIDLE
 *   then reads 45 (the ioctl and the option share the same state).
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

#define TEST_NAME "20_tcp_keepalive_sockopts"

#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT 16
#endif
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL 17
#endif
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE 3
#endif

struct kv { ULONG onoff; ULONG time; ULONG interval; };

static int geti(SOCKET s, int level, int opt, int *v)
{
  int len = sizeof(*v);
  *v = -1;
  return getsockopt(s, level, opt, (char *)v, &len);
}

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  WSADATA wsa;
  SOCKET c, a;
  int rc = 0, v, one = 1, n;
  struct kv k;
  DWORD ret = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa))
    return 1;
  CHECK(tcp_pair(&c, &a) == 0, "pair");
  CHECK(setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, sizeof(one)) == 0,
        "SO_KEEPALIVE");
  CHECK(geti(c, SOL_SOCKET, SO_KEEPALIVE, &v) == 0 && v != 0,
        "SO_KEEPALIVE reads %d", v);

  n = 60;
  CHECK(setsockopt(c, IPPROTO_TCP, TCP_KEEPIDLE, (char *)&n, sizeof(n)) == 0,
        "TCP_KEEPIDLE set");
  n = 30;
  CHECK(setsockopt(c, IPPROTO_TCP, TCP_KEEPINTVL, (char *)&n, sizeof(n)) == 0,
        "TCP_KEEPINTVL set");
  n = 5;
  CHECK(setsockopt(c, IPPROTO_TCP, TCP_KEEPCNT, (char *)&n, sizeof(n)) == 0,
        "TCP_KEEPCNT set");
  CHECK(geti(c, IPPROTO_TCP, TCP_KEEPIDLE, &v) == 0, "get KEEPIDLE");
  printf("INFO KEEPIDLE=%d\n", v);
  CHECK(v == 60, "TCP_KEEPIDLE reads %d", v);
  CHECK(geti(c, IPPROTO_TCP, TCP_KEEPINTVL, &v) == 0, "get KEEPINTVL");
  printf("INFO KEEPINTVL=%d\n", v);
  CHECK(v == 30, "TCP_KEEPINTVL reads %d", v);
  CHECK(geti(c, IPPROTO_TCP, TCP_KEEPCNT, &v) == 0, "get KEEPCNT");
  printf("INFO KEEPCNT=%d\n", v);
  CHECK(v == 5, "TCP_KEEPCNT reads %d", v);

  k.onoff = 1; k.time = 45000; k.interval = 15000;
  CHECK(WSAIoctl(c, SIO_KEEPALIVE_VALS, &k, sizeof(k), NULL, 0, &ret, NULL,
                 NULL) == 0, "SIO_KEEPALIVE_VALS");
  CHECK(geti(c, IPPROTO_TCP, TCP_KEEPIDLE, &v) == 0, "get KEEPIDLE(2)");
  printf("INFO KEEPIDLE after ioctl=%d\n", v);
  CHECK(v == 45, "TCP_KEEPIDLE after ioctl reads %d", v);
  CHECK(geti(c, IPPROTO_TCP, TCP_KEEPINTVL, &v) == 0, "get KEEPINTVL(2)");
  printf("INFO KEEPINTVL after ioctl=%d\n", v);
  CHECK(v == 15, "TCP_KEEPINTVL after ioctl reads %d", v);

  printf("PASS %s\n", TEST_NAME);
out:
  WSACleanup();
  return rc;
}
