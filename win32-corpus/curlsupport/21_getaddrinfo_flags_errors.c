/*
 * Test: 21_getaddrinfo_flags_errors
 * Purpose: The getaddrinfo flag and error behaviour curl's resolver relies on
 *   without any network: numeric-host short cut, AI_NUMERICHOST rejection of
 *   names, error numbers, getnameinfo numeric output.
 * APIs: getaddrinfo, freeaddrinfo, getnameinfo, WSAGetLastError, gai_strerrorW
 * Source: lib/asyn-thrdd.c / lib/curl_addrinfo.c (Curl_getaddrinfo_ex),
 *   lib/hostip.c (numeric host detection).
 * Success (probed on Windows 10 22H2): "127.0.0.1" with AI_NUMERICHOST
 *   succeeds with one AF_INET entry; "localhost" with AI_NUMERICHOST fails
 *   with WSAHOST_NOT_FOUND (11001); "::1" with AF_INET fails; port "80"
 *   fills sin_port and returns ai_socktype SOCK_STREAM with ai_protocol 0; service "nosuchservice" fails with WSATYPE_NOT_FOUND (10109), and
 *   with AI_NUMERICSERV with WSAHOST_NOT_FOUND (11001); the numeric service
 *   "70000" is silently truncated to port 4464; a NULL node with AI_PASSIVE gives 0.0.0.0
 *   and without it the loopback address; getnameinfo into a 4 byte host
 *   buffer fails with 122 (ERROR_INSUFFICIENT_BUFFER); getaddrinfo's return value equals
 *   WSAGetLastError(); getnameinfo(NI_NUMERICHOST|NI_NUMERICSERV) of
 *   127.0.0.1:8080 gives "127.0.0.1" and "8080".
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

#define TEST_NAME "21_getaddrinfo_flags_errors"

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  WSADATA wsa;
  struct addrinfo hints, *res = NULL;
  int rc = 0, r;
  char host[64], serv[16];
  struct sockaddr_in sa;

  if(WSAStartup(MAKEWORD(2, 2), &wsa))
    return 1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST;
  r = getaddrinfo("127.0.0.1", "80", &hints, &res);
  CHECK(r == 0 && res && res->ai_family == AF_INET && res->ai_next == NULL,
        "numeric ipv4 r=%d", r);
  CHECK(((struct sockaddr_in *)res->ai_addr)->sin_port == htons(80) &&
        ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK),
        "numeric ipv4 address/port");
  CHECK(res->ai_socktype == SOCK_STREAM && res->ai_protocol == 0,
        "socktype %d proto %d", res->ai_socktype, res->ai_protocol);
  freeaddrinfo(res); res = NULL;

  r = getaddrinfo("localhost", NULL, &hints, &res);
  CHECK(r == WSAHOST_NOT_FOUND && WSAGetLastError() == r,
        "AI_NUMERICHOST localhost r=%d (err %d)", r, WSAGetLastError());

  hints.ai_family = AF_INET;
  r = getaddrinfo("::1", NULL, &hints, &res);
  printf("INFO ::1 with AF_INET: r=%d\n", r);
  CHECK(r == WSAHOST_NOT_FOUND, "ipv6 literal with AF_INET r=%d", r);

  hints.ai_flags = AI_NUMERICSERV;
  r = getaddrinfo("127.0.0.1", "nosuchservice", &hints, &res);
  printf("INFO bad service: r=%d\n", r);
  CHECK(r == WSAHOST_NOT_FOUND, "bad service r=%d, expected 11001", r);
  hints.ai_flags = 0;
  r = getaddrinfo("127.0.0.1", "nosuchservice", &hints, &res);
  CHECK(r == WSATYPE_NOT_FOUND, "bad service name r=%d, expected 10109", r);
  hints.ai_flags = AI_NUMERICSERV;
  r = getaddrinfo("127.0.0.1", "70000", &hints, &res);
  CHECK(r == 0 && res &&
        ntohs(((struct sockaddr_in *)res->ai_addr)->sin_port) == (70000 & 0xFFFF),
        "port 70000 r=%d, expected silent truncation to 4464", r);
  freeaddrinfo(res); res = NULL;

  hints.ai_flags = AI_PASSIVE;
  r = getaddrinfo(NULL, "8080", &hints, &res);
  CHECK(r == 0 && res, "passive r=%d", r);
  CHECK(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr == 0 &&
        ((struct sockaddr_in *)res->ai_addr)->sin_port == htons(8080),
        "passive address is not 0.0.0.0:8080");
  freeaddrinfo(res); res = NULL;
  hints.ai_flags = 0;
  r = getaddrinfo(NULL, "8080", &hints, &res);
  CHECK(r == 0 && res, "non-passive r=%d", r);
  CHECK(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK),
        "non-passive NULL node is not loopback");
  freeaddrinfo(res); res = NULL;

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(8080);
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  r = getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), serv,
                  sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
  CHECK(r == 0 && strcmp(host, "127.0.0.1") == 0 && strcmp(serv, "8080") == 0,
        "getnameinfo r=%d '%s' '%s'", r, host, serv);
  r = getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, 4, serv,
                  sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
  CHECK(r == ERROR_INSUFFICIENT_BUFFER, "getnameinfo with a 4 byte host buffer r=%d, expected 122", r);

  printf("PASS %s\n", TEST_NAME);
out:
  WSACleanup();
  return rc;
}
