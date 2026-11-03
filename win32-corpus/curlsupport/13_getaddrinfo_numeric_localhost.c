/*
 * Test: 13_getaddrinfo_numeric_localhost
 * Purpose: Mirror curl's name resolution entry points on Windows: numeric
 *   hosts resolved with AI_NUMERICHOST, failures reported as a getaddrinfo
 *   error, and "localhost" resolved through the system resolver.
 * APIs: WSAStartup, getaddrinfo, freeaddrinfo, htons, ntohs, htonl
 * Source: lib/curl_addrinfo.c:111-126 (Curl_getaddrinfo_ex, the wrapper
 *   curl uses for name lookups, calls CURL_GETADDRINFO at line 126; see
 *   lib/curl_setup.h:1460-1483). In release builds
 *   that macro is the system getaddrinfo(); in CURLDEBUG builds it is
 *   curl_dbg_getaddrinfo (lib/curl_addrinfo.c:589-607), which calls
 *   getaddrinfo(hostname, service, hints, result). Numeric addresses take the
 *   same path with AI_NUMERICHOST.
 * Success: "127.0.0.1" port "8080" with AI_NUMERICHOST returns one AF_INET
 *   SOCK_STREAM result whose address is INADDR_LOOPBACK and whose port is
 *   8080; "999.1.1.1" with AI_NUMERICHOST fails with non-zero; the
 *   localhost lookup succeeds and returns 127.0.0.1 or ::1.
 * FAIL: the localhost lookup failing is a FAIL, not a SKIP. Loopback name
 *   resolution is always expected to work (it is answered from the hosts
 *   file), so a failure here is not genuine absence of the feature.
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

#define TEST_NAME "13_getaddrinfo_numeric_localhost"

int main(void)
{
  WSADATA wsa;
  struct addrinfo hints;
  struct addrinfo *res = NULL, *ai;
  int rc;
  int found_loopback = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa)) {
    printf("FAIL %s: WSAStartup failed\n", TEST_NAME);
    return 1;
  }

  /* 1. Numeric IPv4 literal, port given as a string */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST;
  rc = getaddrinfo("127.0.0.1", "8080", &hints, &res);
  if(rc != 0 || !res) {
    printf("FAIL %s: getaddrinfo(127.0.0.1) returned %d, WSAGetLastError=%d\n",
           TEST_NAME, rc, WSAGetLastError());
    WSACleanup();
    return 1;
  }
  if(res->ai_family != AF_INET || res->ai_socktype != SOCK_STREAM ||
     res->ai_addrlen < (size_t)sizeof(struct sockaddr_in)) {
    printf("FAIL %s: result family=%d socktype=%d addrlen=%u\n", TEST_NAME,
           res->ai_family, res->ai_socktype, (unsigned)res->ai_addrlen);
    freeaddrinfo(res);
    WSACleanup();
    return 1;
  }
  {
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    if(sin->sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
       ntohs(sin->sin_port) != 8080) {
      printf("FAIL %s: numeric result address/port wrong (port=%u)\n",
             TEST_NAME, (unsigned)ntohs(sin->sin_port));
      freeaddrinfo(res);
      WSACleanup();
      return 1;
    }
  }
  freeaddrinfo(res);
  res = NULL;

  /* 2. Invalid numeric literal with AI_NUMERICHOST must fail */
  rc = getaddrinfo("999.1.1.1", "80", &hints, &res);
  if(rc == 0) {
    printf("FAIL %s: invalid numeric host 999.1.1.1 resolved\n", TEST_NAME);
    freeaddrinfo(res);
    WSACleanup();
    return 1;
  }
  res = NULL;

  /* 3. localhost through the system resolver */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  rc = getaddrinfo("localhost", "80", &hints, &res);
  if(rc != 0 || !res) {
    printf("FAIL %s: localhost lookup failed, getaddrinfo=%d, "
           "WSAGetLastError=%d\n", TEST_NAME, rc, WSAGetLastError());
    WSACleanup();
    return 1;
  }
  for(ai = res; ai; ai = ai->ai_next) {
    if(ai->ai_family == AF_INET) {
      struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
      if(sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
        found_loopback = 1;
    }
    else if(ai->ai_family == AF_INET6) {
      struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ai->ai_addr;
      static const unsigned char loop6[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 1 };
      if(memcmp(&s6->sin6_addr, loop6, 16) == 0)
        found_loopback = 1;
    }
  }
  freeaddrinfo(res);
  res = NULL;
  if(!found_loopback) {
    printf("FAIL %s: localhost did not resolve to 127.0.0.1 or ::1\n",
           TEST_NAME);
    WSACleanup();
    return 1;
  }

  WSACleanup();
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
