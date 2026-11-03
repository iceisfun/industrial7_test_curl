/*
 * Test 06_getaddrinfow_getnameinfow_roundtrip
 *
 * Purpose: the wide-character resolver pair GetAddrInfoW/FreeAddrInfoW
 * resolves a literal and "localhost" with UTF-16 arguments, and GetNameInfoW
 * converts the resulting sockaddr back to numeric wide host and service
 * strings. Also checks the GetNameInfoW buffer-too-small error path.
 *
 * APIs: WSAStartup, GetAddrInfoW, FreeAddrInfoW, GetNameInfoW, WSACleanup.
 *
 * Success: GetAddrInfoW(L"127.0.0.1", L"8080", AI_NUMERICHOST) returns 0 with
 * one AF_INET entry; GetNameInfoW on its sockaddr with NI_NUMERICHOST |
 * NI_NUMERICSERV yields L"127.0.0.1" and L"8080". GetAddrInfoW(L"localhost")
 * returns 0 and includes 127.0.0.1 or ::1. GetNameInfoW into a 4-character
 * host buffer returns non-zero (the exact code is stack-specific, so only the
 * failure itself is asserted).
 *
 * Source: lib/curl_addrinfo.c:111-130 (getaddrinfo wrapper; this is its
 *         wide-character counterpart), lib/idn.c:175-176 (the wide string
 *         conversions that precede a wide resolver call on Windows).
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
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#define T "06_getaddrinfow_getnameinfow_roundtrip"

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [WSA=%d GLE=%lu]\n", WSAGetLastError(), (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

int main(void)
{
  WSADATA wsa;
  ADDRINFOW hints, *res = NULL, *ai;
  WCHAR host[256], serv[32];
  int rc, n = 0, wsa_ok = 0, loop = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

  rc = GetAddrInfoW(L"127.0.0.1", L"8080", &hints, &res);
  if(rc != 0)
    FAILF("GetAddrInfoW(127.0.0.1) returned %d", rc);
  for(ai = res; ai; ai = ai->ai_next)
    n++;
  if(n != 1)
    FAILF("GetAddrInfoW literal returned %d entries, expected 1", n);
  if(res->ai_family != AF_INET)
    FAILF("GetAddrInfoW ai_family=%d", res->ai_family);
  if(res->ai_canonname != NULL)
    FAILF("ai_canonname set without AI_CANONNAME");

  /* Reverse direction: sockaddr back to numeric wide strings. */
  rc = GetNameInfoW(res->ai_addr, (socklen_t)res->ai_addrlen,
                    host, 256, serv, 32,
                    NI_NUMERICHOST | NI_NUMERICSERV);
  if(rc != 0)
    FAILF("GetNameInfoW returned %d", rc);
  if(wcscmp(host, L"127.0.0.1") != 0)
    FAILF("GetNameInfoW host is '%ls', expected 127.0.0.1", host);
  if(wcscmp(serv, L"8080") != 0)
    FAILF("GetNameInfoW service is '%ls', expected 8080", serv);

  /* A host buffer that cannot hold "127.0.0.1" plus NUL must fail. */
  rc = GetNameInfoW(res->ai_addr, (socklen_t)res->ai_addrlen,
                    host, 4, serv, 32, NI_NUMERICHOST | NI_NUMERICSERV);
  /* Buffer-too-small is reported as a non-zero code. MSDN documents it as
     EAI_OVERFLOW-class; the exact value differs between stacks (wine returns
     -12), so only the failure itself is asserted. */
  if(rc == 0)
    FAILF("GetNameInfoW with 4-char host buffer succeeded (must not truncate silently)");

  FreeAddrInfoW(res);
  res = NULL;

  /* Wide localhost resolution: loopback must be among the results. */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  rc = GetAddrInfoW(L"localhost", L"80", &hints, &res);
  if(rc != 0)
    FAILF("GetAddrInfoW(localhost) returned %d", rc);
  for(ai = res; ai; ai = ai->ai_next) {
    if(ai->ai_family == AF_INET) {
      struct sockaddr_in *s4 = (struct sockaddr_in *)ai->ai_addr;
      if(ntohl(s4->sin_addr.S_un.S_addr) == 0x7F000001UL)
        loop++;
    }
    else if(ai->ai_family == AF_INET6) {
      struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ai->ai_addr;
      if(IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr))
        loop++;
    }
  }
  if(loop < 1)
    FAILF("GetAddrInfoW(localhost) has no loopback entry");

out:
  if(res)
    FreeAddrInfoW(res);
  if(wsa_ok)
    WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
