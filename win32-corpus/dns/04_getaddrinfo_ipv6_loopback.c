/*
 * Test 04_getaddrinfo_ipv6_loopback
 *
 * Purpose: numeric IPv6 literal handling through getaddrinfo(): "::1" with
 * AI_NUMERICHOST and AF_INET6 must yield the in6addr_loopback sockaddr,
 * "::ffff:127.0.0.1" must yield an IPv4-mapped address, and an invalid IPv6
 * literal must be rejected. curl depends on this for IPv6 literal URLs and
 * for choosing AI_NUMERICHOST when resolving literals.
 *
 * APIs: WSAStartup, socket (feature probe), getaddrinfo, freeaddrinfo,
 *       WSACleanup.
 *
 * Success: when AF_INET6 sockets are available, getaddrinfo("::1") returns 0
 * with one AF_INET6 entry, IN6_IS_ADDR_LOOPBACK true, sin6_port == htons(8080),
 * ai_addrlen == sizeof(sockaddr_in6). "::ffff:127.0.0.1" returns an entry with
 * IN6_IS_ADDR_V4MAPPED true. "1::2::3" is rejected. If the socket probe
 * fails with WSAEAFNOSUPPORT, the test SKIPs (77).
 *
 * Source: lib/vdns/hostip6.c:91-98 (AI_NUMERICHOST for literal addresses),
 *         lib/curl_addrinfo.c:433-436 (Curl_is_ipaddr path for IPv6 literal),
 *         lib/curlx/inet_pton.c:203-214 (AF_INET6 presentation parser).
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
#include <string.h>

#define T "04_getaddrinfo_ipv6_loopback"

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [WSA=%d GLE=%lu]\n", WSAGetLastError(), (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

#define SKIPF(msg) do { \
    printf("SKIP %s: %s\n", T, msg); status = 77; goto out; } while(0)

int main(void)
{
  WSADATA wsa;
  struct addrinfo hints, *res = NULL, *ai;
  struct sockaddr_in6 *s6;
  SOCKET probe;
  int rc, n = 0, wsa_ok = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

  /* Feature probe: no AF_INET6 support means SKIP, not FAIL. */
  probe = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if(probe == INVALID_SOCKET) {
    if(WSAGetLastError() == WSAEAFNOSUPPORT)
      SKIPF("AF_INET6 not supported by this stack");
    FAILF("socket(AF_INET6) failed for a reason other than missing support");
  }
  closesocket(probe);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

  rc = getaddrinfo("::1", "8080", &hints, &res);
  if(rc != 0)
    FAILF("getaddrinfo(::1) returned %d", rc);
  for(ai = res; ai; ai = ai->ai_next)
    n++;
  if(n != 1)
    FAILF("expected 1 result for ::1, got %d", n);
  if(res->ai_family != AF_INET6)
    FAILF("ai_family=%d, expected AF_INET6", res->ai_family);
  if(res->ai_addrlen != (socklen_t)sizeof(struct sockaddr_in6))
    FAILF("ai_addrlen=%d, expected %d", (int)res->ai_addrlen,
          (int)sizeof(struct sockaddr_in6));
  s6 = (struct sockaddr_in6 *)res->ai_addr;
  if(!IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr))
    FAILF("::1 did not resolve to the loopback address");
  if(s6->sin6_port != htons(8080))
    FAILF("sin6_port=%u, expected 8080", (unsigned)ntohs(s6->sin6_port));
  freeaddrinfo(res);
  res = NULL;

  /* IPv4-mapped literal must keep its IPv4 meaning. */
  rc = getaddrinfo("::ffff:127.0.0.1", "80", &hints, &res);
  if(rc != 0)
    FAILF("getaddrinfo(::ffff:127.0.0.1) returned %d", rc);
  s6 = (struct sockaddr_in6 *)res->ai_addr;
  if(!IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr))
    FAILF("::ffff:127.0.0.1 is not reported as an IPv4-mapped address");
  if(s6->sin6_addr.u.Byte[12] != 127 || s6->sin6_addr.u.Byte[15] != 1)
    FAILF("IPv4-mapped bytes do not encode 127.0.0.1");
  freeaddrinfo(res);
  res = NULL;

  /* Two "::" compressions is an invalid literal. */
  rc = getaddrinfo("1::2::3", "80", &hints, &res);
  if(rc == 0)
    FAILF("AI_NUMERICHOST accepted invalid IPv6 literal 1::2::3");

out:
  if(res)
    freeaddrinfo(res);
  if(wsa_ok)
    WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
