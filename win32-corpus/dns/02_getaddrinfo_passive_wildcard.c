/*
 * Test 02_getaddrinfo_passive_wildcard
 *
 * Purpose: AI_PASSIVE with a NULL node name yields wildcard (INADDR_ANY /
 * in6addr_any) addresses suitable for bind(), while the same call without
 * AI_PASSIVE yields loopback. The wildcard address is then actually bound
 * to an ephemeral port on a real socket to prove it is usable.
 *
 * APIs: WSAStartup, getaddrinfo (AI_PASSIVE), socket, bind, getsockname,
 *       closesocket, freeaddrinfo, WSACleanup.
 *
 * Success: every AI_PASSIVE result has port == requested port, IPv4 entries
 * are 0.0.0.0, IPv6 entries are ::; the non-passive NULL-node call returns
 * 127.0.0.1 as its first IPv4 entry; a wildcard bind to port 0 succeeds and
 * getsockname() reports a non-zero ephemeral port.
 *
 * Source: no direct curl call site in this checkout. This mirrors the
 *         Curl_getaddrinfo_ex() wrapper contract (lib/curl_addrinfo.c:111-130)
 *         for a listening-socket hint set.
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

#define T "02_getaddrinfo_passive_wildcard"

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [WSA=%d GLE=%lu]\n", WSAGetLastError(), (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

static int count_list(const struct addrinfo *ai)
{
  int n = 0;
  for(; ai; ai = ai->ai_next)
    n++;
  return n;
}

int main(void)
{
  WSADATA wsa;
  struct addrinfo hints, *passive = NULL, *plain = NULL, *ai;
  struct sockaddr_in *sin;
  struct sockaddr_storage bound;
  int rc, n4 = 0, wsa_ok = 0;
  SOCKET s = INVALID_SOCKET;
  int blen = (int)sizeof(bound);

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

  rc = getaddrinfo(NULL, "8080", &hints, &passive);
  if(rc != 0)
    FAILF("AI_PASSIVE getaddrinfo(NULL) returned %d", rc);
  if(count_list(passive) < 1)
    FAILF("AI_PASSIVE returned an empty list");

  for(ai = passive; ai; ai = ai->ai_next) {
    struct sockaddr_in *s4;
    struct sockaddr_in6 *s6;
    if(ai->ai_family == AF_INET) {
      s4 = (struct sockaddr_in *)ai->ai_addr;
      n4++;
      if(s4->sin_addr.S_un.S_addr != htonl(INADDR_ANY))
        FAILF("AI_PASSIVE IPv4 entry is not 0.0.0.0 (got 0x%08lx)",
              (unsigned long)ntohl(s4->sin_addr.S_un.S_addr));
      if(s4->sin_port != htons(8080))
        FAILF("AI_PASSIVE IPv4 port=%u, expected 8080", (unsigned)ntohs(s4->sin_port));
    }
    else if(ai->ai_family == AF_INET6) {
      struct in6_addr any6;
      memset(&any6, 0, sizeof(any6));
      s6 = (struct sockaddr_in6 *)ai->ai_addr;
      if(memcmp(&s6->sin6_addr, &any6, sizeof(any6)) != 0)
        FAILF("AI_PASSIVE IPv6 entry is not ::");
      if(s6->sin6_port != htons(8080))
        FAILF("AI_PASSIVE IPv6 port=%u, expected 8080", (unsigned)ntohs(s6->sin6_port));
    }
    else
      FAILF("AI_PASSIVE returned unexpected family %d", ai->ai_family);
  }

  /* Without AI_PASSIVE the NULL node means loopback. */
  hints.ai_flags = AI_NUMERICSERV;
  hints.ai_family = AF_INET;
  rc = getaddrinfo(NULL, "8080", &hints, &plain);
  if(rc != 0)
    FAILF("non-passive getaddrinfo(NULL) returned %d", rc);
  sin = (struct sockaddr_in *)plain->ai_addr;
  if(sin->sin_addr.S_un.S_addr != htonl(0x7F000001UL))
    FAILF("non-passive NULL node is not 127.0.0.1 (got 0x%08lx)",
          (unsigned long)ntohl(sin->sin_addr.S_un.S_addr));

  /* The wildcard IPv4 entry must actually be bindable. Port 0 asks for an
     ephemeral port, so the test does not collide with anything. */
  if(n4 == 0)
    FAILF("no AI_PASSIVE IPv4 entry to bind");
  for(ai = passive; ai && ai->ai_family != AF_INET; ai = ai->ai_next)
    ;
  sin = (struct sockaddr_in *)ai->ai_addr;
  sin->sin_port = 0;

  s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if(s == INVALID_SOCKET)
    FAILF("socket() failed");
  if(bind(s, ai->ai_addr, (int)ai->ai_addrlen) == SOCKET_ERROR)
    FAILF("bind(0.0.0.0:0) failed");
  if(getsockname(s, (struct sockaddr *)&bound, &blen) == SOCKET_ERROR)
    FAILF("getsockname() failed");
  if(((struct sockaddr_in *)&bound)->sin_port == 0)
    FAILF("bound ephemeral port is 0");

out:
  if(s != INVALID_SOCKET)
    closesocket(s);
  if(passive)
    freeaddrinfo(passive);
  if(plain)
    freeaddrinfo(plain);
  if(wsa_ok)
    WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
