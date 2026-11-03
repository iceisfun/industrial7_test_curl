/*
 * Test 01_getaddrinfo_numeric_ipv4
 *
 * Purpose: getaddrinfo() on a dotted-quad literal with AI_NUMERICHOST and
 * AI_NUMERICSERV, AF_INET, SOCK_STREAM/IPPROTO_TCP. Also checks that
 * AI_NUMERICHOST refuses a hostname (no name lookup is allowed) and refuses
 * an out-of-range literal.
 *
 * APIs: WSAStartup, getaddrinfo, freeaddrinfo, WSACleanup.
 *
 * Success: the literal call returns 0 with exactly one entry whose
 * ai_family==AF_INET, ai_addrlen==sizeof(struct sockaddr_in),
 * sin_addr==127.0.0.1 and sin_port==htons(8080). The hostname call with
 * AI_NUMERICHOST returns EAI_NONAME. The out-of-range literal returns non-zero.
 * The numeric service "65535" with AI_NUMERICSERV yields sin_port==65535.
 *
 * Source: lib/vdns/asyn-thrdd.c:395-415 (hints setup, then
 *         Curl_getaddrinfo_ex() call), lib/vdns/hostip6.c:91-106
 *         (AI_NUMERICHOST for literal addresses), lib/curl_addrinfo.c:111-130
 *         (wrapper around getaddrinfo()).
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

#define T "01_getaddrinfo_numeric_ipv4"

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [WSA=%d GLE=%lu]\n", WSAGetLastError(), (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

int main(void)
{
  WSADATA wsa;
  struct addrinfo hints, *res = NULL, *ai;
  struct sockaddr_in *sin;
  int rc, n = 0;
  int wsa_ok = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

  rc = getaddrinfo("127.0.0.1", "8080", &hints, &res);
  if(rc != 0)
    FAILF("getaddrinfo(127.0.0.1) returned %d", rc);

  for(ai = res; ai; ai = ai->ai_next)
    n++;
  if(n != 1)
    FAILF("expected 1 result for a literal, got %d", n);

  if(res->ai_family != AF_INET)
    FAILF("ai_family=%d, expected AF_INET", res->ai_family);
  if(res->ai_socktype != SOCK_STREAM || res->ai_protocol != IPPROTO_TCP)
    FAILF("socktype/protocol=%d/%d, expected SOCK_STREAM/IPPROTO_TCP",
          res->ai_socktype, res->ai_protocol);
  if(res->ai_addrlen != (socklen_t)sizeof(struct sockaddr_in))
    FAILF("ai_addrlen=%d, expected %d", (int)res->ai_addrlen,
          (int)sizeof(struct sockaddr_in));

  sin = (struct sockaddr_in *)res->ai_addr;
  if(sin->sin_addr.S_un.S_addr != htonl(0x7F000001UL))
    FAILF("sin_addr=0x%08lx, expected 127.0.0.1",
          (unsigned long)ntohl(sin->sin_addr.S_un.S_addr));
  if(sin->sin_port != htons(8080))
    FAILF("sin_port=%u, expected 8080", (unsigned)ntohs(sin->sin_port));

  freeaddrinfo(res);
  res = NULL;

  /* A hostname must be refused under AI_NUMERICHOST: no lookup happens. */
  rc = getaddrinfo("localhost", "8080", &hints, &res);
  if(rc != EAI_NONAME)
    FAILF("AI_NUMERICHOST(localhost) returned %d, expected EAI_NONAME (%d)",
          rc, (int)EAI_NONAME);
  if(res)
    FAILF("AI_NUMERICHOST(localhost) returned a non-NULL result list");

  /* Out-of-range dotted quad is not a valid numeric host. */
  rc = getaddrinfo("127.0.0.256", "8080", &hints, &res);
  if(rc == 0)
    FAILF("AI_NUMERICHOST accepted invalid literal 127.0.0.256");

  /* Numeric service must be accepted with AI_NUMERICSERV. */
  rc = getaddrinfo("127.0.0.1", "65535", &hints, &res);
  if(rc != 0)
    FAILF("getaddrinfo(127.0.0.1, 65535) returned %d", rc);
  sin = (struct sockaddr_in *)res->ai_addr;
  if(sin->sin_port != htons(65535))
    FAILF("sin_port=%u, expected 65535", (unsigned)ntohs(sin->sin_port));

out:
  if(res)
    freeaddrinfo(res);
  if(wsa_ok)
    WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
