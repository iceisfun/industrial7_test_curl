/*
 * Test 03_getaddrinfo_localhost_addrconfig
 *
 * Purpose: resolve "localhost" with AF_UNSPEC through getaddrinfo() both
 * plain and with AI_ADDRCONFIG|AI_CANONNAME. Verifies that every result is
 * a loopback address, that AI_ADDRCONFIG can only reduce the result set, and
 * that each entry's ai_addrlen is the size of its family's sockaddr (the
 * same size check curl applies when copying results).
 *
 * APIs: WSAStartup, getaddrinfo, freeaddrinfo, WSACleanup.
 *
 * Success: the plain call returns 0 with at least one loopback entry
 * (127.0.0.1 or ::1) and a non-NULL ai_canonname for AI_CANONNAME. The
 * AI_ADDRCONFIG call either returns 0 with only loopback entries and no more
 * entries than the plain call, or returns WSAHOST_NOT_FOUND, which
 * AI_ADDRCONFIG produces when no configured address family is usable; that
 * outcome is accepted without further checks. Each entry has
 * ai_addrlen >= sizeof(sockaddr_in) for AF_INET, or sizeof(sockaddr_in6)
 * for AF_INET6.
 *
 * Source: lib/vdns/asyn-thrdd.c:407 (AI_ADDRCONFIG set unconditionally),
 *         lib/vdns/asyn-thrdd.c:411-412 (AI_NUMERICSERV),
 *         lib/curl_addrinfo.c:135-150 (ss_size check per family),
 *         lib/curl_addrinfo.c:111-130 (wrapper).
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

#define T "03_getaddrinfo_localhost_addrconfig"

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [WSA=%d GLE=%lu]\n", WSAGetLastError(), (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

/* Returns 1 if the entry is a loopback address, 0 if not, -1 on unknown family. */
static int is_loopback(const struct addrinfo *ai)
{
  if(ai->ai_family == AF_INET) {
    const struct sockaddr_in *s4 = (const struct sockaddr_in *)ai->ai_addr;
    return ntohl(s4->sin_addr.S_un.S_addr) == 0x7F000001UL;
  }
  if(ai->ai_family == AF_INET6) {
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ai->ai_addr;
    return IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr);
  }
  return -1;
}

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
  struct addrinfo hints, *plain = NULL, *cfg = NULL, *ai;
  int rc, nplain, ncfg, wsa_ok = 0, loop_plain = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;

  rc = getaddrinfo("localhost", "80", &hints, &plain);
  if(rc != 0)
    FAILF("getaddrinfo(localhost) returned %d", rc);
  nplain = count_list(plain);
  if(nplain < 1)
    FAILF("getaddrinfo(localhost) returned an empty list");

  if(plain->ai_canonname == NULL)
    FAILF("AI_CANONNAME requested but ai_canonname is NULL");

  for(ai = plain; ai; ai = ai->ai_next) {
    int lb = is_loopback(ai);
    if(lb < 0)
      FAILF("localhost returned unexpected family %d", ai->ai_family);
    if(!lb)
      FAILF("localhost resolved to a non-loopback address");
    loop_plain++;
    if(ai->ai_family == AF_INET &&
       ai->ai_addrlen < (socklen_t)sizeof(struct sockaddr_in))
      FAILF("AF_INET ai_addrlen=%d is smaller than sockaddr_in", (int)ai->ai_addrlen);
    if(ai->ai_family == AF_INET6 &&
       ai->ai_addrlen < (socklen_t)sizeof(struct sockaddr_in6))
      FAILF("AF_INET6 ai_addrlen=%d is smaller than sockaddr_in6", (int)ai->ai_addrlen);
  }
  if(loop_plain < 1)
    FAILF("no loopback entry for localhost");

  /* AI_ADDRCONFIG may only remove entries, never add them. */
  hints.ai_flags = AI_ADDRCONFIG | AI_CANONNAME;
  rc = getaddrinfo("localhost", "80", &hints, &cfg);
  if(rc == 0) {
    ncfg = count_list(cfg);
    if(ncfg < 1)
      FAILF("AI_ADDRCONFIG returned 0 with an empty list");
    if(ncfg > nplain)
      FAILF("AI_ADDRCONFIG returned %d entries, more than plain (%d)", ncfg, nplain);
    for(ai = cfg; ai; ai = ai->ai_next) {
      if(!is_loopback(ai))
        FAILF("AI_ADDRCONFIG localhost returned a non-loopback address");
    }
  }
  else if(rc == WSAHOST_NOT_FOUND) {
    /* Documented filtering outcome: AI_ADDRCONFIG drops every entry when no
       configured address family is usable. Accepted, nothing more to check. */
  }
  else
    FAILF("AI_ADDRCONFIG getaddrinfo(localhost) returned unexpected %d", rc);

  if(cfg) {
    freeaddrinfo(cfg);
    cfg = NULL;
  }

out:
  if(plain)
    freeaddrinfo(plain);
  if(cfg)
    freeaddrinfo(cfg);
  if(wsa_ok)
    WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
