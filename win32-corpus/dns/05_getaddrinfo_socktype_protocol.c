/*
 * Test 05_getaddrinfo_socktype_protocol
 *
 * Purpose: the hints socktype/protocol pair decides what getaddrinfo()
 * returns for the same literal and port. curl sets these from the transport
 * (TCP vs UDP), so a UDP request must come back as SOCK_DGRAM/IPPROTO_UDP and
 * a TCP request as SOCK_STREAM/IPPROTO_TCP. An unknown service name under
 * AI_NUMERICSERV must be rejected.
 *
 * APIs: WSAStartup, getaddrinfo, freeaddrinfo, WSACleanup.
 *
 * Success: SOCK_DGRAM + IPPROTO_UDP request returns 0 with ai_socktype ==
 * SOCK_DGRAM and ai_protocol == IPPROTO_UDP, sin_port == htons(53). A
 * SOCK_STREAM request returns SOCK_STREAM/IPPROTO_TCP. A zero socktype with
 * zero protocol returns 0 with exactly one entry whose socktype and protocol
 * are both 0 (probed on Windows 10 22H2). A non-numeric service with
 * AI_NUMERICSERV returns non-zero.
 *
 * Source: lib/vdns/asyn-thrdd.c:401-411 (ai_socktype from
 *         Curl_socktype_for_transport(), ai_protocol from
 *         Curl_protocol_for_transport(), AI_NUMERICSERV on service).
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

#define T "05_getaddrinfo_socktype_protocol"

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
  int rc, n = 0, wsa_ok = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

  /* UDP request. */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  rc = getaddrinfo("127.0.0.1", "53", &hints, &res);
  if(rc != 0)
    FAILF("UDP getaddrinfo returned %d", rc);
  for(ai = res; ai; ai = ai->ai_next) {
    n++;
    if(ai->ai_socktype != SOCK_DGRAM)
      FAILF("UDP request returned ai_socktype=%d", ai->ai_socktype);
    if(ai->ai_protocol != IPPROTO_UDP)
      FAILF("UDP request returned ai_protocol=%d", ai->ai_protocol);
    sin = (struct sockaddr_in *)ai->ai_addr;
    if(sin->sin_port != htons(53))
      FAILF("UDP sin_port=%u, expected 53", (unsigned)ntohs(sin->sin_port));
  }
  if(n != 1)
    FAILF("UDP request returned %d entries, expected 1", n);
  freeaddrinfo(res);
  res = NULL;

  /* TCP request for the same literal and port. */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  rc = getaddrinfo("127.0.0.1", "53", &hints, &res);
  if(rc != 0)
    FAILF("TCP getaddrinfo returned %d", rc);
  if(res->ai_socktype != SOCK_STREAM || res->ai_protocol != IPPROTO_TCP)
    FAILF("TCP request returned %d/%d, expected SOCK_STREAM/IPPROTO_TCP",
          res->ai_socktype, res->ai_protocol);
  freeaddrinfo(res);
  res = NULL;

  /* Unspecified socktype and protocol: Windows 10 returns exactly one entry
     per address with ai_socktype == 0 and ai_protocol == 0 (it does NOT
     expand into TCP/UDP/RAW entries). curl always sets both from the
     transport, so it never sees this form. */
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  rc = getaddrinfo("127.0.0.1", "53", &hints, &res);
  if(rc != 0)
    FAILF("unspecified-socktype getaddrinfo returned %d", rc);
  n = 0;
  for(ai = res; ai; ai = ai->ai_next) {
    n++;
    if(ai->ai_socktype != 0 || ai->ai_protocol != 0)
      FAILF("unspecified hints: ai_socktype=%d ai_protocol=%d, expected 0/0",
            ai->ai_socktype, ai->ai_protocol);
  }
  if(n != 1)
    FAILF("unspecified-socktype request returned %d entries, expected 1", n);
  freeaddrinfo(res);
  res = NULL;

  /* A service name that is not a number must be rejected under
     AI_NUMERICSERV, without any service database lookup succeeding. */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  rc = getaddrinfo("127.0.0.1", "nosuchservice_corpus_xyz", &hints, &res);
  if(rc == 0)
    FAILF("AI_NUMERICSERV accepted a non-numeric service name");

out:
  if(res)
    freeaddrinfo(res);
  if(wsa_ok)
    WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
