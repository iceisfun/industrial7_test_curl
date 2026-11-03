/*
 * Test 08_gethostbyname_fallback
 *
 * Purpose: the legacy gethostbyname() path, which curl falls back to when
 * getaddrinfo() is not used (the non-IPv6, non-threaded resolver). Checks
 * that a dotted-quad literal round-trips through gethostbyname() without a
 * name lookup, and that "localhost" resolves to the IPv4 loopback address.
 *
 * APIs: WSAStartup, gethostbyname, WSAGetLastError, WSACleanup.
 *
 * Success: gethostbyname("127.0.0.1") returns a non-NULL HOSTENT with
 * h_addrtype==AF_INET, h_length==4 and h_addr_list[0] bytes 7f 00 00 01.
 * gethostbyname("localhost") returns non-NULL and its address list contains
 * 127.0.0.1. gethostbyname("127.0.0.1") returns the literal, not a name
 * lookup, so h_name must be a non-empty string.
 *
 * Source: lib/vdns/hostip4.c:126-170 (gethostbyname_r() is the reentrant
 *         form; gethostbyname() is the plain call it falls back to on
 *         platforms without the _r variant).
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
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define T "08_gethostbyname_fallback"

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [WSA=%d GLE=%lu]\n", WSAGetLastError(), (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

/* Returns 1 if any IPv4 entry in the list is 127.0.0.1. */
static int has_loopback(const struct hostent *h)
{
  int i;
  if(h->h_addrtype != AF_INET || h->h_length != 4)
    return 0;
  for(i = 0; h->h_addr_list[i]; i++) {
    const unsigned char *b = (const unsigned char *)h->h_addr_list[i];
    if(b[0] == 127 && b[1] == 0 && b[2] == 0 && b[3] == 1)
      return 1;
  }
  return 0;
}

int main(void)
{
  WSADATA wsa;
  const struct hostent *h;
  const unsigned char *b;
  int wsa_ok = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

  h = gethostbyname("127.0.0.1");
  if(!h)
    FAILF("gethostbyname(127.0.0.1) returned NULL");
  if(h->h_addrtype != AF_INET)
    FAILF("h_addrtype=%d, expected AF_INET", h->h_addrtype);
  if(h->h_length != 4)
    FAILF("h_length=%d, expected 4", h->h_length);
  if(!h->h_addr_list || !h->h_addr_list[0])
    FAILF("h_addr_list is empty for a literal");
  b = (const unsigned char *)h->h_addr_list[0];
  if(!(b[0] == 127 && b[1] == 0 && b[2] == 0 && b[3] == 1))
    FAILF("literal address bytes are %u.%u.%u.%u",
          (unsigned)b[0], (unsigned)b[1], (unsigned)b[2], (unsigned)b[3]);
  if(!h->h_name || h->h_name[0] == '\0')
    FAILF("h_name is empty for a literal");

  /* gethostbyname() returns a static buffer that the next call overwrites,
     so every check on the literal result above is finished before this call. */
  h = gethostbyname("localhost");
  if(!h)
    FAILF("gethostbyname(localhost) returned NULL, WSA error below");
  if(!has_loopback(h))
    FAILF("localhost did not include 127.0.0.1 in its IPv4 address list");

out:
  if(wsa_ok)
    WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
