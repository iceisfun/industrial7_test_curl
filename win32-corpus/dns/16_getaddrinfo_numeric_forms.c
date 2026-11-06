/*
 * Test 16_getaddrinfo_numeric_forms
 *
 * Purpose: which numeric host spellings Windows treats as IP addresses.
 * curl decides whether a host is a literal with its own parser (and
 * inet_pton) and only then passes AI_NUMERICHOST to getaddrinfo()
 * (lib/vdns/hostip6.c, lib/curl_addrinfo.c). The Winsock resolver is more
 * permissive than inet_pton: it accepts the legacy inet_addr() forms
 * (shortened dotted, hex, octal, single 32-bit number) and bracketed IPv6.
 * This test pins that difference, which is why curl must not hand arbitrary
 * strings to getaddrinfo(AI_NUMERICHOST) and expect it to be strict.
 *
 * APIs: WSAStartup, getaddrinfo (AI_NUMERICHOST), inet_pton, inet_addr,
 *       freeaddrinfo, WSACleanup.
 *
 * Success (probed on Windows 10 22H2): with AF_INET + AI_NUMERICHOST the
 * hosts "127.1", "127.0.1", "0x7f.1", "0x7f000001", "2130706433",
 * "017700000001", "0177.0.0.1" and "127.000.000.001" all resolve to
 * 127.0.0.1; "1.2.3" resolves to 1.2.0.3; "0" and "0.0.0.0" to 0.0.0.0 and
 * "255.255.255.255" to itself. "127.0.0.1." (trailing dot), " 127.0.0.1",
 * "127.0.0.1 ", "127.0.0.1<TAB>", "1.2.3.4.5", "1..2", ".1.2.3" and
 * "4294967296" are rejected with 11001. With AF_INET6 the forms "::1",
 * "[::1]" (brackets accepted), "::1%1" (scope id 1), "fe80::1%1" and
 * "fe80::1%999" (scope ids are not validated) resolve; "fe80::1%lo",
 * "fe80::1%", "fe80::1%1%1", "1::2::3" and nine groups are rejected.
 * "::ffff:1.2.3.4" and "::1.2.3.4" parse. inet_pton(AF_INET) accepts only
 * the strict dotted quad (none of the shortened forms), inet_pton(AF_INET6)
 * rejects brackets and scope ids, while inet_addr accepts the legacy forms
 * (127.1, 0x7f.1, 1.2.3, 017700000001) and returns INADDR_NONE for
 * "256.1.1.1", "", "a" and "1.2.3.4x".
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

#define T "16_getaddrinfo_numeric_forms"

static int status = 0;
#define NOTE_FAIL(...) do { printf("FAIL %s: ", T); printf(__VA_ARGS__); printf("\n"); status = 1; } while(0)

/* want == NULL: must be rejected with 11001; otherwise the dotted/colon text
   the first entry prints as, and the scope id */
static void num(int family, const char *host, const char *want, unsigned long want_scope)
{
  struct addrinfo hints, *res = NULL;
  int rc;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST;
  rc = getaddrinfo(host, "80", &hints, &res);
  if(!want) {
    if(rc != 11001)
      NOTE_FAIL("getaddrinfo(\"%s\") returned %d, expected 11001", host, rc);
    if(res)
      freeaddrinfo(res);
    return;
  }
  if(rc != 0 || !res) {
    NOTE_FAIL("getaddrinfo(\"%s\") returned %d, expected success as %s", host, rc, want);
    return;
  }
  {
    char buf[64] = "";
    unsigned long scope = 0;
    if(res->ai_family == AF_INET)
      inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, buf, sizeof(buf));
    else if(res->ai_family == AF_INET6) {
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, buf, sizeof(buf));
      scope = ((struct sockaddr_in6 *)res->ai_addr)->sin6_scope_id;
    }
    if(res->ai_family != family || strcmp(buf, want) != 0)
      NOTE_FAIL("getaddrinfo(\"%s\") gave family %d %s, expected %s", host, res->ai_family, buf, want);
    if(scope != want_scope)
      NOTE_FAIL("getaddrinfo(\"%s\") scope id %lu, expected %lu", host, scope, want_scope);
  }
  freeaddrinfo(res);
}

static void pton4(const char *s, int want)
{
  struct in_addr a;
  int rc = inet_pton(AF_INET, s, &a);
  if(rc != want)
    NOTE_FAIL("inet_pton(AF_INET, \"%s\") = %d, expected %d", s, rc, want);
}

static void pton6(const char *s, int want)
{
  struct in6_addr a;
  int rc = inet_pton(AF_INET6, s, &a);
  if(rc != want)
    NOTE_FAIL("inet_pton(AF_INET6, \"%s\") = %d, expected %d", s, rc, want);
}

static void iaddr(const char *s, unsigned long want_host_order)
{
  unsigned long v = ntohl(inet_addr(s));
  if(v != want_host_order)
    NOTE_FAIL("inet_addr(\"%s\") = 0x%lx, expected 0x%lx", s, v, want_host_order);
}

int main(void)
{
  WSADATA wsa;
  static const char *const loop[] = { "127.1", "127.0.1", "0x7f.1", "0x7f000001", "2130706433",
                                      "017700000001", "0177.0.0.1", "127.000.000.001", "127.0.0.1", NULL };
  static const char *const rejected[] = { "127.0.0.1.", " 127.0.0.1", "127.0.0.1 ", "127.0.0.1\t",
                                          "1.2.3.4.5", "1..2", ".1.2.3", "4294967296", NULL };
  static const char *const v6bad[] = { "fe80::1%lo", "fe80::1%", "fe80::1%1%1", "1::2::3",
                                       "1:2:3:4:5:6:7:8:9", NULL };
  int i;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    printf("FAIL %s: WSAStartup failed\n", T);
    return 1;
  }

  for(i = 0; loop[i]; i++)
    num(AF_INET, loop[i], "127.0.0.1", 0);
  num(AF_INET, "1.2.3", "1.2.0.3", 0);
  num(AF_INET, "0", "0.0.0.0", 0);
  num(AF_INET, "0.0.0.0", "0.0.0.0", 0);
  num(AF_INET, "255.255.255.255", "255.255.255.255", 0);
  for(i = 0; rejected[i]; i++)
    num(AF_INET, rejected[i], NULL, 0);

  num(AF_INET6, "::1", "::1", 0);
  num(AF_INET6, "[::1]", "::1", 0);
  num(AF_INET6, "::1%1", "::1", 1);
  num(AF_INET6, "fe80::1%1", "fe80::1", 1);
  num(AF_INET6, "fe80::1%999", "fe80::1", 999);
  num(AF_INET6, "0:0:0:0:0:0:0:1", "::1", 0);
  num(AF_INET6, "::", "::", 0);
  num(AF_INET6, "FE80::ABCD", "fe80::abcd", 0);
  num(AF_INET6, "::ffff:1.2.3.4", "::ffff:1.2.3.4", 0);
  num(AF_INET6, "::1.2.3.4", "::1.2.3.4", 0);
  for(i = 0; v6bad[i]; i++)
    num(AF_INET6, v6bad[i], NULL, 0);

  /* inet_pton is strict */
  pton4("127.0.0.1", 1);
  pton4("255.255.255.255", 1);
  pton4("127.1", 0);
  pton4("0x7f.1", 0);
  pton4("1.2.3", 0);
  pton4("017700000001", 0);
  pton4("256.1.1.1", 0);
  pton4("", 0);
  pton4("a", 0);
  pton4("1.2.3.4x", 0);
  pton6("::1", 1);
  pton6("1:2:3:4:5:6:7:8", 1);
  pton6("::ffff:1.2.3.4", 1);
  pton6("1::", 1);
  pton6("::1%1", 0);
  pton6("[::1]", 0);
  pton6("fe80::1%1", 0);
  pton6(":::", 0);
  pton6("::g", 0);
  { struct in_addr a; if(inet_pton(99, "1", &a) != -1 || WSAGetLastError() != WSAEAFNOSUPPORT)
      NOTE_FAIL("inet_pton(99) should return -1 with WSAEAFNOSUPPORT"); }

  /* inet_addr is the legacy parser */
  iaddr("127.0.0.1", 0x7f000001UL);
  iaddr("127.1", 0x7f000001UL);
  iaddr("0x7f.1", 0x7f000001UL);
  iaddr("017700000001", 0x7f000001UL);
  iaddr("1.2.3", 0x01020003UL);
  iaddr("255.255.255.255", 0xffffffffUL);
  iaddr("256.1.1.1", 0xffffffffUL);
  iaddr("", 0xffffffffUL);
  iaddr("a", 0xffffffffUL);
  iaddr("1.2.3.4x", 0xffffffffUL);

  WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
