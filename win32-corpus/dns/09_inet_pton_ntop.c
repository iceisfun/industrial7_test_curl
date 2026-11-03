/*
 * Test 09_inet_pton_ntop
 *
 * Purpose: presentation/network conversion that curl uses to decide whether
 * a host string is already an IP literal (Curl_is_ipv4addr, Curl_is_ipaddr)
 * and to print socket addresses. Checks strict IPv4 and IPv6 parsing (return
 * values and parsed bytes), the unsupported-family error, and the inet_ntop()
 * buffer-too-small failure.
 *
 * APIs: WSAStartup, inet_pton, inet_ntop, WSAGetLastError, WSACleanup.
 *
 * Success:
 *   inet_pton(AF_INET, "127.0.0.1") == 1, bytes 7f 00 00 01.
 *   inet_pton(AF_INET, "127.0.0.256"), "1.2.3", "" and "127.0.0.1x" == 0.
 *     The contents of dst after a failed parse are not specified by the API,
 *     so they are not asserted.
 *   inet_pton(AF_INET6, "::1") == 1 and equals in6addr_loopback.
 *   inet_pton(AF_INET6, "::ffff:127.0.0.1") == 1 with IPv4-mapped bytes.
 *   inet_pton(AF_INET6, "1::2::3") == 0 and inet_pton(AF_INET6, "127.0.0.1") == 0.
 *   inet_pton(99, ...) == -1 with WSAEAFNOSUPPORT.
 *   inet_ntop(AF_INET, 127.0.0.1) == "127.0.0.1"; with a 9-byte buffer it
 *     returns NULL.
 *   inet_ntop(AF_INET6, ::1) == "::1"; the ::ffff:127.0.0.1 text round-trips
 *     back to the same 16 bytes.
 *
 * Source: lib/curlx/inet_pton.c:203-214 (curlx_inet_pton() dispatch, same
 *         contract as inet_pton), lib/curl_addrinfo.c:427-444
 *         (Curl_is_ipv4addr / Curl_is_ipaddr), lib/proxy.c:69-71
 *         (dotted-quad parse), lib/cf-socket.c:112-122 (inet_ntop use).
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

#define T "09_inet_pton_ntop"

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [WSA=%d GLE=%lu]\n", WSAGetLastError(), (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

int main(void)
{
  WSADATA wsa;
  struct in_addr v4;
  struct in6_addr v6, v6b, scratch6;
  struct in_addr scratch4;
  char buf[64];
  const char *p;
  int rc, wsa_ok = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

  /* IPv4 success. */
  memset(&v4, 0, sizeof(v4));
  rc = inet_pton(AF_INET, "127.0.0.1", &v4);
  if(rc != 1)
    FAILF("inet_pton(AF_INET, 127.0.0.1) returned %d", rc);
  if(((unsigned char *)&v4)[0] != 127 || ((unsigned char *)&v4)[3] != 1)
    FAILF("inet_pton IPv4 bytes wrong");

  /* IPv4 rejects: the documented return value is 0 for an invalid string. */
  {
    static const char *bad[] = {"127.0.0.256", "1.2.3", "", "127.0.0.1x"};
    struct in_addr scratch;
    size_t i;
    for(i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
      rc = inet_pton(AF_INET, bad[i], &scratch);
      if(rc != 0)
        FAILF("inet_pton(AF_INET, \"%s\") returned %d, expected 0", bad[i], rc);
    }
  }

  /* IPv6 loopback and IPv4-mapped literals. */
  memset(&v6, 0, sizeof(v6));
  rc = inet_pton(AF_INET6, "::1", &v6);
  if(rc != 1)
    FAILF("inet_pton(AF_INET6, ::1) returned %d", rc);
  if(!IN6_IS_ADDR_LOOPBACK(&v6))
    FAILF("::1 did not parse to the loopback address");

  rc = inet_pton(AF_INET6, "::ffff:127.0.0.1", &v6b);
  if(rc != 1)
    FAILF("inet_pton(AF_INET6, ::ffff:127.0.0.1) returned %d", rc);
  if(!IN6_IS_ADDR_V4MAPPED(&v6b))
    FAILF("::ffff:127.0.0.1 is not IPv4-mapped");

  /* IPv6 rejects. */
  rc = inet_pton(AF_INET6, "1::2::3", &scratch6);
  if(rc != 0)
    FAILF("inet_pton(AF_INET6, 1::2::3) returned %d, expected 0", rc);
  rc = inet_pton(AF_INET6, "127.0.0.1", &scratch6);
  if(rc != 0)
    FAILF("inet_pton(AF_INET6, 127.0.0.1) returned %d, expected 0", rc);

  /* Unsupported family is -1 with WSAEAFNOSUPPORT. */
  WSASetLastError(0);
  rc = inet_pton(99, "127.0.0.1", &scratch4);
  if(rc != -1)
    FAILF("inet_pton(family 99) returned %d, expected -1", rc);
  if(WSAGetLastError() != WSAEAFNOSUPPORT)
    FAILF("inet_pton(family 99) WSA error is %d, expected WSAEAFNOSUPPORT",
          WSAGetLastError());

  /* ntop: IPv4 text and buffer-too-small. */
  p = inet_ntop(AF_INET, &v4, buf, sizeof(buf));
  if(!p)
    FAILF("inet_ntop(AF_INET) returned NULL");
  if(strcmp(p, "127.0.0.1") != 0)
    FAILF("inet_ntop(AF_INET) returned '%s'", p);

  memset(&v4, 0, sizeof(v4));
  ((unsigned char *)&v4)[0] = 127;
  ((unsigned char *)&v4)[3] = 1;
  p = inet_ntop(AF_INET, &v4, buf, 9); /* "127.0.0.1" needs 10 bytes */
  if(p != NULL)
    FAILF("inet_ntop with a 9-byte buffer did not fail");

  /* ntop: IPv6 loopback text. */
  p = inet_ntop(AF_INET6, &v6, buf, sizeof(buf));
  if(!p)
    FAILF("inet_ntop(AF_INET6, ::1) returned NULL");
  if(strcmp(p, "::1") != 0)
    FAILF("inet_ntop(AF_INET6, ::1) returned '%s'", p);

  /* Round trip of the mapped address: text form may differ, bytes must not. */
  p = inet_ntop(AF_INET6, &v6b, buf, sizeof(buf));
  if(!p)
    FAILF("inet_ntop(AF_INET6, mapped) returned NULL");
  memset(&v6, 0, sizeof(v6));
  rc = inet_pton(AF_INET6, buf, &v6);
  if(rc != 1)
    FAILF("re-parsing '%s' returned %d", buf, rc);
  if(memcmp(&v6, &v6b, sizeof(v6)) != 0)
    FAILF("round trip of '%s' changed the address bytes", buf);

out:
  if(wsa_ok)
    WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
