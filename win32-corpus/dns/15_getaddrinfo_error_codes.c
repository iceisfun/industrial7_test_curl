/*
 * Test 15_getaddrinfo_error_codes
 *
 * Purpose: the exact error codes getaddrinfo() returns for the failure cases
 * curl's resolver code can hit (lib/curl_addrinfo.c wraps getaddrinfo() and
 * reports the returned code; lib/vdns/asyn-thrdd.c sets ai_family, ai_socktype
 * and AI_NUMERICSERV from the transport). On Windows the EAI_* values are the
 * WSA error numbers, and the function's return value equals WSAGetLastError().
 *
 * APIs: WSAStartup, getaddrinfo, freeaddrinfo, WSAGetLastError, WSACleanup.
 *
 * Success (probed on Windows 10 22H2):
 *   a numeric-only lookup of an out-of-range literal or of a hostname, a NULL
 *   node with a NULL service, and a non-numeric service name under
 *   AI_NUMERICSERV return 11001 (WSAHOST_NOT_FOUND = EAI_NONAME). An unknown
 *   service name without AI_NUMERICSERV returns 10109 (WSATYPE_NOT_FOUND =
 *   EAI_SERVICE). ai_family 999 returns 10047 (WSAEAFNOSUPPORT = EAI_FAMILY)
 *   and ai_socktype 999 returns 10044 (WSAESOCKTNOSUPPORT = EAI_SOCKTYPE). A
 *   numeric lookup with the wrong family (::1 as AF_INET, 127.0.0.1 as
 *   AF_INET6, also with AI_V4MAPPED) returns 11001. A socktype/protocol
 *   mismatch (SOCK_STREAM + IPPROTO_UDP) is NOT rejected and is echoed
 *   back. Unknown ai_flags bits are ignored. Service parsing: the service
 *   "65535" gives port 65535, "65536" wraps to 0, "-1" gives 65535, " 80"
 *   (leading space) gives 80, "0x50" is rejected with 11001 under
 *   AI_NUMERICSERV, "http" and "https" resolve through the services database
 *   to 80 and 443, and an empty or NULL service gives port 0. Entries for a
 *   numeric host carry ai_flags 0x4 (AI_NUMERICHOST) and no canonical name.
 *   The return value always equals WSAGetLastError().
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

#define T "15_getaddrinfo_error_codes"

static int status = 0;
#define NOTE_FAIL(...) do { printf("FAIL %s: ", T); printf(__VA_ARGS__); printf("\n"); status = 1; } while(0)

/* expected result of one call: want_rc 0 = success, want_port checked then */
static void probe(const char *node, const char *service, int family, int socktype,
                  int protocol, int flags, int want_rc, int want_port,
                  int want_socktype, int want_protocol)
{
  struct addrinfo hints, *res = NULL;
  int rc;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = family;
  hints.ai_socktype = socktype;
  hints.ai_protocol = protocol;
  hints.ai_flags = flags;
  rc = getaddrinfo(node, service, &hints, &res);
  if(rc != want_rc) {
    NOTE_FAIL("getaddrinfo(%s, %s, fam=%d st=%d pr=%d fl=0x%x) returned %d, expected %d",
              node ? node : "NULL", service ? service : "NULL", family, socktype,
              protocol, flags, rc, want_rc);
  }
  else if(rc != 0) {
    if(res)
      NOTE_FAIL("failed getaddrinfo(%s, %s) left a result list", node ? node : "NULL",
                service ? service : "NULL");
    if(WSAGetLastError() != rc)
      NOTE_FAIL("getaddrinfo(%s, %s): WSAGetLastError()=%d differs from return %d",
                node ? node : "NULL", service ? service : "NULL", WSAGetLastError(), rc);
  }
  else {
    int port = -1;
    if(!res)
      NOTE_FAIL("getaddrinfo(%s, %s) returned 0 with no list", node, service ? service : "NULL");
    else {
      if(res->ai_family == AF_INET)
        port = ntohs(((struct sockaddr_in *)res->ai_addr)->sin_port);
      else if(res->ai_family == AF_INET6)
        port = ntohs(((struct sockaddr_in6 *)res->ai_addr)->sin6_port);
      if(want_port >= 0 && port != want_port)
        NOTE_FAIL("getaddrinfo(%s, %s): port %d, expected %d", node,
                  service ? service : "NULL", port, want_port);
      if(want_socktype >= 0 && res->ai_socktype != want_socktype)
        NOTE_FAIL("getaddrinfo(%s, %s): ai_socktype %d, expected %d", node,
                  service ? service : "NULL", res->ai_socktype, want_socktype);
      if(want_protocol >= 0 && res->ai_protocol != want_protocol)
        NOTE_FAIL("getaddrinfo(%s, %s): ai_protocol %d, expected %d", node,
                  service ? service : "NULL", res->ai_protocol, want_protocol);
    }
  }
  if(res)
    freeaddrinfo(res);
}

int main(void)
{
  WSADATA wsa;
  struct addrinfo hints, *res = NULL;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    printf("FAIL %s: WSAStartup failed\n", T);
    return 1;
  }

  /* EAI_NONAME (11001) family */
  probe("127.0.0.256", "80", 0, 0, 0, AI_NUMERICHOST, 11001, 0, 0, 0);
  probe("localhost", "80", 0, 0, 0, AI_NUMERICHOST, 11001, 0, 0, 0);
  probe(NULL, NULL, 0, 0, 0, 0, 11001, 0, 0, 0);
  probe("127.0.0.1", "nosuch_svc", AF_INET, SOCK_STREAM, 0, AI_NUMERICSERV, 11001, 0, 0, 0);
  probe("127.0.0.1", "0x50", AF_INET, SOCK_STREAM, 0, AI_NUMERICSERV, 11001, 0, 0, 0);
  probe("::1", "80", AF_INET, SOCK_STREAM, 0, AI_NUMERICHOST, 11001, 0, 0, 0);
  probe("127.0.0.1", "80", AF_INET6, SOCK_STREAM, 0, AI_NUMERICHOST, 11001, 0, 0, 0);
  probe("127.0.0.1", "80", AF_INET6, SOCK_STREAM, 0, AI_NUMERICHOST | AI_V4MAPPED, 11001, 0, 0, 0);
  /* other EAI codes */
  probe("127.0.0.1", "nosuch_svc", AF_INET, SOCK_STREAM, 0, 0, WSATYPE_NOT_FOUND, 0, 0, 0);
  probe("127.0.0.1", "80", 999, 0, 0, 0, WSAEAFNOSUPPORT, 0, 0, 0);
  probe("127.0.0.1", "80", AF_INET, 999, 0, 0, WSAESOCKTNOSUPPORT, 0, 0, 0);
  /* accepted oddities */
  probe("127.0.0.1", "80", AF_INET, SOCK_STREAM, IPPROTO_UDP, 0, 0, 80, SOCK_STREAM, IPPROTO_UDP);
  probe("127.0.0.1", "80", AF_INET, SOCK_DGRAM, IPPROTO_TCP, 0, 0, 80, SOCK_DGRAM, IPPROTO_TCP);
  probe("127.0.0.1", "80", AF_INET, SOCK_RAW, 0, 0, 0, 80, SOCK_RAW, 0);
  probe("127.0.0.1", "80", 0, 0, 0, (int)0x40000000, 0, 80, 0, 0);
  probe("127.0.0.1", "80", 0, 0, 0, 0x00010000, 0, 80, 0, 0);
  /* service parsing */
  probe("127.0.0.1", "65535", AF_INET, SOCK_STREAM, 0, AI_NUMERICSERV, 0, 65535, -1, -1);
  probe("127.0.0.1", "65536", AF_INET, SOCK_STREAM, 0, AI_NUMERICSERV, 0, 0, -1, -1);
  probe("127.0.0.1", "-1", AF_INET, SOCK_STREAM, 0, AI_NUMERICSERV, 0, 65535, -1, -1);
  probe("127.0.0.1", " 80", AF_INET, SOCK_STREAM, 0, AI_NUMERICSERV, 0, 80, -1, -1);
  probe("127.0.0.1", "0", AF_INET, SOCK_STREAM, 0, AI_NUMERICSERV, 0, 0, -1, -1);
  probe("127.0.0.1", "", AF_INET, SOCK_STREAM, 0, 0, 0, 0, -1, -1);
  probe("127.0.0.1", NULL, AF_INET, SOCK_STREAM, 0, AI_NUMERICSERV, 0, 0, -1, -1);
  probe("127.0.0.1", "http", AF_INET, SOCK_STREAM, 0, 0, 0, 80, -1, -1);
  probe("127.0.0.1", "https", AF_INET, SOCK_STREAM, 0, 0, 0, 443, -1, -1);
  /* service name with socktype 0 selects SOCK_STREAM */
  probe("127.0.0.1", "http", AF_INET, 0, 0, 0, 0, 80, SOCK_STREAM, 0);

  /* numeric entries: ai_flags echo and no canonical name */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST;
  if(getaddrinfo("127.0.0.1", "80", &hints, &res) != 0 || !res)
    NOTE_FAIL("numeric lookup failed");
  else {
    if(res->ai_flags != AI_NUMERICHOST)
      NOTE_FAIL("numeric entry ai_flags 0x%x, expected 0x4", res->ai_flags);
    if(res->ai_canonname != NULL)
      NOTE_FAIL("numeric entry has a canonical name without AI_CANONNAME");
    if(res->ai_next != NULL)
      NOTE_FAIL("numeric lookup returned more than one entry");
    freeaddrinfo(res);
  }

  WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
