/*
 * Test 17_getnameinfo_buffers_flags
 *
 * Purpose: getnameinfo() behaviour that curl relies on when it formats a peer
 * address (lib/cf-socket.c Curl_socket_addr_from_ai / socket_addr_to_string
 * use inet_ntop; getnameinfo with NI_NUMERICHOST|NI_NUMERICSERV is the
 * portable form) and when sockaddr lengths are validated. Pins the error
 * codes for undersized buffers and malformed sockaddrs, and how the IPv6
 * scope id is rendered.
 *
 * APIs: WSAStartup, getnameinfo, gethostname, GetComputerNameExA, WSACleanup.
 *
 * Success (probed on Windows 10 22H2):
 *   127.0.0.1:8080 with NI_NUMERICHOST|NI_NUMERICSERV gives "127.0.0.1" and
 *   "8080". A host buffer of 10 bytes (9 characters plus NUL) is enough; 9
 *   bytes or fewer fail with 122 (ERROR_INSUFFICIENT_BUFFER, also the value of
 *   WSAGetLastError) after writing a truncated prefix. A service buffer of 5
 *   bytes fits "8080", 4 bytes fail with 122. Omitting the host buffer
 *   (NULL, 0) or both buffers succeeds. NI_NUMERICHOST|NI_NAMEREQD succeeds
 *   numerically. A sockaddr length shorter than sockaddr_in (15 or 2 bytes)
 *   or a NULL sockaddr fails with 10014 (WSAEFAULT); a longer length is
 *   accepted; AF_UNIX fails with 10047 (WSAEAFNOSUPPORT). An undefined flag
 *   bit (0x100) is ignored. ::1 port 443 gives "::1"; a scope id is appended
 *   as "%<id>" for loopback and link-local addresses ("::1%1", "fe80::1%1",
 *   "fe80::1%999") with or without NI_NUMERICSCOPE. gethostname() returns the
 *   machine name (equal to the DNS host name), fails with 10014 for a
 *   2-byte buffer, and the reverse lookup of 127.0.0.1 without
 *   NI_NUMERICHOST returns that same machine name.
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

#define T "17_getnameinfo_buffers_flags"

#ifndef NI_NUMERICSCOPE
#define NI_NUMERICSCOPE 0x20
#endif

static int status = 0;
#define NOTE_FAIL(...) do { printf("FAIL %s: ", T); printf(__VA_ARGS__); printf("\n"); status = 1; } while(0)

static void gni(const char *tag, const struct sockaddr *sa, int len, int hl, int sl, int fl,
                int want_rc, const char *want_host, const char *want_serv)
{
  char h[256], s[64];
  int rc;
  memset(h, 'x', sizeof(h));
  memset(s, 'x', sizeof(s));
  h[sizeof(h) - 1] = 0;
  s[sizeof(s) - 1] = 0;
  WSASetLastError(0);
  rc = getnameinfo(sa, len, hl ? h : NULL, (DWORD)hl, sl ? s : NULL, (DWORD)sl, fl);
  if(rc != want_rc) {
    NOTE_FAIL("%s: returned %d, expected %d", tag, rc, want_rc);
    return;
  }
  if(rc != 0 && WSAGetLastError() != want_rc)
    NOTE_FAIL("%s: WSAGetLastError()=%d, expected %d", tag, WSAGetLastError(), want_rc);
  if(rc == 0) {
    if(want_host && strcmp(h, want_host) != 0)
      NOTE_FAIL("%s: host \"%s\", expected \"%s\"", tag, h, want_host);
    if(want_serv && strcmp(s, want_serv) != 0)
      NOTE_FAIL("%s: service \"%s\", expected \"%s\"", tag, s, want_serv);
  }
}

int main(void)
{
  WSADATA wsa;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  struct sockaddr sx;
  char hn[300], dn[300];
  DWORD n = sizeof(dn);
  const int NUM = NI_NUMERICHOST | NI_NUMERICSERV;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    printf("FAIL %s: WSAStartup failed\n", T);
    return 1;
  }
  memset(&a4, 0, sizeof(a4));
  a4.sin_family = AF_INET;
  a4.sin_port = htons(8080);
  a4.sin_addr.s_addr = htonl(0x7f000001);
  memset(&a6, 0, sizeof(a6));
  a6.sin6_family = AF_INET6;
  a6.sin6_port = htons(443);
  a6.sin6_addr = in6addr_loopback;

  gni("v4 numeric", (struct sockaddr *)&a4, sizeof(a4), 256, 32, NUM, 0, "127.0.0.1", "8080");
  gni("v4 host buffer 10", (struct sockaddr *)&a4, sizeof(a4), 10, 32, NUM, 0, "127.0.0.1", "8080");
  gni("v4 host buffer 9", (struct sockaddr *)&a4, sizeof(a4), 9, 32, NUM, 122, NULL, NULL);
  gni("v4 host buffer 4", (struct sockaddr *)&a4, sizeof(a4), 4, 32, NUM, 122, NULL, NULL);
  gni("v4 service buffer 5", (struct sockaddr *)&a4, sizeof(a4), 256, 5, NUM, 0, "127.0.0.1", "8080");
  gni("v4 service buffer 4", (struct sockaddr *)&a4, sizeof(a4), 256, 4, NUM, 122, NULL, NULL);
  gni("v4 no host buffer", (struct sockaddr *)&a4, sizeof(a4), 0, 32, NUM, 0, NULL, "8080");
  gni("v4 no buffers", (struct sockaddr *)&a4, sizeof(a4), 0, 0, NUM, 0, NULL, NULL);
  gni("v4 NUMERICHOST|NAMEREQD", (struct sockaddr *)&a4, sizeof(a4), 256, 32,
      NI_NUMERICHOST | NI_NAMEREQD | NI_NUMERICSERV, 0, "127.0.0.1", "8080");
  gni("v4 undefined flag bit", (struct sockaddr *)&a4, sizeof(a4), 256, 32, NUM | 0x100, 0, "127.0.0.1", "8080");
  gni("v4 length 15", (struct sockaddr *)&a4, sizeof(a4) - 1, 256, 32, NUM, WSAEFAULT, NULL, NULL);
  gni("v4 length 2", (struct sockaddr *)&a4, 2, 256, 32, NUM, WSAEFAULT, NULL, NULL);
  gni("v4 length 20", (struct sockaddr *)&a4, sizeof(a4) + 4, 256, 32, NUM, 0, "127.0.0.1", "8080");
  gni("NULL sockaddr", NULL, 0, 256, 32, NUM, WSAEFAULT, NULL, NULL);
  memset(&sx, 0, sizeof(sx));
  sx.sa_family = AF_UNIX;
  gni("AF_UNIX", &sx, sizeof(sx), 256, 32, NUM, WSAEAFNOSUPPORT, NULL, NULL);

  gni("v6 loopback", (struct sockaddr *)&a6, sizeof(a6), 256, 32, NUM, 0, "::1", "443");
  a6.sin6_scope_id = 1;
  gni("v6 loopback scope 1", (struct sockaddr *)&a6, sizeof(a6), 256, 32, NUM, 0, "::1%1", "443");
  a6.sin6_addr.u.Byte[0] = 0xfe;
  a6.sin6_addr.u.Byte[1] = 0x80;
  a6.sin6_addr.u.Byte[15] = 1;
  gni("fe80::1 scope 1", (struct sockaddr *)&a6, sizeof(a6), 256, 32, NUM, 0, "fe80::1%1", "443");
  gni("fe80::1 scope 1 NUMERICSCOPE", (struct sockaddr *)&a6, sizeof(a6), 256, 32, NUM | NI_NUMERICSCOPE,
      0, "fe80::1%1", "443");
  a6.sin6_scope_id = 999;
  gni("fe80::1 scope 999", (struct sockaddr *)&a6, sizeof(a6), 256, 32, NUM, 0, "fe80::1%999", "443");

  /* gethostname and the reverse lookup of the loopback address */
  if(gethostname(hn, sizeof(hn)) != 0 || hn[0] == 0)
    NOTE_FAIL("gethostname failed");
  else {
    if(!GetComputerNameExA(ComputerNameDnsHostname, dn, &n) || _stricmp(hn, dn) != 0)
      NOTE_FAIL("gethostname \"%s\" differs from the DNS host name \"%s\"", hn, dn);
    gni("reverse 127.0.0.1", (struct sockaddr *)&a4, sizeof(a4), 256, 32, NI_NUMERICSERV, 0, hn, "8080");
  }
  {
    char two[2];
    if(gethostname(two, 2) != -1 || WSAGetLastError() != WSAEFAULT)
      NOTE_FAIL("gethostname into 2 bytes: expected -1 / WSAEFAULT, got WSA %d", WSAGetLastError());
  }

  WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
