/*
 * Test: 03_wsaioctl_initial_rto
 * Purpose: Mirror curl's localhost-only SYN retransmission tuning on Windows.
 * APIs: WSAStartup, socket, bind, getsockname, listen, connect, accept,
 *   WSAIoctl(SIO_TCP_INITIAL_RTO), closesocket, WSACleanup
 * Source: lib/cf-socket.c:1206-1248 (tcplocalhost). For a loopback target
 *   curl sets TCP_INITIAL_RTO_PARAMETERS {Rtt = 0, MaxSynRetransmissions}
 *   where MaxSynRetransmissions is TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS
 *   (0xFE) on Windows 10 1709+ (10.0.16299, checked at cf-socket.c:1241)
 *   and 1 on older systems, then calls WSAIoctl with no output buffer.
 *   curl ignores the result, so this test checks the return value directly.
 *   The 0xFE variant is only exercised on 10.0.16299 and later, matching
 *   curl; the 1-retransmission variant runs everywhere.
 * Success: the WSAIoctl call(s) return 0 on a connected loopback TCP socket.
 * SKIP: the ioctl is not implemented by this Winsock (WSAEOPNOTSUPP), for
 *   example under wine. Any other error is a FAIL.
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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "03_wsaioctl_initial_rto"

#ifndef SIO_TCP_INITIAL_RTO
#define SIO_TCP_INITIAL_RTO _WSAIOW(IOC_VENDOR, 17)
#endif
#ifndef TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS
#define TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS 0xFE /* -2 */
#endif

/* Layout as declared in lib/cf-socket.c:1211-1214 */
typedef struct curl_test_rto_params {
  USHORT Rtt;
  UCHAR MaxSynRetransmissions;
} curl_test_rto_params;

static SOCKET make_tcp_pair(SOCKET *accepted, int *err)
{
  struct sockaddr_in sa;
  int salen = (int)sizeof(sa);
  SOCKET listener, client;

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;

  listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(listener == INVALID_SOCKET) {
    *err = WSAGetLastError();
    return INVALID_SOCKET;
  }
  if(bind(listener, (struct sockaddr *)&sa, (int)sizeof(sa)) != 0 ||
     getsockname(listener, (struct sockaddr *)&sa, &salen) != 0 ||
     listen(listener, 1) != 0) {
    *err = WSAGetLastError();
    closesocket(listener);
    return INVALID_SOCKET;
  }
  client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(client == INVALID_SOCKET) {
    *err = WSAGetLastError();
    closesocket(listener);
    return INVALID_SOCKET;
  }
  if(connect(client, (struct sockaddr *)&sa, (int)sizeof(sa)) != 0) {
    *err = WSAGetLastError();
    closesocket(client);
    closesocket(listener);
    return INVALID_SOCKET;
  }
  *accepted = accept(listener, NULL, NULL);
  closesocket(listener);
  if(*accepted == INVALID_SOCKET) {
    *err = WSAGetLastError();
    closesocket(client);
    return INVALID_SOCKET;
  }
  return client;
}

/* Returns 0 on success, -1 on a real failure, 77 when the ioctl is absent
   (WSAEOPNOTSUPP is the only error that means "not implemented"). */
static int set_rto(SOCKET s, UCHAR max_syn, const char *label)
{
  curl_test_rto_params rto;
  DWORD bytes = 0;
  int rc, werr;

  memset(&rto, 0, sizeof(rto));
  rto.Rtt = 0; /* TCP_INITIAL_RTO_DEFAULT_RTT */
  rto.MaxSynRetransmissions = max_syn;

  rc = WSAIoctl(s, SIO_TCP_INITIAL_RTO, &rto, (DWORD)sizeof(rto),
                NULL, 0, &bytes, NULL, NULL);
  if(rc == 0)
    return 0;
  werr = WSAGetLastError();
  if(werr == WSAEOPNOTSUPP)
    return 77;
  printf("FAIL %s: %s WSAIoctl(SIO_TCP_INITIAL_RTO) returned %d, "
         "WSAGetLastError=%d\n", TEST_NAME, label, rc, werr);
  return -1;
}

/* Mirrors curlx_verify_windows_version(10, 0, 16299, ..., GREATER_EQUAL)
   from cf-socket.c:1241. VerifyVersionInfoW is in kernel32, so it is linked
   directly. Returns non-zero when the OS is 10.0.16299 or later. */
static int os_is_1709_or_later(void)
{
  OSVERSIONINFOEXW info;
  DWORDLONG cond = 0;
  DWORD mask = VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER;

  memset(&info, 0, sizeof(info));
  info.dwOSVersionInfoSize = sizeof(info);
  info.dwMajorVersion = 10;
  info.dwMinorVersion = 0;
  info.dwBuildNumber = 16299;
  cond = VerSetConditionMask(cond, VER_MAJORVERSION, VER_GREATER_EQUAL);
  cond = VerSetConditionMask(cond, VER_MINORVERSION, VER_GREATER_EQUAL);
  cond = VerSetConditionMask(cond, VER_BUILDNUMBER, VER_GREATER_EQUAL);
  return VerifyVersionInfoW(&info, mask, cond) ? 1 : 0;
}

int main(void)
{
  WSADATA wsa;
  SOCKET server = INVALID_SOCKET, client;
  int err = 0;
  int rc;

  rc = WSAStartup(MAKEWORD(2, 2), &wsa);
  if(rc) {
    printf("FAIL %s: WSAStartup returned %d\n", TEST_NAME, rc);
    return 1;
  }

  client = make_tcp_pair(&server, &err);
  if(client == INVALID_SOCKET) {
    printf("FAIL %s: loopback pair setup failed, WSAGetLastError=%d\n",
           TEST_NAME, err);
    WSACleanup();
    return 1;
  }

  /* Windows 10 1709+ variant: zero SYN retransmissions (only on 1709+,
     as curl does; older systems reject it) */
  if(os_is_1709_or_later()) {
    rc = set_rto(client, TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS, "no-syn-retx");
    if(rc != 0) {
      closesocket(client);
      closesocket(server);
      WSACleanup();
      if(rc == 77) {
        printf("SKIP %s: SIO_TCP_INITIAL_RTO not supported by this Winsock\n",
               TEST_NAME);
        return 77;
      }
      return 1;
    }
  }

  /* Pre-1709 variant: one SYN retransmission, valid on every version */
  rc = set_rto(client, 1, "one-syn-retx");
  closesocket(client);
  closesocket(server);
  WSACleanup();
  if(rc == 77) {
    printf("SKIP %s: SIO_TCP_INITIAL_RTO not supported by this Winsock\n",
           TEST_NAME);
    return 77;
  }
  if(rc != 0)
    return 1;

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
