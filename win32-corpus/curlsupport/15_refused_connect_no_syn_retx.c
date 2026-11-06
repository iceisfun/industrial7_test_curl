/*
 * Test: 15_refused_connect_no_syn_retx
 * Purpose: The reason curl sets SIO_TCP_INITIAL_RTO for loopback targets: a
 *   refused loopback connect is otherwise reported only after about 2 s
 *   (one SYN retransmission), which makes "connection refused" slow.
 * APIs: WSAIoctl(SIO_TCP_INITIAL_RTO), ioctlsocket(FIONBIO), connect, select,
 *   getsockopt(SO_ERROR), RtlVerifyVersionInfo
 * Source: lib/cf-socket.c tcplocalhost (sets {Rtt 0, 0xFE} on 1709+ else
 *   {Rtt 0, 1} before connect on a loopback destination).
 * Success (probed on Windows 10 22H2, 60 connects): with MaxSynRetransmissions
 *   0xFE set on the unconnected socket, a non-blocking connect to a closed
 *   loopback port is reported (except set, SO_ERROR 10061) in under 500 ms
 *   (measured 0 ms); without it the report takes more than 1 s (measured
 *   2000-2109 ms). Needs Windows 10 1709 or later; SKIP below that or
 *   under wine.
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

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if(!(cond)) {                                                          \
      printf("FAIL %s: ", TEST_NAME);                                      \
      printf(__VA_ARGS__);                                                 \
      printf(" [line %d, WSAGetLastError=%d]\n", __LINE__,                 \
             WSAGetLastError());                                           \
      rc = 1;                                                              \
      goto out;                                                            \
    }                                                                      \
  } while(0)

__attribute__((unused)) static SOCKET tcp_listener(struct sockaddr_in *sa)
{
  int len = (int)sizeof(*sa);
  SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(l == INVALID_SOCKET)
    return l;
  memset(sa, 0, sizeof(*sa));
  sa->sin_family = AF_INET;
  sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(bind(l, (struct sockaddr *)sa, (int)sizeof(*sa)) ||
     getsockname(l, (struct sockaddr *)sa, &len) || listen(l, 4)) {
    closesocket(l);
    return INVALID_SOCKET;
  }
  return l;
}

/* blocking connected loopback pair; returns 0 on success */
__attribute__((unused)) static int tcp_pair(SOCKET *c, SOCKET *a)
{
  struct sockaddr_in sa;
  SOCKET l = tcp_listener(&sa);
  *c = *a = INVALID_SOCKET;
  if(l == INVALID_SOCKET)
    return -1;
  *c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(*c == INVALID_SOCKET || connect(*c, (struct sockaddr *)&sa, sizeof(sa))) {
    closesocket(l);
    return -1;
  }
  *a = accept(l, NULL, NULL);
  closesocket(l);
  return *a == INVALID_SOCKET ? -1 : 0;
}

__attribute__((unused)) static unsigned long ms_now(void)
{
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (unsigned long)((c.QuadPart * 1000) / f.QuadPart);
}

__attribute__((unused)) static int is_wine(void)
{
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  return nt && GetProcAddress(nt, "wine_get_version") != NULL;
}

#define TEST_NAME "15_refused_connect_no_syn_retx"

typedef struct { USHORT Rtt; UCHAR MaxSynRetransmissions; } rto_params;
#define SIO_TCP_INITIAL_RTO_ _WSAIOW(IOC_VENDOR, 17)

/* returns elapsed ms until the refused connect is reported, -1 on error */
static long refused_ms(int use_rto, int *soerr)
{
  struct sockaddr_in sa;
  SOCKET l = tcp_listener(&sa), s;
  u_long nb = 1;
  fd_set wr, ex;
  struct timeval tv;
  unsigned long t0;
  int len = (int)sizeof(*soerr), r;
  long ms;

  if(l == INVALID_SOCKET)
    return -1;
  closesocket(l); /* nothing listens on that port now */
  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(s == INVALID_SOCKET)
    return -1;
  if(use_rto) {
    rto_params p;
    DWORD b = 0;
    p.Rtt = 0;
    p.MaxSynRetransmissions = 0xFE;
    if(WSAIoctl(s, SIO_TCP_INITIAL_RTO_, &p, sizeof(p), NULL, 0, &b, NULL, NULL)) {
      closesocket(s);
      return -2;
    }
  }
  ioctlsocket(s, FIONBIO, &nb);
  t0 = ms_now();
  if(connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0 ||
     WSAGetLastError() != WSAEWOULDBLOCK) {
    closesocket(s);
    return -3;
  }
  FD_ZERO(&wr); FD_ZERO(&ex);
  FD_SET(s, &wr); FD_SET(s, &ex);
  tv.tv_sec = 6; tv.tv_usec = 0;
  r = select(0, NULL, &wr, &ex, &tv);
  ms = (long)(ms_now() - t0);
  *soerr = -1;
  getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)soerr, &len);
  closesocket(s);
  return r > 0 && FD_ISSET(s, &ex) ? ms : -4;
}

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  WSADATA wsa;
  int rc = 0, so1 = 0, so2 = 0;
  long fast, slow;
  OSVERSIONINFOEXW info;
  ULONGLONG cond = 0;
  LONG (NTAPI *fn)(OSVERSIONINFOEXW *, ULONG, ULONGLONG);

  fn = (LONG (NTAPI *)(OSVERSIONINFOEXW *, ULONG, ULONGLONG))(void *)
    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlVerifyVersionInfo");
  memset(&info, 0, sizeof(info));
  info.dwOSVersionInfoSize = sizeof(info);
  info.dwMajorVersion = 10;
  info.dwBuildNumber = 16299;
  cond = VerSetConditionMask(cond, VER_MAJORVERSION, VER_GREATER_EQUAL);
  cond = VerSetConditionMask(cond, VER_BUILDNUMBER, VER_GREATER_EQUAL);
  if(is_wine() || !fn || fn(&info, VER_MAJORVERSION | VER_BUILDNUMBER, cond)) {
    printf("SKIP %s: needs Windows 10 1709+ (wine or older system)\n", TEST_NAME);
    return 77;
  }
  if(WSAStartup(MAKEWORD(2, 2), &wsa))
    return 1;

  fast = refused_ms(1, &so1);
  printf("INFO with 0xFE: %ld ms, SO_ERROR=%d\n", fast, so1);
  CHECK(fast >= 0, "refused_ms(with rto) error %ld", fast);
  CHECK(so1 == WSAECONNREFUSED, "SO_ERROR=%d, expected 10061", so1);
  CHECK(fast < 500, "with 0xFE the refusal took %ld ms, expected < 500", fast);

  slow = refused_ms(0, &so2);
  printf("INFO without: %ld ms, SO_ERROR=%d\n", slow, so2);
  CHECK(slow >= 0, "refused_ms(without) error %ld", slow);
  CHECK(so2 == WSAECONNREFUSED, "SO_ERROR=%d, expected 10061", so2);
  CHECK(slow > 1000, "without 0xFE the refusal took only %ld ms", slow);

  printf("PASS %s\n", TEST_NAME);
out:
  WSACleanup();
  return rc;
}
