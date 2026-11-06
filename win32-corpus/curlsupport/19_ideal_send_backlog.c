/*
 * Test: 19_ideal_send_backlog
 * Purpose: curl's Windows upload tuning (cf-socket.c win_update_buffer_size
 *   / Curl_sndbuf): query the ideal send backlog and raise SO_SNDBUF to it.
 * APIs: WSAIoctl(SIO_IDEAL_SEND_BACKLOG_QUERY), WSAIoctl(SIO_IDEAL_SEND_BACKLOG_CHANGE),
 *   getsockopt/setsockopt(SO_SNDBUF)
 * Success (probed on Windows 10 22H2): the query succeeds on a connected
 *   loopback socket and returns a 4 byte ULONG > 0; setsockopt(SO_SNDBUF)
 *   with that value succeeds and getsockopt(SO_SNDBUF) returns exactly it;
 *   SIO_IDEAL_SEND_BACKLOG_CHANGE is a blocking notification (it hangs when
 *   issued synchronously); issued overlapped it returns WSA_IO_PENDING. SKIP under wine when the ioctl
 *   is not implemented.
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

#define TEST_NAME "19_ideal_send_backlog"

#ifndef SIO_IDEAL_SEND_BACKLOG_QUERY
#define SIO_IDEAL_SEND_BACKLOG_QUERY _WSAIOR(IOC_VENDOR, 29)
#endif
#ifndef SIO_IDEAL_SEND_BACKLOG_CHANGE
#define SIO_IDEAL_SEND_BACKLOG_CHANGE _WSAIO(IOC_VENDOR, 30)
#endif

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  WSADATA wsa;
  SOCKET c, a;
  int rc = 0, len, val = 0, e;
  ULONG ideal = 0;
  DWORD ret = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa))
    return 1;
  CHECK(tcp_pair(&c, &a) == 0, "pair");
  if(WSAIoctl(c, SIO_IDEAL_SEND_BACKLOG_QUERY, NULL, 0, &ideal, sizeof(ideal),
              &ret, NULL, NULL)) {
    e = WSAGetLastError();
    if(is_wine() && (e == WSAEOPNOTSUPP || e == WSAEINVAL)) {
      printf("SKIP %s: wine does not implement the ioctl (%d)\n", TEST_NAME, e);
      WSACleanup();
      return 77;
    }
    CHECK(0, "query failed with %d", e);
  }
  printf("INFO ideal backlog=%lu bytes returned=%lu\n", (unsigned long)ideal,
         (unsigned long)ret);
  CHECK(ret == sizeof(ULONG), "query returned %lu bytes", (unsigned long)ret);
  CHECK(ideal > 0, "ideal backlog is 0");
  len = sizeof(val);
  CHECK(getsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *)&val, &len) == 0, "get SNDBUF");
  printf("INFO default SO_SNDBUF=%d\n", val);
  val = (int)ideal;
  CHECK(setsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *)&val, sizeof(val)) == 0,
        "set SNDBUF");
  val = 0; len = sizeof(val);
  CHECK(getsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *)&val, &len) == 0, "get SNDBUF(2)");
  CHECK(val == (int)ideal, "SO_SNDBUF reads %d, expected %lu", val, (unsigned long)ideal);
  /* the CHANGE ioctl is a notification: it blocks until the ideal backlog
     changes, so it can only be issued overlapped and stays pending */
  {
    OVERLAPPED ov;
    int r;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = WSACreateEvent();
    ret = 0;
    r = WSAIoctl(c, SIO_IDEAL_SEND_BACKLOG_CHANGE, NULL, 0, NULL, 0, &ret,
                 &ov, NULL);
    e = WSAGetLastError();
    printf("INFO backlog change overlapped: r=%d err=%d\n", r, e);
    CHECK(r == SOCKET_ERROR && e == WSA_IO_PENDING, "change r=%d err=%d", r, e);
    closesocket(c);
    c = INVALID_SOCKET;
    WSACloseEvent(ov.hEvent);
  }

  printf("PASS %s\n", TEST_NAME);
out:
  WSACleanup();
  return rc;
}
