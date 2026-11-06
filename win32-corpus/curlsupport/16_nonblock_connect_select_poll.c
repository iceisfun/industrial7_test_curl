/*
 * Test: 16_nonblock_connect_select_poll
 * Purpose: How curl learns the outcome of a non-blocking connect on Windows,
 *   for success and for refusal, via select() and via WSAPoll().
 * APIs: ioctlsocket(FIONBIO), connect, select, WSAPoll, getsockopt(SO_ERROR),
 *   getpeername
 * Source: lib/cf-socket.c (cf_tcp_connect, verifyconnect; Curl_poll uses
 *   WSAPoll on Windows) and lib/select.c.
 * Success (probed on Windows 10 22H2): success: connect returns
 *   SOCKET_ERROR/WSAEWOULDBLOCK, select puts the socket in the write set
 *   only, WSAPoll gives revents == POLLWRNORM, SO_ERROR 0, getpeername works.
 *   Refusal (about 2 s, see test 14): select reports the EXCEPT set only;
 *   WSAPoll requesting POLLWRNORM reports POLLHUP|POLLERR|POLLWRNORM; the
 *   first SO_ERROR read is 10061 and a second read still gives 10061
 *   (unlike Linux, Windows does not clear the connect error on read).
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

#define TEST_NAME "16_nonblock_connect_select_poll"

static SOCKET nb_connect(const struct sockaddr_in *sa, int *wsaerr)
{
  u_long nb = 1;
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  ioctlsocket(s, FIONBIO, &nb);
  connect(s, (const struct sockaddr *)sa, sizeof(*sa));
  *wsaerr = WSAGetLastError();
  return s;
}

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  WSADATA wsa;
  struct sockaddr_in sa, peer;
  SOCKET l, s = INVALID_SOCKET, a = INVALID_SOCKET;
  int rc = 0, e, soerr, len, plen;
  fd_set wr, ex;
  struct timeval tv;
  WSAPOLLFD pfd;
  int pr;

  if(WSAStartup(MAKEWORD(2, 2), &wsa))
    return 1;
  l = tcp_listener(&sa);
  CHECK(l != INVALID_SOCKET, "listener");

  /* success via select */
  s = nb_connect(&sa, &e);
  CHECK(e == WSAEWOULDBLOCK, "connect error %d, expected 10035", e);
  FD_ZERO(&wr); FD_ZERO(&ex); FD_SET(s, &wr); FD_SET(s, &ex);
  tv.tv_sec = 5; tv.tv_usec = 0;
  pr = select(0, NULL, &wr, &ex, &tv);
  CHECK(pr == 1 && FD_ISSET(s, &wr) && !FD_ISSET(s, &ex),
        "success select r=%d wr=%d ex=%d", pr, FD_ISSET(s, &wr) ? 1 : 0,
        FD_ISSET(s, &ex) ? 1 : 0);
  len = sizeof(soerr); soerr = -1;
  CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &len) == 0 &&
        soerr == 0, "SO_ERROR after success is %d", soerr);
  plen = sizeof(peer);
  CHECK(getpeername(s, (struct sockaddr *)&peer, &plen) == 0 &&
        peer.sin_port == sa.sin_port, "getpeername after connect");
  a = accept(l, NULL, NULL);
  closesocket(a); closesocket(s);

  /* success via WSAPoll */
  s = nb_connect(&sa, &e);
  CHECK(e == WSAEWOULDBLOCK, "connect(2) error %d", e);
  pfd.fd = s; pfd.events = POLLWRNORM; pfd.revents = 0;
  pr = WSAPoll(&pfd, 1, 5000);
  printf("INFO poll success: r=%d revents=0x%04x\n", pr, (unsigned)pfd.revents);
  CHECK(pr == 1 && pfd.revents == POLLWRNORM, "poll success revents 0x%x",
        (unsigned)pfd.revents);
  a = accept(l, NULL, NULL);
  closesocket(a); closesocket(s);
  closesocket(l);

  /* refusal via select (l is closed: nothing listens on sa's port) */
  s = nb_connect(&sa, &e);
  CHECK(e == WSAEWOULDBLOCK, "refused connect error %d", e);
  FD_ZERO(&wr); FD_ZERO(&ex); FD_SET(s, &wr); FD_SET(s, &ex);
  tv.tv_sec = 6; tv.tv_usec = 0;
  pr = select(0, NULL, &wr, &ex, &tv);
  CHECK(pr == 1 && FD_ISSET(s, &ex) && !FD_ISSET(s, &wr),
        "refused select r=%d wr=%d ex=%d", pr, FD_ISSET(s, &wr) ? 1 : 0,
        FD_ISSET(s, &ex) ? 1 : 0);
  len = sizeof(soerr); soerr = -1;
  CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &len) == 0 &&
        soerr == WSAECONNREFUSED, "first SO_ERROR %d, expected 10061", soerr);
  len = sizeof(soerr); soerr = -1;
  CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &len) == 0,
        "second getsockopt failed");
  printf("INFO second SO_ERROR=%d\n", soerr);
  CHECK(soerr == WSAECONNREFUSED,
        "second SO_ERROR %d, expected 10061 (Windows keeps it)", soerr);
  closesocket(s);

  /* refusal via WSAPoll */
  s = nb_connect(&sa, &e);
  CHECK(e == WSAEWOULDBLOCK, "refused connect(2) error %d", e);
  pfd.fd = s; pfd.events = POLLWRNORM; pfd.revents = 0;
  pr = WSAPoll(&pfd, 1, 6000);
  printf("INFO poll refused: r=%d revents=0x%04x\n", pr, (unsigned)pfd.revents);
  CHECK(pr == 1, "refused poll returned %d", pr);
  CHECK(pfd.revents == (POLLHUP | POLLERR | POLLWRNORM),
        "refused revents 0x%x, expected HUP|ERR|WRNORM", (unsigned)pfd.revents);
  closesocket(s);

  printf("PASS %s\n", TEST_NAME);
out:
  WSACleanup();
  return rc;
}
