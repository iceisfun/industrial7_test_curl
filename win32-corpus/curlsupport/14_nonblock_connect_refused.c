/*
 * Test: 14_nonblock_connect_refused
 * Purpose: Failure path of curl's non-blocking TCP connect on Windows: the
 *   connect is started non-blocking, the failure is reported through the
 *   write/exception sets of select(), and the real reason is read from
 *   SO_ERROR.
 * APIs: WSAStartup, socket, bind, getsockname, listen, closesocket, connect,
 *   ioctlsocket(FIONBIO), select, FD_ISSET, getsockopt(SO_ERROR), WSAGetLastError
 * Source: lib/cf-socket.c:945-968 (verifyconnect(): after a non-blocking
 *   connect curl reads the real outcome with getsockopt(SO_ERROR) and
 *   reports it via psockerr; on _WIN32 it does SleepEx(0) first). The test
 *   reads readiness with select() and then SO_ERROR, which is the same
 *   sequence curl uses to finish a non-blocking connect.
 * Success: a loopback port with no listener refuses the connection. The
 *   non-blocking connect returns SOCKET_ERROR with WSAEWOULDBLOCK (or fails
 *   at once with WSAECONNREFUSED); select reports the socket on the write or
 *   exception set within 2 seconds; SO_ERROR is WSAECONNREFUSED (10061).
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

#define TEST_NAME "14_nonblock_connect_refused"

/* Reserve a loopback port, then close it so nothing listens there */
static int reserve_closed_port(unsigned short *port)
{
  struct sockaddr_in sa;
  int salen = (int)sizeof(sa);
  SOCKET s;

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;

  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(s == INVALID_SOCKET)
    return -1;
  if(bind(s, (struct sockaddr *)&sa, (int)sizeof(sa)) != 0 ||
     getsockname(s, (struct sockaddr *)&sa, &salen) != 0) {
    closesocket(s);
    return -1;
  }
  *port = ntohs(sa.sin_port);
  closesocket(s);
  return 0;
}

int main(void)
{
  WSADATA wsa;
  struct sockaddr_in sa;
  SOCKET s = INVALID_SOCKET;
  unsigned short port = 0;
  u_long mode;
  fd_set rd, wr, ex;
  struct timeval tv;
  int r, rc, err, soerr = 0, optlen = (int)sizeof(soerr);
  int connected_now = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa)) {
    printf("FAIL %s: WSAStartup failed\n", TEST_NAME);
    return 1;
  }

  if(reserve_closed_port(&port) != 0) {
    printf("FAIL %s: could not reserve a loopback port, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    WSACleanup();
    return 1;
  }

  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(s == INVALID_SOCKET) {
    printf("FAIL %s: socket() failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    WSACleanup();
    return 1;
  }
  mode = 1;
  if(ioctlsocket(s, FIONBIO, &mode) != 0) {
    printf("FAIL %s: ioctlsocket(FIONBIO) failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    goto fail;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(port);

  rc = connect(s, (struct sockaddr *)&sa, (int)sizeof(sa));
  if(rc == 0) {
    printf("FAIL %s: connect to closed port %u succeeded\n", TEST_NAME,
           (unsigned)port);
    goto fail;
  }
  err = WSAGetLastError();
  if(err == WSAECONNREFUSED) {
    /* Refused immediately: still a valid outcome, nothing to poll */
    connected_now = 1;
  }
  else if(err != WSAEWOULDBLOCK) {
    printf("FAIL %s: nonblocking connect failed with %d, expected "
           "WSAEWOULDBLOCK or WSAECONNREFUSED\n", TEST_NAME, err);
    goto fail;
  }

  if(!connected_now) {
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    FD_ZERO(&ex);
    FD_SET(s, &wr);
    FD_SET(s, &ex);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    r = select(0, NULL, &wr, &ex, &tv);
    if(r <= 0 || (!FD_ISSET(s, &wr) && !FD_ISSET(s, &ex))) {
      printf("FAIL %s: select did not report the refused connect (r=%d)\n",
             TEST_NAME, r);
      goto fail;
    }
  }

  if(getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &optlen) != 0) {
    printf("FAIL %s: getsockopt(SO_ERROR) failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    goto fail;
  }
  if(soerr != WSAECONNREFUSED) {
    printf("FAIL %s: SO_ERROR=%d, expected WSAECONNREFUSED (10061)\n",
           TEST_NAME, soerr);
    goto fail;
  }

  closesocket(s);
  WSACleanup();
  printf("PASS %s\n", TEST_NAME);
  return 0;

fail:
  closesocket(s);
  WSACleanup();
  return 1;
}
