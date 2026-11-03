/*
 * Test: 02_wsaioctl_keepalive
 * Purpose: Mirror curl's Windows TCP keepalive setup on a connected socket.
 * APIs: WSAStartup, socket, bind, getsockname, listen, connect, accept,
 *   WSAIoctl(SIO_KEEPALIVE_VALS), getsockopt(SO_KEEPALIVE), closesocket,
 *   WSACleanup
 * Source: lib/cf-socket.c:248-270. On _WIN32 with USE_WINSOCK curl defines
 *   SIO_KEEPALIVE_VALS as _WSAIOW(IOC_VENDOR, 4), fills a struct
 *   tcp_keepalive {onoff, keepalivetime, keepaliveinterval} (u_long fields,
 *   times in milliseconds) and calls WSAIoctl with no output buffer.
 * Success: WSAIoctl returns 0 and the socket reports SO_KEEPALIVE != 0 after
 *   the call, proving that onoff=1 took effect.
 * SKIP: WSAIoctl reports WSAEOPNOTSUPP (wine without the ioctl).
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

#define TEST_NAME "02_wsaioctl_keepalive"

#ifndef SIO_KEEPALIVE_VALS
#define SIO_KEEPALIVE_VALS _WSAIOW(IOC_VENDOR, 4)
#endif

/* Same layout curl declares in lib/cf-socket.c:250-254 */
struct curl_test_tcp_keepalive {
  u_long onoff;
  u_long keepalivetime;
  u_long keepaliveinterval;
};

/* Loopback TCP pair: returns the connected client, *accepted is the server
   side. On failure returns INVALID_SOCKET and sets *err. */
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

int main(void)
{
  WSADATA wsa;
  SOCKET server = INVALID_SOCKET, client;
  struct curl_test_tcp_keepalive vals;
  DWORD dummy = 0;
  int err = 0;
  int optval = 0;
  int optlen = (int)sizeof(optval);
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

  /* curl: keepidle 60s and keepintvl 60s are converted to milliseconds */
  memset(&vals, 0, sizeof(vals));
  vals.onoff = 1;
  vals.keepalivetime = 60000u;
  vals.keepaliveinterval = 60000u;

  rc = WSAIoctl(client, SIO_KEEPALIVE_VALS, (LPVOID)&vals, (DWORD)sizeof(vals),
                NULL, 0, &dummy, NULL, NULL);
  if(rc != 0) {
    int werr = WSAGetLastError();
    closesocket(client);
    closesocket(server);
    WSACleanup();
    if(werr == WSAEOPNOTSUPP) {
      printf("SKIP %s: SIO_KEEPALIVE_VALS not supported (WSAEOPNOTSUPP)\n",
             TEST_NAME);
      return 77;
    }
    printf("FAIL %s: WSAIoctl(SIO_KEEPALIVE_VALS) returned %d, "
           "WSAGetLastError=%d\n", TEST_NAME, rc, werr);
    return 1;
  }

  if(getsockopt(client, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval,
                &optlen) != 0) {
    printf("FAIL %s: getsockopt(SO_KEEPALIVE) failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    closesocket(client);
    closesocket(server);
    WSACleanup();
    return 1;
  }
  if(optval == 0) {
    printf("FAIL %s: SO_KEEPALIVE still 0 after SIO_KEEPALIVE_VALS onoff=1\n",
           TEST_NAME);
    closesocket(client);
    closesocket(server);
    WSACleanup();
    return 1;
  }

  closesocket(client);
  closesocket(server);
  WSACleanup();
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
