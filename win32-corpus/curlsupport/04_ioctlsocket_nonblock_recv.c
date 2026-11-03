/*
 * Test: 04_ioctlsocket_nonblock_recv
 * Purpose: Mirror curl's socket non-blocking switch and the WSAEWOULDBLOCK
 *   behaviour its I/O loops depend on.
 * APIs: WSAStartup, socket, bind, getsockname, listen, connect, accept,
 *   ioctlsocket(FIONBIO), recv, send, Sleep, WSAGetLastError, WSACleanup
 * Source: lib/curlx/nonblock.c:81 (curlx_nonblock calls
 *   ioctlsocket(sockfd, (long)FIONBIO, &flags) on Windows). Curl's
 *   non-blocking I/O relies on WSAEWOULDBLOCK meaning "no data yet".
 * Success: ioctlsocket(FIONBIO, 1) returns 0, recv with no pending data
 *   returns SOCKET_ERROR with WSAEWOULDBLOCK (10035), recv after the peer
 *   sends "abc" returns 3 bytes, and switching back to blocking mode with
 *   ioctlsocket(FIONBIO, 0) returns 0.
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

#define TEST_NAME "04_ioctlsocket_nonblock_recv"

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
  u_long mode;
  char buf[16];
  int n = 0, tries;
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

  mode = 1;
  if(ioctlsocket(client, FIONBIO, &mode) != 0) {
    printf("FAIL %s: ioctlsocket(FIONBIO, 1) failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    goto fail;
  }

  /* Nothing has been sent yet: must not block, must report WSAEWOULDBLOCK */
  n = recv(client, buf, (int)sizeof(buf), 0);
  if(n != SOCKET_ERROR || WSAGetLastError() != WSAEWOULDBLOCK) {
    printf("FAIL %s: empty non-blocking recv returned %d, "
           "WSAGetLastError=%d (expected SOCKET_ERROR/WSAEWOULDBLOCK)\n",
           TEST_NAME, n, WSAGetLastError());
    goto fail;
  }

  if(send(server, "abc", 3, 0) != 3) {
    printf("FAIL %s: send returned fewer bytes, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    goto fail;
  }

  /* Loopback delivery is asynchronous, poll for up to 2 seconds */
  n = SOCKET_ERROR;
  for(tries = 0; tries < 200; tries++) {
    n = recv(client, buf, (int)sizeof(buf), 0);
    if(n != SOCKET_ERROR)
      break;
    if(WSAGetLastError() != WSAEWOULDBLOCK) {
      printf("FAIL %s: recv failed with WSAGetLastError=%d\n",
             TEST_NAME, WSAGetLastError());
      goto fail;
    }
    Sleep(10);
  }
  if(n != 3 || memcmp(buf, "abc", 3) != 0) {
    printf("FAIL %s: recv after send returned %d bytes (expected 3 'abc')\n",
           TEST_NAME, n);
    goto fail;
  }

  mode = 0;
  if(ioctlsocket(client, FIONBIO, &mode) != 0) {
    printf("FAIL %s: ioctlsocket(FIONBIO, 0) failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    goto fail;
  }

  closesocket(client);
  closesocket(server);
  WSACleanup();
  printf("PASS %s\n", TEST_NAME);
  return 0;

fail:
  closesocket(client);
  closesocket(server);
  WSACleanup();
  return 1;
}
