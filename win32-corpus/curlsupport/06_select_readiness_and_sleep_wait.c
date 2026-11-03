/*
 * Test: 06_select_readiness_and_sleep_wait
 * Purpose: Mirror the two wait primitives curl uses on Windows: Sleep() for
 *   a pure timeout with no sockets, and select() on fd sets for readiness.
 * APIs: WSAStartup, socket, bind, getsockname, listen, connect, accept,
 *   select, FD_ZERO, FD_SET, FD_ISSET, Sleep, GetTickCount64, send
 * Source: lib/curlx/wait.c:70-80 (Winsock: with no fds curl waits with
 *   Sleep((DWORD)timeout_ms) instead of select, so the no-fd sleep is
 *   tested here too). select() readiness is the path curl's Curl_poll
 *   fallback uses for Windows sockets.
 * Success: Sleep(100) elapses at least ~80 ms by GetTickCount64; select()
 *   on an idle socket with a 50 ms timeout returns 0 and FD_ISSET is false;
 *   after the peer sends one byte, select() on the server side returns 1 and
 *   FD_ISSET is true; a connected client socket is immediately writable.
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

#define TEST_NAME "06_select_readiness_and_sleep_wait"

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
  SOCKET server = INVALID_SOCKET, client = INVALID_SOCKET;
  fd_set rd, wr;
  struct timeval tv;
  ULONGLONG t0, elapsed;
  int r;
  int err = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa)) {
    printf("FAIL %s: WSAStartup failed\n", TEST_NAME);
    return 1;
  }

  /* 1. Sleep-based timeout with no sockets (curlx/wait.c Windows path) */
  t0 = GetTickCount64();
  Sleep(100);
  elapsed = GetTickCount64() - t0;
  if(elapsed < 80) {
    printf("FAIL %s: Sleep(100) elapsed only %llu ms\n", TEST_NAME,
           (unsigned long long)elapsed);
    WSACleanup();
    return 1;
  }

  client = make_tcp_pair(&server, &err);
  if(client == INVALID_SOCKET) {
    printf("FAIL %s: loopback pair setup failed, WSAGetLastError=%d\n",
           TEST_NAME, err);
    WSACleanup();
    return 1;
  }

  /* 2. Idle socket: select with a 50 ms timeout returns 0 */
  FD_ZERO(&rd);
  FD_SET(server, &rd);
  tv.tv_sec = 0;
  tv.tv_usec = 50000;
  r = select(0, &rd, NULL, NULL, &tv);
  if(r != 0 || FD_ISSET(server, &rd)) {
    printf("FAIL %s: idle select returned %d (expected 0), WSAGetLastError=%d\n",
           TEST_NAME, r, WSAGetLastError());
    goto fail;
  }

  /* 3. Send one byte: select must report the server side readable */
  if(send(client, "x", 1, 0) != 1) {
    printf("FAIL %s: send failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    goto fail;
  }
  FD_ZERO(&rd);
  FD_SET(server, &rd);
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  r = select(0, &rd, NULL, NULL, &tv);
  if(r != 1 || !FD_ISSET(server, &rd)) {
    printf("FAIL %s: readable select returned %d (expected 1)\n",
           TEST_NAME, r);
    goto fail;
  }

  /* 4. Client socket is writable right away */
  FD_ZERO(&wr);
  FD_SET(client, &wr);
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  r = select(0, NULL, &wr, NULL, &tv);
  if(r != 1 || !FD_ISSET(client, &wr)) {
    printf("FAIL %s: writable select returned %d (expected 1)\n",
           TEST_NAME, r);
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
