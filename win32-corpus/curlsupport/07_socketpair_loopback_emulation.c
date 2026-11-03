/*
 * Test: 07_socketpair_loopback_emulation
 * Purpose: Replicate curl's Windows socketpair emulation (a connected pair
 *   over 127.0.0.1) that backs the wakeup channel for the multi/event code.
 * APIs: WSAStartup, socket, setsockopt(SO_EXCLUSIVEADDRUSE), bind,
 *   getsockname, listen, connect, accept, ioctlsocket(FIONBIO), send, recv,
 *   closesocket, WSAGetLastError
 * Source: lib/socketpair.c:160-205 (wakeup_inet). On _WIN32 the listener
 *   skips SO_REUSEADDR and sets SO_EXCLUSIVEADDRUSE instead (socketpair.c:
 *   185-192), binds INADDR_LOOPBACK port 0, reads the port back with
 *   getsockname, connects a second socket and accepts. curl then closes the
 *   listener; this test keeps it open (emulate_socketpair's held_listener
 *   argument) so the exclusivity probe can run, and closes it afterwards.
 *   The non-blocking switch is applied to both ends.
 * Success: the exclusive option is accepted; a second socket with
 *   SO_REUSEADDR cannot bind the same loopback port while the listener holds
 *   it (WSAEACCES on Windows, WSAEADDRINUSE also accepted; this is why curl
 *   avoids SO_REUSEADDR here);
 *   after pairing, a byte written on one end is read on the other, and an
 *   empty non-blocking read returns WSAEWOULDBLOCK.
 * SKIP: SO_EXCLUSIVEADDRUSE is not implemented (WSAENOPROTOOPT), for
 *   example under wine.
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

#define TEST_NAME "07_socketpair_loopback_emulation"

#ifndef SO_EXCLUSIVEADDRUSE
#define SO_EXCLUSIVEADDRUSE ((int)(~SO_REUSEADDR))
#endif

/* Returns 0 on success. On failure *err holds WSAGetLastError() and
   *skip is set when the exclusive option is unsupported. */
static int emulate_socketpair(SOCKET socks[2], int *err, int *skip,
                              unsigned short *port_out, SOCKET *held_listener)
{
  struct sockaddr_in sa;
  int salen = (int)sizeof(sa);
  int exclusive = 1;
  SOCKET listener;
  u_long mode;

  socks[0] = socks[1] = INVALID_SOCKET;
  *skip = 0;

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;

  listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(listener == INVALID_SOCKET) {
    *err = WSAGetLastError();
    return -1;
  }

  /* socketpair.c:185-192 */
  if(setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                (char *)&exclusive, (int)sizeof(exclusive)) == -1) {
    *err = WSAGetLastError();
    if(*err == WSAENOPROTOOPT)
      *skip = 1;
    closesocket(listener);
    return -1;
  }

  if(bind(listener, (struct sockaddr *)&sa, (int)sizeof(sa)) != 0 ||
     getsockname(listener, (struct sockaddr *)&sa, &salen) != 0 ||
     listen(listener, 1) != 0) {
    *err = WSAGetLastError();
    closesocket(listener);
    return -1;
  }
  *port_out = ntohs(sa.sin_port);

  socks[1] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(socks[1] == INVALID_SOCKET ||
     connect(socks[1], (struct sockaddr *)&sa, (int)sizeof(sa)) != 0) {
    *err = WSAGetLastError();
    closesocket(listener);
    return -1;
  }
  socks[0] = accept(listener, NULL, NULL);
  if(socks[0] == INVALID_SOCKET) {
    *err = WSAGetLastError();
    closesocket(listener);
    return -1;
  }

  /* Keep the listener open only when the caller wants to probe it. */
  if(held_listener)
    *held_listener = listener;
  else
    closesocket(listener);

  /* Non-blocking on both ends, like curlx_nonblock() in socketpair.c */
  mode = 1;
  if(ioctlsocket(socks[0], FIONBIO, &mode) != 0 ||
     ioctlsocket(socks[1], FIONBIO, &mode) != 0) {
    *err = WSAGetLastError();
    return -1;
  }
  return 0;
}

int main(void)
{
  WSADATA wsa;
  SOCKET socks[2] = { INVALID_SOCKET, INVALID_SOCKET };
  SOCKET held = INVALID_SOCKET, probe;
  struct sockaddr_in sa;
  unsigned short port = 0;
  int err = 0, skip = 0;
  int reuse = 1;
  char buf[4];
  int n;

  if(WSAStartup(MAKEWORD(2, 2), &wsa)) {
    printf("FAIL %s: WSAStartup failed\n", TEST_NAME);
    return 1;
  }

  if(emulate_socketpair(socks, &err, &skip, &port, &held) != 0) {
    if(skip) {
      printf("SKIP %s: SO_EXCLUSIVEADDRUSE not supported (WSAENOPROTOOPT)\n",
             TEST_NAME);
      WSACleanup();
      return 77;
    }
    printf("FAIL %s: socketpair emulation failed, WSAGetLastError=%d\n",
           TEST_NAME, err);
    WSACleanup();
    return 1;
  }

  /* The listener is still bound: a SO_REUSEADDR socket must not take the
     same port because the listener holds it exclusively. */
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(port);
  probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(probe == INVALID_SOCKET) {
    printf("FAIL %s: probe socket() failed\n", TEST_NAME);
    goto fail;
  }
  setsockopt(probe, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
             (int)sizeof(reuse));
  if(bind(probe, (struct sockaddr *)&sa, (int)sizeof(sa)) == 0) {
    printf("FAIL %s: second bind to exclusive loopback port %u succeeded\n",
           TEST_NAME, (unsigned)port);
    closesocket(probe);
    goto fail;
  }
  /* SO_EXCLUSIVEADDRUSE conflicts are reported as WSAEACCES by Windows
     (documented for SO_EXCLUSIVEADDRUSE); WSAEADDRINUSE is accepted too. */
  if(WSAGetLastError() != WSAEACCES && WSAGetLastError() != WSAEADDRINUSE) {
    printf("FAIL %s: second bind failed with %d, expected WSAEACCES or "
           "WSAEADDRINUSE\n", TEST_NAME, WSAGetLastError());
    closesocket(probe);
    goto fail;
  }
  closesocket(probe);
  closesocket(held);
  held = INVALID_SOCKET;

  /* Wakeup-style round trip */
  if(send(socks[1], "w", 1, 0) != 1) {
    printf("FAIL %s: send on wakeup end failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    goto fail;
  }
  {
    int tries;
    n = SOCKET_ERROR;
    for(tries = 0; tries < 200 && n == SOCKET_ERROR; tries++) {
      n = recv(socks[0], buf, (int)sizeof(buf), 0);
      if(n == SOCKET_ERROR) {
        if(WSAGetLastError() != WSAEWOULDBLOCK) {
          printf("FAIL %s: recv failed, WSAGetLastError=%d\n",
                 TEST_NAME, WSAGetLastError());
          goto fail;
        }
        Sleep(10);
      }
    }
  }
  if(n != 1 || buf[0] != 'w') {
    printf("FAIL %s: wakeup read returned %d bytes, expected 1 'w'\n",
           TEST_NAME, n);
    goto fail;
  }

  /* Nothing pending now: the non-blocking read must report WSAEWOULDBLOCK */
  n = recv(socks[0], buf, (int)sizeof(buf), 0);
  if(n != SOCKET_ERROR || WSAGetLastError() != WSAEWOULDBLOCK) {
    printf("FAIL %s: drained read returned %d, expected WSAEWOULDBLOCK\n",
           TEST_NAME, n);
    goto fail;
  }

  closesocket(socks[0]);
  closesocket(socks[1]);
  WSACleanup();
  printf("PASS %s\n", TEST_NAME);
  return 0;

fail:
  if(held != INVALID_SOCKET)
    closesocket(held);
  if(socks[0] != INVALID_SOCKET)
    closesocket(socks[0]);
  if(socks[1] != INVALID_SOCKET)
    closesocket(socks[1]);
  WSACleanup();
  return 1;
}
