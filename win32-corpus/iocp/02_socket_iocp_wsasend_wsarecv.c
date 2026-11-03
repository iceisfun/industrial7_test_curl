/*
 * 02_socket_iocp_wsasend_wsarecv
 *
 * Purpose: associate two overlapped TCP sockets with one completion port
 *   (client with key 0x1234, server with key 0x5678) and drive them with
 *   overlapped WSASend and WSARecv, the way an IOCP based transfer engine
 *   does. Also checks the end-of-stream completion after the peer closes.
 * APIs: WSAStartup, WSASocketW (WSA_FLAG_OVERLAPPED), bind, listen, accept,
 *   connect, getsockname, CreateIoCompletionPort (socket association),
 *   WSASend, WSARecv, GetQueuedCompletionStatus, closesocket.
 * Success: the send completes with key 0x1234 and 10 bytes; the receive
 *   completes with key 0x5678, 10 bytes and the payload "hello iocp"; after
 *   the client closes, a new WSARecv completes with TRUE and 0 bytes
 *   (graceful end of stream, not an error).
 * Source: curl does not use IOCP for sockets (it uses WSAEventSelect, see
 *   lib/multi.c:1389). This covers the generic socket IOCP contract.
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
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_NAME "02_socket_iocp_wsasend_wsarecv"
#define KEY_CLIENT ((ULONG_PTR)0x1234)
#define KEY_SERVER ((ULONG_PTR)0x5678)

static void fail_exit(const char *why, DWORD err)
{
  printf("FAIL %s: %s (err=%lu)\n", TEST_NAME, why, (unsigned long)err);
  exit(1);
}

static SOCKET make_socket(void)
{
  SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                        WSA_FLAG_OVERLAPPED);
  if(s == INVALID_SOCKET)
    fail_exit("WSASocketW(WSA_FLAG_OVERLAPPED)", (DWORD)WSAGetLastError());
  return s;
}

/* Build a connected loopback TCP pair. *server receives the accepted side. */
static SOCKET loopback_pair(SOCKET *server)
{
  struct sockaddr_in sa;
  int salen = sizeof(sa);
  SOCKET listener = make_socket();
  SOCKET client = make_socket();

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;
  if(bind(listener, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR)
    fail_exit("bind", (DWORD)WSAGetLastError());
  if(getsockname(listener, (struct sockaddr *)&sa, &salen) == SOCKET_ERROR)
    fail_exit("getsockname", (DWORD)WSAGetLastError());
  if(listen(listener, 1) == SOCKET_ERROR)
    fail_exit("listen", (DWORD)WSAGetLastError());
  if(connect(client, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR)
    fail_exit("connect", (DWORD)WSAGetLastError());
  *server = accept(listener, NULL, NULL);
  if(*server == INVALID_SOCKET)
    fail_exit("accept", (DWORD)WSAGetLastError());
  closesocket(listener);
  return client;
}

/* Dequeue one packet and verify key, byte count and OVERLAPPED identity. */
static void expect_packet(HANDLE port, OVERLAPPED *expect, ULONG_PTR key,
                          DWORD want_bytes, BOOL want_ok, const char *what)
{
  OVERLAPPED *done = NULL;
  DWORD bytes = 0;
  ULONG_PTR got_key = 0;
  BOOL ok = GetQueuedCompletionStatus(port, &bytes, &got_key, &done, 5000);
  DWORD gle = GetLastError();

  if(!done)
    fail_exit(what, gle);
  if(done != expect) {
    printf("FAIL %s: %s wrong OVERLAPPED\n", TEST_NAME, what);
    exit(1);
  }
  if(got_key != key) {
    printf("FAIL %s: %s key=0x%llx expected 0x%llx\n", TEST_NAME, what,
           (unsigned long long)got_key, (unsigned long long)key);
    exit(1);
  }
  if(ok != want_ok) {
    printf("FAIL %s: %s ok=%d expected %d (gle=%lu)\n", TEST_NAME, what,
           (int)ok, (int)want_ok, (unsigned long)gle);
    exit(1);
  }
  if(bytes != want_bytes) {
    printf("FAIL %s: %s bytes=%lu expected %lu\n", TEST_NAME, what,
           (unsigned long)bytes, (unsigned long)want_bytes);
    exit(1);
  }
}

int main(void)
{
  WSADATA wsa;
  SOCKET server = INVALID_SOCKET, client;
  HANDLE port;
  WSABUF buf;
  OVERLAPPED ovs, ovr, ovz;
  char rbuf[64];
  DWORD sent = 0, rcvd = 0, flags = 0;
  const char payload[] = "hello iocp";

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    fail_exit("WSAStartup", (DWORD)WSAGetLastError());

  client = loopback_pair(&server);

  port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  if(!port)
    fail_exit("CreateIoCompletionPort(port)", GetLastError());
  if(CreateIoCompletionPort((HANDLE)client, port, KEY_CLIENT, 0) != port)
    fail_exit("associate client socket", GetLastError());
  if(CreateIoCompletionPort((HANDLE)server, port, KEY_SERVER, 0) != port)
    fail_exit("associate server socket", GetLastError());

  /* Overlapped send. Success or WSA_IO_PENDING, both post a packet. */
  memset(&ovs, 0, sizeof ovs);
  buf.buf = (char *)payload;
  buf.len = 10;
  if(WSASend(client, &buf, 1, &sent, 0, &ovs, NULL) == SOCKET_ERROR &&
     WSAGetLastError() != WSA_IO_PENDING)
    fail_exit("WSASend(overlapped)", (DWORD)WSAGetLastError());
  expect_packet(port, &ovs, KEY_CLIENT, 10, TRUE, "send packet");

  /* Overlapped receive into a 64 byte buffer. */
  memset(&ovr, 0, sizeof ovr);
  memset(rbuf, 0, sizeof rbuf);
  buf.buf = rbuf;
  buf.len = sizeof(rbuf);
  flags = 0;
  if(WSARecv(server, &buf, 1, &rcvd, &flags, &ovr, NULL) == SOCKET_ERROR &&
     WSAGetLastError() != WSA_IO_PENDING)
    fail_exit("WSARecv(overlapped)", (DWORD)WSAGetLastError());
  expect_packet(port, &ovr, KEY_SERVER, 10, TRUE, "recv packet");
  if(memcmp(rbuf, payload, 10) != 0) {
    printf("FAIL %s: received payload mismatch\n", TEST_NAME);
    return 1;
  }

  /* Close the client. A pending receive on the server completes with 0 bytes
   * and no error: this is how an IOCP engine sees a graceful close. */
  closesocket(client);
  client = INVALID_SOCKET;
  memset(&ovz, 0, sizeof ovz);
  buf.buf = rbuf;
  buf.len = sizeof(rbuf);
  flags = 0;
  rcvd = 99;
  if(WSARecv(server, &buf, 1, &rcvd, &flags, &ovz, NULL) == SOCKET_ERROR &&
     WSAGetLastError() != WSA_IO_PENDING)
    fail_exit("WSARecv after peer close", (DWORD)WSAGetLastError());
  expect_packet(port, &ovz, KEY_SERVER, 0, TRUE, "EOF packet");

  closesocket(server);
  CloseHandle(port);
  WSACleanup();
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
