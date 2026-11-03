/*
 * 11_curl_multi_winsock_wakeup
 *
 * Purpose: reproduce the curl multi winsock wait sequence (multi_winsock_select
 *   in lib/multi.c) on a loopback TCP socket plus one WSA event used as the
 *   multi wakeup handle, in the same order curl uses it:
 *     a) another thread wakes the waiter with WSASetEvent (lib/multi.c:1697)
 *        and the waiter uses WSAWaitForMultipleEvents with a timeout
 *        (lib/multi.c:1409) and then WSAResetEvent (lib/multi.c:1460);
 *     b) WSAEventSelect(fd, wake, FD_READ|FD_ACCEPT|FD_CLOSE) for POLLIN and
 *        FD_WRITE|FD_CONNECT|FD_CLOSE for POLLOUT (lib/multi.c:1380-1392);
 *     c) a pre-check with WSAPoll (Curl_poll, lib/multi.c:1399) that reports
 *        readiness without waiting;
 *     d) WSAEnumNetworkEvents(fd, NULL, &ev) to read and clear the network
 *        events, then WSAEventSelect(fd, wake, 0) to unbind (lib/multi.c:1423,
 *        1433, 1454, 1458);
 *     e) a socket that becomes readable while the waiter sleeps wakes it.
 * APIs: WSAStartup, WSASocketW, bind/listen/connect/accept, WSACreateEvent,
 *   WSASetEvent, WSAWaitForMultipleEvents, WSAResetEvent, WSAEventSelect,
 *   WSAEnumNetworkEvents, WSAPoll, send, recv, CreateThread.
 * Success:
 *   - the wake event is signaled from a thread and the wait returns
 *     WSA_WAIT_EVENT_0; a wait with no signal returns WSA_WAIT_TIMEOUT;
 *   - WSAPoll reports POLLOUT on the connected socket (pre-check hits);
 *   - WSAEnumNetworkEvents reports FD_WRITE and no FD_READ;
 *   - after WSAEventSelect(...,FD_READ|FD_CLOSE), a server send from another
 *     thread wakes the waiter; WSAEnumNetworkEvents reports FD_READ and the
 *     three bytes "xyz" are received.
 * Source: lib/multi.c:1354-1466 (reset_socket_fdwrite, multi_winsock_select),
 *   lib/multi.c:1697 (WSASetEvent wakeup), lib/multi.c:311 (WSACreateEvent).
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

#define TEST_NAME "11_curl_multi_winsock_wakeup"

static SOCKET g_server = INVALID_SOCKET;
static WSAEVENT g_wake = WSA_INVALID_EVENT;

static void fail_exit(const char *why, DWORD err)
{
  printf("FAIL %s: %s (err=%lu)\n", TEST_NAME, why, (unsigned long)err);
  exit(1);
}

/* Stage a: wake the waiter after a short delay, like another curl thread
 * calling curl_multi_wakeup(). */
static DWORD WINAPI waker_thread(LPVOID arg)
{
  (void)arg;
  Sleep(100);
  WSASetEvent(g_wake);
  return 0;
}

/* Stage e: send data from the server side after a short delay. */
static DWORD WINAPI sender_thread(LPVOID arg)
{
  (void)arg;
  Sleep(100);
  send(g_server, "xyz", 3, 0);
  return 0;
}

int main(void)
{
  WSADATA wsa;
  struct sockaddr_in sa;
  int salen = sizeof(sa);
  SOCKET listener, client;
  WSAPOLLFD pfd;
  WSANETWORKEVENTS ne;
  HANDLE th;
  DWORD r;
  char buf[8];
  int got, tries;
  int pollrc;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    fail_exit("WSAStartup", (DWORD)WSAGetLastError());

  listener = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                        WSA_FLAG_OVERLAPPED);
  client = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                      WSA_FLAG_OVERLAPPED);
  if(listener == INVALID_SOCKET || client == INVALID_SOCKET)
    fail_exit("WSASocketW", (DWORD)WSAGetLastError());

  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(bind(listener, (struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR ||
     getsockname(listener, (struct sockaddr *)&sa, &salen) == SOCKET_ERROR ||
     listen(listener, 1) == SOCKET_ERROR)
    fail_exit("listener setup", (DWORD)WSAGetLastError());
  if(connect(client, (struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR)
    fail_exit("connect", (DWORD)WSAGetLastError());
  g_server = accept(listener, NULL, NULL);
  if(g_server == INVALID_SOCKET)
    fail_exit("accept", (DWORD)WSAGetLastError());
  closesocket(listener);

  /* Wakeup handle: curl creates one per multi handle (lib/multi.c:311). */
  g_wake = WSACreateEvent();
  if(g_wake == WSA_INVALID_EVENT)
    fail_exit("WSACreateEvent", (DWORD)WSAGetLastError());

  /* a) Cross-thread wakeup with no socket involved. */
  th = CreateThread(NULL, 0, waker_thread, NULL, 0, NULL);
  if(!th)
    fail_exit("CreateThread(waker)", GetLastError());
  r = WSAWaitForMultipleEvents(1, &g_wake, FALSE, 5000, FALSE);
  if(r != WSA_WAIT_EVENT_0)
    fail_exit("wakeup wait did not return WSA_WAIT_EVENT_0", r);
  WaitForSingleObject(th, 5000);
  if(WaitForSingleObject(th, 5000) != WAIT_OBJECT_0)
    fail_exit("waker thread did not exit", GetLastError());
  CloseHandle(th);
  if(!WSAResetEvent(g_wake))
    fail_exit("WSAResetEvent", (DWORD)WSAGetLastError());
  r = WSAWaitForMultipleEvents(1, &g_wake, FALSE, 50, FALSE);
  if(r != WSA_WAIT_TIMEOUT)
    fail_exit("reset wakeup should time out", r);

  /* b) Register POLLIN and POLLOUT interest in one mask, as curl builds it
   * from the pollfd events (the masks are ORed before WSAEventSelect). */
  if(WSAEventSelect(client, g_wake,
                    FD_READ | FD_ACCEPT | FD_CLOSE |
                    FD_WRITE | FD_CONNECT) == SOCKET_ERROR)
    fail_exit("WSAEventSelect(POLLIN|POLLOUT mask)", (DWORD)WSAGetLastError());

  /* c) Pre-check with WSAPoll (curl's Curl_poll with timeout 0). */
  memset(&pfd, 0, sizeof pfd);
  pfd.fd = client;
  pfd.events = POLLOUT | POLLIN;
  pollrc = WSAPoll(&pfd, 1, 0);
  if(pollrc != 1)
    fail_exit("WSAPoll pre-check should report 1 ready socket",
              (DWORD)pollrc);
  if(!(pfd.revents & POLLOUT))
    fail_exit("WSAPoll: POLLOUT not set on connected socket", (DWORD)pfd.revents);
  if(pfd.revents & POLLIN)
    fail_exit("WSAPoll: POLLIN set before any data was sent",
              (DWORD)pfd.revents);

  /* d) Read and clear network events, then unbind, then reset the wake event. */
  memset(&ne, 0, sizeof ne);
  if(WSAEnumNetworkEvents(client, NULL, &ne) == SOCKET_ERROR)
    fail_exit("WSAEnumNetworkEvents(client)", (DWORD)WSAGetLastError());
  if(!(ne.lNetworkEvents & FD_WRITE))
    fail_exit("WSAEnumNetworkEvents: FD_WRITE missing", 0);
  if(ne.lNetworkEvents & FD_READ)
    fail_exit("WSAEnumNetworkEvents: FD_READ before data", 0);
  if(WSAEventSelect(client, g_wake, 0) == SOCKET_ERROR)
    fail_exit("WSAEventSelect(client, 0)", (DWORD)WSAGetLastError());
  if(!WSAResetEvent(g_wake))
    fail_exit("WSAResetEvent after POLLOUT round", (DWORD)WSAGetLastError());

  /* e) Read-interest only; a send from the peer must wake the waiter. */
  if(WSAEventSelect(client, g_wake, FD_READ | FD_CLOSE) == SOCKET_ERROR)
    fail_exit("WSAEventSelect(POLLIN only)", (DWORD)WSAGetLastError());
  th = CreateThread(NULL, 0, sender_thread, NULL, 0, NULL);
  if(!th)
    fail_exit("CreateThread(sender)", GetLastError());
  r = WSAWaitForMultipleEvents(1, &g_wake, FALSE, 5000, FALSE);
  if(r != WSA_WAIT_EVENT_0)
    fail_exit("data arrival did not wake the waiter", r);
  if(WaitForSingleObject(th, 5000) != WAIT_OBJECT_0)
    fail_exit("sender thread did not exit", GetLastError());
  CloseHandle(th);

  memset(&ne, 0, sizeof ne);
  if(WSAEnumNetworkEvents(client, NULL, &ne) == SOCKET_ERROR)
    fail_exit("WSAEnumNetworkEvents(read)", (DWORD)WSAGetLastError());
  if(!(ne.lNetworkEvents & FD_READ))
    fail_exit("WSAEnumNetworkEvents: FD_READ missing after send", 0);
  if(WSAEventSelect(client, g_wake, 0) == SOCKET_ERROR)
    fail_exit("WSAEventSelect(client, 0) after read", (DWORD)WSAGetLastError());
  if(!WSAResetEvent(g_wake))
    fail_exit("WSAResetEvent after read round", (DWORD)WSAGetLastError());

  got = 0;
  memset(buf, 0, sizeof buf);
  for(tries = 0; got < 3 && tries < 200; tries++) {
    int n = recv(client, buf + got, 3 - got, 0);
    if(n > 0)
      got += n;
    else if(n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)
      Sleep(10);
    else
      fail_exit("recv", (DWORD)WSAGetLastError());
  }
  if(got != 3 || memcmp(buf, "xyz", 3) != 0) {
    printf("FAIL %s: received %d bytes, expected \"xyz\"\n", TEST_NAME, got);
    return 1;
  }

  if(!WSACloseEvent(g_wake))
    fail_exit("WSACloseEvent", (DWORD)WSAGetLastError());
  closesocket(client);
  closesocket(g_server);
  WSACleanup();
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
