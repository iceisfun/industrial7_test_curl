/*
 * Test: curl_loopback_bind_sequence
 *
 * Purpose: Reproduce the local-interface sequence curl runs for
 *   --interface/--local-port style binding, end to end on loopback:
 *   1. resolve the adapter that owns 127.0.0.1 with GetAdaptersAddresses,
 *   2. confirm the same index with GetIpAddrTable,
 *   3. create a listening socket bound to 127.0.0.1:0 and read the port back
 *      with getsockname,
 *   4. create a client socket bound to 127.0.0.1:0, connect it to the
 *      listener, accept, and check getpeername on the server side against the
 *      client's getsockname.
 *
 * APIs: GetAdaptersAddresses, GetIpAddrTable (iphlpapi); WSAStartup,
 *   WSACleanup, socket, bind, listen, connect, accept, getsockname,
 *   getpeername, closesocket, WSAGetLastError (ws2_32).
 *
 * Success means: loopback adapter index from GetAdaptersAddresses equals the
 *   index of 127.0.0.1 in GetIpAddrTable; the listener reports 127.0.0.1 and
 *   a nonzero port; connect succeeds; the accepted peer address is 127.0.0.1
 *   and its port equals the client's bound ephemeral port. Only loopback
 *   traffic is used. A missing API is a FAIL (Win10 22H2 has it).0.0.1 entry
 *   is reported. A WSAStartup failure is a FAIL.
 *
 * Source reference: lib/if2ip.c:94 (Curl_if2ip, the interface-to-address
 *   lookup behind --interface) and lib/cf-socket.c:898 where the local bind is
 *   applied before connect; this test models that sequence on loopback.
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
#define TEST_NAME "curl_loopback_bind_sequence"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ULONG loopback_index_gaa(BOOL *found_addr)
{
  ULONG size = 15000, rc;
  PIP_ADAPTER_ADDRESSES buf, a;
  ULONG idx = 0;
  int attempt;
  *found_addr = FALSE;
  for(attempt = 0; attempt < 3; attempt++) {
    buf = (PIP_ADAPTER_ADDRESSES)malloc(size);
    if(!buf)
      return 0;
    rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, buf, &size);
    if(rc == NO_ERROR)
      break;
    free(buf);
    buf = NULL;
    if(rc != ERROR_BUFFER_OVERFLOW)
      return 0;
  }
  if(!buf)
    return 0;
  for(a = buf; a; a = a->Next) {
    PIP_ADAPTER_UNICAST_ADDRESS ua;
    if(a->IfType != IF_TYPE_SOFTWARE_LOOPBACK)
      continue;
    for(ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
      if(ua->Address.lpSockaddr->sa_family == AF_INET &&
         ((struct sockaddr_in *)ua->Address.lpSockaddr)->sin_addr.S_un.S_addr ==
           htonl(0x7f000001UL)) {
        *found_addr = TRUE;
        idx = a->IfIndex;
      }
    }
  }
  free(buf);
  return idx;
}

static DWORD loopback_index_table(void)
{
  ULONG size = 0;
  PMIB_IPADDRTABLE t;
  DWORD i, idx = 0;
  if(GetIpAddrTable(NULL, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER)
    return 0;
  t = (PMIB_IPADDRTABLE)malloc(size);
  if(!t)
    return 0;
  if(GetIpAddrTable(t, &size, FALSE) == NO_ERROR) {
    for(i = 0; i < t->dwNumEntries; i++) {
      if(ntohl(t->table[i].dwAddr) == 0x7f000001UL) {
        idx = t->table[i].dwIndex;
        break;
      }
    }
  }
  free(t);
  return idx;
}

static int bind_loopback(SOCKET s)
{
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.S_un.S_addr = htonl(0x7f000001UL);
  sin.sin_port = 0;
  return bind(s, (struct sockaddr *)&sin, sizeof(sin));
}

int main(void)
{
  WSADATA wsa;
  BOOL gaa_addr = FALSE;
  ULONG gaa_idx, tbl_idx;
  SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, peer = INVALID_SOCKET;
  struct sockaddr_in lsin, csin, psin;
  int len;
  int rc;

  gaa_idx = loopback_index_gaa(&gaa_addr);
  if(gaa_idx == 0 || !gaa_addr) {
    printf("FAIL %s: no loopback adapter owning 127.0.0.1 in GetAdaptersAddresses\n",
           TEST_NAME);
    return 1;
  }
  tbl_idx = loopback_index_table();
  if(tbl_idx == 0) {
    printf("FAIL %s: 127.0.0.1 absent from GetIpAddrTable\n", TEST_NAME);
    return 1;
  }
  if(gaa_idx != tbl_idx) {
    printf("FAIL %s: GetAdaptersAddresses index %lu != GetIpAddrTable index %lu for 127.0.0.1\n",
           TEST_NAME, (unsigned long)gaa_idx, (unsigned long)tbl_idx);
    return 1;
  }

  rc = WSAStartup(MAKEWORD(2, 2), &wsa);
  if(rc != 0) {
    printf("FAIL %s: WSAStartup failed (%d)\n", TEST_NAME, rc);
    return 1;
  }

  listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(listener == INVALID_SOCKET) {
    printf("FAIL %s: listener socket WSAGetLastError=%d\n", TEST_NAME, WSAGetLastError());
    WSACleanup();
    return 1;
  }
  if(bind_loopback(listener) != 0) {
    printf("FAIL %s: bind 127.0.0.1:0 WSAGetLastError=%d\n", TEST_NAME, WSAGetLastError());
    goto fail_close;
  }
  if(listen(listener, 1) != 0) {
    printf("FAIL %s: listen WSAGetLastError=%d\n", TEST_NAME, WSAGetLastError());
    goto fail_close;
  }
  len = sizeof(lsin);
  if(getsockname(listener, (struct sockaddr *)&lsin, &len) != 0) {
    printf("FAIL %s: getsockname(listener) WSAGetLastError=%d\n", TEST_NAME, WSAGetLastError());
    goto fail_close;
  }
  if(lsin.sin_addr.S_un.S_addr != htonl(0x7f000001UL) || ntohs(lsin.sin_port) == 0) {
    printf("FAIL %s: listener bound to %s:%u (want 127.0.0.1 with nonzero port)\n",
           TEST_NAME, inet_ntoa(lsin.sin_addr), (unsigned)ntohs(lsin.sin_port));
    goto fail_close;
  }

  client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(client == INVALID_SOCKET) {
    printf("FAIL %s: client socket WSAGetLastError=%d\n", TEST_NAME, WSAGetLastError());
    goto fail_close;
  }
  if(bind_loopback(client) != 0) {
    printf("FAIL %s: client bind 127.0.0.1:0 WSAGetLastError=%d\n", TEST_NAME, WSAGetLastError());
    goto fail_close;
  }
  len = sizeof(csin);
  if(getsockname(client, (struct sockaddr *)&csin, &len) != 0 || ntohs(csin.sin_port) == 0) {
    printf("FAIL %s: getsockname(client) WSAGetLastError=%d\n", TEST_NAME, WSAGetLastError());
    goto fail_close;
  }

  memset(&psin, 0, sizeof(psin));
  psin.sin_family = AF_INET;
  psin.sin_addr.S_un.S_addr = htonl(0x7f000001UL);
  psin.sin_port = lsin.sin_port;
  if(connect(client, (struct sockaddr *)&psin, sizeof(psin)) != 0) {
    printf("FAIL %s: connect to listener WSAGetLastError=%d\n", TEST_NAME, WSAGetLastError());
    goto fail_close;
  }

  len = sizeof(psin);
  peer = accept(listener, (struct sockaddr *)&psin, &len);
  if(peer == INVALID_SOCKET) {
    printf("FAIL %s: accept WSAGetLastError=%d\n", TEST_NAME, WSAGetLastError());
    goto fail_close;
  }
  if(psin.sin_addr.S_un.S_addr != htonl(0x7f000001UL) ||
     psin.sin_port != csin.sin_port) {
    printf("FAIL %s: accepted peer %s:%u differs from client bind port %u\n",
           TEST_NAME, inet_ntoa(psin.sin_addr), (unsigned)ntohs(psin.sin_port),
           (unsigned)ntohs(csin.sin_port));
    goto fail_close;
  }

  {
    struct sockaddr_in pname;
    len = sizeof(pname);
    if(getpeername(peer, (struct sockaddr *)&pname, &len) != 0 ||
       pname.sin_port != csin.sin_port) {
      printf("FAIL %s: getpeername port mismatch WSAGetLastError=%d\n",
             TEST_NAME, WSAGetLastError());
      goto fail_close;
    }
  }

  closesocket(peer);
  closesocket(client);
  closesocket(listener);
  WSACleanup();
  printf("PASS %s\n", TEST_NAME);
  return 0;

fail_close:
  if(peer != INVALID_SOCKET)
    closesocket(peer);
  if(client != INVALID_SOCKET)
    closesocket(client);
  if(listener != INVALID_SOCKET)
    closesocket(listener);
  WSACleanup();
  return 1;
}
