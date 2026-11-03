/*
 * Test: 01_wsastartup_init
 * Purpose: Mirror curl's optional Winsock initialisation in curl_global_init()
 *   (the CURL_GLOBAL_WINSOCK flag path).
 * APIs: WSAStartup, WSACleanup, WSAGetLastError
 * Source: lib/easy.c:166-172. curl calls WSAStartup(MAKEWORD(2, 2), &wsa),
 *   treats any non-zero return as failure and remembers that it owns the
 *   Winsock reference so that curl_global_cleanup() balances it with
 *   WSACleanup().
 * Success: the first WSAStartup returns 0 and negotiates wVersion 2.2, a
 *   nested WSAStartup also returns 0 (Winsock keeps a per-process count),
 *   the two matching WSACleanup calls return 0, and one extra WSACleanup
 *   fails with SOCKET_ERROR and WSANOTINITIALISED (10093).
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
#include <stdio.h>

#define TEST_NAME "01_wsastartup_init"

int main(void)
{
  WSADATA first;
  WSADATA nested;
  int rc;

  rc = WSAStartup(MAKEWORD(2, 2), &first);
  if(rc != 0) {
    printf("FAIL %s: WSAStartup returned %d\n", TEST_NAME, rc);
    return 1;
  }
  if(LOBYTE(first.wVersion) != 2 || HIBYTE(first.wVersion) != 2) {
    printf("FAIL %s: negotiated wVersion=0x%04x, expected 0x0202\n",
           TEST_NAME, (unsigned)first.wVersion);
    WSACleanup();
    return 1;
  }

  rc = WSAStartup(MAKEWORD(2, 2), &nested);
  if(rc != 0) {
    printf("FAIL %s: nested WSAStartup returned %d\n", TEST_NAME, rc);
    WSACleanup();
    return 1;
  }

  if(WSACleanup() != 0) {
    printf("FAIL %s: first WSACleanup failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    return 1;
  }
  if(WSACleanup() != 0) {
    printf("FAIL %s: second WSACleanup failed, WSAGetLastError=%d\n",
           TEST_NAME, WSAGetLastError());
    return 1;
  }

  if(WSACleanup() != SOCKET_ERROR || WSAGetLastError() != WSANOTINITIALISED) {
    printf("FAIL %s: extra WSACleanup did not fail with WSANOTINITIALISED "
           "(WSAGetLastError=%d)\n", TEST_NAME, WSAGetLastError());
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
