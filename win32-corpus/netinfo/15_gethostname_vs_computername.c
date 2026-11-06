/*
 * Test: gethostname_vs_computername
 * Area: netinfo
 * Purpose: curl's Curl_gethostname() (lib/hostip.c) calls ws2_32!gethostname
 *   for the NTLM/FTP/SMTP local name. Verify the Winsock call against the
 *   kernel32 DNS host name, its failure modes, and the length limits.
 * APIs: gethostname, WSAStartup, WSACleanup, GetComputerNameExW.
 * Success means: before WSAStartup gethostname fails with WSANOTINITIALISED
 *   (10093); after it, the name equals ComputerNameDnsHostname
 *   (case-insensitive); a buffer one byte too small for name+NUL fails with
 *   WSAEFAULT (10014); a buffer of exactly len+1 succeeds; a NULL buffer fails
 *   with WSAEFAULT.
 * Exit: 0 PASS, 1 FAIL.
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
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define EXPECT(cond, ...) do { if(!(cond)) { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } } while(0)
#define INFO(...) do { printf("INFO "); printf(__VA_ARGS__); printf("\n"); } while(0)

#define TEST_NAME "gethostname_vs_computername"

int main(void)
{
  char name[256], small[256];
  wchar_t wname[256];
  DWORD wlen = 256;
  WSADATA d;
  int rc, err;
  size_t n;

  rc = gethostname(name, sizeof(name));
  err = WSAGetLastError();
  EXPECT(rc == SOCKET_ERROR && err == WSANOTINITIALISED, "gethostname before WSAStartup rc=%d err=%d (want -1, 10093)", rc, err);

  EXPECT(WSAStartup(MAKEWORD(2, 2), &d) == 0, "WSAStartup");
  rc = gethostname(name, sizeof(name));
  EXPECT(rc == 0, "gethostname rc=%d err=%d", rc, WSAGetLastError());
  n = strlen(name);
  EXPECT(n > 0 && n <= 63, "host name length %u", (unsigned)n);
  INFO("hostname='%s'", name);

  EXPECT(GetComputerNameExW(ComputerNameDnsHostname, wname, &wlen), "GetComputerNameExW %lu", GetLastError());
  {
    char conv[256];
    int k = WideCharToMultiByte(CP_UTF8, 0, wname, -1, conv, sizeof(conv), NULL, NULL);
    EXPECT(k > 0, "convert");
    EXPECT(_stricmp(conv, name) == 0, "gethostname '%s' != DNS host name '%s'", name, conv);
  }

  /* exact-fit: n+1 bytes succeeds, n bytes fails WSAEFAULT */
  rc = gethostname(small, (int)(n + 1));
  EXPECT(rc == 0 && strcmp(small, name) == 0, "exact fit rc=%d err=%d", rc, WSAGetLastError());
  rc = gethostname(small, (int)n);
  err = WSAGetLastError();
  EXPECT(rc == SOCKET_ERROR && err == WSAEFAULT, "short buffer rc=%d err=%d (want -1, 10014)", rc, err);
  rc = gethostname(NULL, 10);
  err = WSAGetLastError();
  EXPECT(rc == SOCKET_ERROR && err == WSAEFAULT, "NULL buffer rc=%d err=%d (want -1, 10014)", rc, err);
  WSACleanup();
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
