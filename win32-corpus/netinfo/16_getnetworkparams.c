/*
 * Test: getnetworkparams
 * Area: netinfo
 * Purpose: GetNetworkParams (FIXED_INFO) is the Windows resolver
 *   configuration source used by c-ares builds of curl (DNS server list, host
 *   and domain names). Verify the two-call sizing protocol and contents.
 * APIs: GetNetworkParams (iphlpapi), GetComputerNameExW.
 * Success means: with a NULL buffer the call returns ERROR_BUFFER_OVERFLOW
 *   (111) and a size >= sizeof(FIXED_INFO); with that buffer it returns
 *   NO_ERROR, HostName equals the DNS host name (case-insensitive),
 *   DomainName is shorter than 128, DnsServerList.IpAddress.String is a
 *   parseable address or empty, and EnableRouting/EnableProxy/EnableDns are 0/1.
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

#define TEST_NAME "getnetworkparams"

int main(void)
{
  ULONG len = 0, rc;
  FIXED_INFO *fi;
  IP_ADDR_STRING *a;
  wchar_t wname[256];
  DWORD wlen = 256;
  char conv[256];
  int cnt = 0;

  rc = GetNetworkParams(NULL, &len);
  EXPECT(rc == ERROR_BUFFER_OVERFLOW, "sizing call rc=%lu (want 111)", rc);
  EXPECT(len >= sizeof(FIXED_INFO), "required size %lu < sizeof(FIXED_INFO)=%u", len, (unsigned)sizeof(FIXED_INFO));
  fi = (FIXED_INFO *)malloc(len);
  EXPECT(fi != NULL, "malloc");
  rc = GetNetworkParams(fi, &len);
  EXPECT(rc == NO_ERROR, "GetNetworkParams rc=%lu", rc);
  INFO("host='%s' domain='%s' scope='%s' nodetype=%u routing=%u proxy=%u dns=%u", fi->HostName, fi->DomainName, fi->ScopeId,
       fi->NodeType, fi->EnableRouting, fi->EnableProxy, fi->EnableDns);
  EXPECT(GetComputerNameExW(ComputerNameDnsHostname, wname, &wlen), "GetComputerNameExW");
  WideCharToMultiByte(CP_UTF8, 0, wname, -1, conv, sizeof(conv), NULL, NULL);
  EXPECT(_stricmp(conv, fi->HostName) == 0, "HostName '%s' != '%s'", fi->HostName, conv);
  EXPECT(strlen(fi->DomainName) < 128, "DomainName length");
  EXPECT(fi->EnableRouting <= 1 && fi->EnableProxy <= 1 && fi->EnableDns <= 1, "flags not 0/1");
  for(a = &fi->DnsServerList; a; a = a->Next) {
    struct in_addr ia;
    cnt++;
    INFO("dns[%d]='%s'", cnt, a->IpAddress.String);
    if(a->IpAddress.String[0])
      EXPECT(inet_pton(AF_INET, a->IpAddress.String, &ia) == 1, "unparseable DNS server '%s'", a->IpAddress.String);
    EXPECT(cnt < 64, "DNS list loop");
  }
  free(fi);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
