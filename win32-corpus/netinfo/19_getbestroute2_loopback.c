/*
 * Test: getbestroute2_loopback
 * Area: netinfo
 * Purpose: Route selection for the loopback destination through the NETIOAPI
 *   route functions, plus the WSAIoctl(SIO_ROUTING_INTERFACE_QUERY) form that
 *   Winsock exposes. curl's Curl_connect path relies on the stack choosing the
 *   loopback adapter for 127.0.0.1 and ::1.
 * APIs: GetBestRoute2, GetIpForwardTable2, FreeMibTable, WSAIoctl
 *   (SIO_ROUTING_INTERFACE_QUERY), GetBestInterfaceEx, GetAdaptersAddresses.
 * Success means: GetBestRoute2(127.0.0.1) is NO_ERROR with the loopback
 *   InterfaceIndex and best source address 127.0.0.1; for ::1 the same with
 *   source ::1; GetBestInterfaceEx(127.0.0.1) == loopback index;
 *   SIO_ROUTING_INTERFACE_QUERY(127.0.0.1) returns a sockaddr_in 127.0.0.1;
 *   GetIpForwardTable2(AF_INET) holds a 127.0.0.0/8 prefix on the loopback
 *   interface.
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

#define TEST_NAME "getbestroute2_loopback"

int main(void)
{
  ULONG size = 32768, rc, i;
  IP_ADAPTER_ADDRESSES *all, *a;
  DWORD lidx = 0, bi = 0;
  MIB_IPFORWARD_ROW2 route;
  SOCKADDR_INET src, dst;
  MIB_IPFORWARD_TABLE2 *tbl = NULL;
  int found = 0;
  WSADATA d;
  SOCKET s;
  struct sockaddr_in q, out;
  DWORD bytes = 0;

  all = (IP_ADAPTER_ADDRESSES *)malloc(size);
  rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, all, &size);
  if(rc == ERROR_BUFFER_OVERFLOW) { free(all); all = malloc(size); rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, all, &size); }
  EXPECT(rc == NO_ERROR, "GetAdaptersAddresses rc=%lu", rc);
  for(a = all; a; a = a->Next)
    if(a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) { lidx = a->IfIndex; break; }
  EXPECT(lidx != 0, "no loopback adapter");
  free(all);

  memset(&dst, 0, sizeof(dst));
  dst.si_family = AF_INET;
  dst.Ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  memset(&route, 0, sizeof(route)); memset(&src, 0, sizeof(src));
  rc = GetBestRoute2(NULL, 0, NULL, &dst, 0, &route, &src);
  EXPECT(rc == NO_ERROR, "GetBestRoute2(127.0.0.1) rc=%lu", rc);
  INFO("v4 route if=%lu prefixlen=%u src=%08lx", (unsigned long)route.InterfaceIndex, route.DestinationPrefix.PrefixLength, (unsigned long)ntohl(src.Ipv4.sin_addr.s_addr));
  EXPECT(route.InterfaceIndex == lidx, "v4 best route if %lu want %lu", (unsigned long)route.InterfaceIndex, lidx);
  EXPECT(src.si_family == AF_INET && src.Ipv4.sin_addr.s_addr == htonl(INADDR_LOOPBACK), "v4 best source not 127.0.0.1");

  memset(&dst, 0, sizeof(dst));
  dst.si_family = AF_INET6;
  dst.Ipv6.sin6_addr.s6_addr[15] = 1;
  memset(&route, 0, sizeof(route)); memset(&src, 0, sizeof(src));
  rc = GetBestRoute2(NULL, 0, NULL, &dst, 0, &route, &src);
  EXPECT(rc == NO_ERROR, "GetBestRoute2(::1) rc=%lu", rc);
  INFO("v6 route if=%lu prefixlen=%u", (unsigned long)route.InterfaceIndex, route.DestinationPrefix.PrefixLength);
  EXPECT(src.si_family == AF_INET6 && memcmp(&src.Ipv6.sin6_addr, &in6addr_loopback, 16) == 0, "v6 best source not ::1");

  memset(&q, 0, sizeof(q)); q.sin_family = AF_INET; q.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  rc = GetBestInterfaceEx((struct sockaddr *)&q, &bi);
  EXPECT(rc == NO_ERROR && bi == lidx, "GetBestInterfaceEx rc=%lu if=%lu want %lu", rc, bi, lidx);

  EXPECT(WSAStartup(MAKEWORD(2, 2), &d) == 0, "WSAStartup");
  s = socket(AF_INET, SOCK_DGRAM, 0);
  EXPECT(s != INVALID_SOCKET, "socket");
  memset(&out, 0, sizeof(out));
  EXPECT(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &q, sizeof(q), &out, sizeof(out), &bytes, NULL, NULL) == 0,
         "SIO_ROUTING_INTERFACE_QUERY err=%d", WSAGetLastError());
  INFO("routing query bytes=%lu fam=%d addr=%08lx", (unsigned long)bytes, out.sin_family, (unsigned long)ntohl(out.sin_addr.s_addr));
  EXPECT(out.sin_family == AF_INET && out.sin_addr.s_addr == htonl(INADDR_LOOPBACK), "routing query result not 127.0.0.1");
  closesocket(s);
  WSACleanup();

  rc = GetIpForwardTable2(AF_INET, &tbl);
  EXPECT(rc == NO_ERROR && tbl, "GetIpForwardTable2 rc=%lu", rc);
  for(i = 0; i < tbl->NumEntries; i++) {
    MIB_IPFORWARD_ROW2 *r = &tbl->Table[i];
    if(r->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr == htonl(0x7f000000UL) && r->DestinationPrefix.PrefixLength == 8 &&
       r->InterfaceIndex == lidx)
      found = 1;
  }
  EXPECT(found, "no 127.0.0.0/8 route on loopback interface in %lu rows", (unsigned long)tbl->NumEntries);
  FreeMibTable(tbl);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
