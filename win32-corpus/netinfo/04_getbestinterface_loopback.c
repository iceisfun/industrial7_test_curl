/*
 * Test: getbestinterface_loopback
 *
 * Purpose: Ask the IP stack which interface routes traffic to 127.0.0.1 with
 *   GetBestInterface and GetBestRoute, and cross-check the answer against the
 *   interface index that GetIpAddrTable reports for the 127.0.0.1 address.
 *   This is the route lookup that a "bind to local address" or
 *   "send to loopback" path needs in order to choose the right adapter.
 *
 * APIs: GetBestInterface, GetBestRoute, GetIpAddrTable (iphlpapi),
 *   MIB_IPFORWARDROW.
 *
 * Success means: GetBestInterface(127.0.0.1) returns NO_ERROR with a nonzero
 *   index; GetBestRoute(127.0.0.1) returns NO_ERROR and its dwForwardIfIndex
 *   equals the GetBestInterface index; both equal the dwIndex of the
 *   127.0.0.1 row in the IPv4 address table. A failure to resolve 127.0.0.1
 *   (ERROR_NETWORK_UNREACHABLE) is a FAIL. A missing API is a FAIL (Win10 22H2 has it).
 *
 * Source reference: no direct curl call site. Relates to the interface
 *   selection performed by curl's --interface handling in lib/if2ip.c:94 (Curl_if2ip).
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
#define TEST_NAME "getbestinterface_loopback"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static DWORD table_index_of_loopback(void)
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

/* True when the IPv4 forwarding table lists a non-default route covering
 * 127.0.0.1. Real Windows always lists the 127.0.0.0/8 route on the loopback
 * adapter. The 0.0.0.0/0 default route is excluded: its zero mask matches
 * every address and says nothing about loopback. */
static int loopback_route_listed(void)
{
  ULONG size = 0;
  PMIB_IPFORWARDTABLE t;
  DWORD i;
  int found = 0;
  if(GetIpForwardTable(NULL, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER)
    return 0;
  t = (PMIB_IPFORWARDTABLE)malloc(size);
  if(!t)
    return 0;
  if(GetIpForwardTable(t, &size, FALSE) == NO_ERROR) {
    for(i = 0; i < t->dwNumEntries && !found; i++) {
      DWORD dest = ntohl(t->table[i].dwForwardDest);
      DWORD mask = ntohl(t->table[i].dwForwardMask);
      if(mask != 0 && (0x7f000001UL & mask) == (dest & mask))
        found = 1;
    }
  }
  free(t);
  return found;
}

int main(void)
{
  DWORD dest = htonl(0x7f000001UL);
  DWORD best_if = 0, table_if;
  MIB_IPFORWARDROW row;
  DWORD rc;

  rc = GetBestInterface(dest, &best_if);
  if(rc == ERROR_NOT_SUPPORTED || rc == ERROR_CALL_NOT_IMPLEMENTED) {
    printf("FAIL %s: GetBestInterface not implemented (rc=%lu)\n",
           TEST_NAME, (unsigned long)rc);
    return 1;
  }
  if(rc != NO_ERROR) {
    printf("FAIL %s: GetBestInterface(127.0.0.1) rc=%lu GetLastError=%lu\n",
           TEST_NAME, (unsigned long)rc, (unsigned long)GetLastError());
    return 1;
  }
  if(best_if == 0) {
    printf("FAIL %s: GetBestInterface returned interface index 0\n", TEST_NAME);
    return 1;
  }

  table_if = table_index_of_loopback();
  if(table_if == 0) {
    printf("FAIL %s: 127.0.0.1 absent from IPv4 address table; cannot cross-check\n",
           TEST_NAME);
    return 1;
  }
  /* Win10 22H2 lists a route covering 127.0.0.1 that is not the default route. */
  if(!loopback_route_listed()) {
    printf("FAIL %s: IPv4 forward table has no non-default route covering 127.0.0.1\n", TEST_NAME);
    return 1;
  }
  if(best_if != table_if) {
    printf("FAIL %s: GetBestInterface=%lu but 127.0.0.1 is on interface %lu (Windows routes 127.0.0.0/8 via the loopback adapter)\n",
           TEST_NAME, (unsigned long)best_if, (unsigned long)table_if);
    return 1;
  }

  memset(&row, 0, sizeof(row));
  rc = GetBestRoute(dest, 0, &row);
  if(rc != NO_ERROR) {
    printf("FAIL %s: GetBestRoute(127.0.0.1) rc=%lu GetLastError=%lu\n",
           TEST_NAME, (unsigned long)rc, (unsigned long)GetLastError());
    return 1;
  }
  if(row.dwForwardIfIndex != best_if) {
    printf("FAIL %s: GetBestRoute ifindex=%lu disagrees with GetBestInterface=%lu\n",
           TEST_NAME, (unsigned long)row.dwForwardIfIndex, (unsigned long)best_if);
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
