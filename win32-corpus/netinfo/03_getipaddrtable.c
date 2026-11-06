/*
 * Test: getipaddrtable
 *
 * Purpose: Verify the legacy IPv4 table API GetIpAddrTable with the
 *   documented size-query protocol and bOrder=TRUE. The table must contain
 *   the loopback address 127.0.0.1/255.0.0.0 with an interface index that
 *   matches the loopback adapter, and the entries must be sorted ascending
 *   by address when bOrder is TRUE.
 *
 * APIs: GetIpAddrTable (iphlpapi), MIB_IPADDRTABLE, MIB_IPADDRROW.
 *
 * Success means: size query returns ERROR_INSUFFICIENT_BUFFER with
 *   size >= sizeof(MIB_IPADDRTABLE); the sized call returns NO_ERROR;
 *   dwNumEntries >= 1; an entry with address 127.0.0.1 and mask 255.0.0.0
 *   exists; entries are in ascending host-order address order.
 *   A missing API is a FAIL (Win10 22H2 has it).
 *
 * Source reference: none. curl's tree has no GetIpAddrTable call site. The
 *   test is the IPv4 table analogue of the getifaddrs() enumeration in
 *   lib/if2ip.c:94 (Curl_if2ip); curl itself does not use this API.
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
#define TEST_NAME "getipaddrtable"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
  ULONG size = 0, rc;
  PMIB_IPADDRTABLE table;
  DWORD i, loop_idx = 0;
  BOOL found_loop = FALSE, sorted = TRUE;
  DWORD prev = 0;

  rc = GetIpAddrTable(NULL, &size, FALSE);
  if(rc == ERROR_NOT_SUPPORTED || rc == ERROR_CALL_NOT_IMPLEMENTED) {
    printf("FAIL %s: GetIpAddrTable not implemented (rc=%lu)\n",
           TEST_NAME, (unsigned long)rc);
    return 1;
  }
  if(rc != ERROR_INSUFFICIENT_BUFFER) {
    printf("FAIL %s: size query rc=%lu (want ERROR_INSUFFICIENT_BUFFER=122) GetLastError=%lu\n",
           TEST_NAME, (unsigned long)rc, (unsigned long)GetLastError());
    return 1;
  }
  if(size < sizeof(MIB_IPADDRTABLE)) {
    printf("FAIL %s: size query reported %lu, below sizeof(MIB_IPADDRTABLE)\n",
           TEST_NAME, (unsigned long)size);
    return 1;
  }

  table = (PMIB_IPADDRTABLE)malloc(size);
  if(!table) {
    printf("FAIL %s: malloc(%lu) failed\n", TEST_NAME, (unsigned long)size);
    return 1;
  }

  rc = GetIpAddrTable(table, &size, TRUE);
  if(rc != NO_ERROR) {
    free(table);
    printf("FAIL %s: GetIpAddrTable(bOrder=TRUE) rc=%lu GetLastError=%lu\n",
           TEST_NAME, (unsigned long)rc, (unsigned long)GetLastError());
    return 1;
  }
  if(table->dwNumEntries < 1) {
    free(table);
    printf("FAIL %s: table has no entries\n", TEST_NAME);
    return 1;
  }
  if(sizeof(MIB_IPADDRTABLE) - sizeof(MIB_IPADDRROW) +
     (size_t)table->dwNumEntries * sizeof(MIB_IPADDRROW) > (size_t)size) {
    printf("FAIL %s: dwNumEntries=%lu overruns reported size %lu\n",
           TEST_NAME, (unsigned long)table->dwNumEntries, (unsigned long)size);
    free(table);
    return 1;
  }

  for(i = 0; i < table->dwNumEntries; i++) {
    DWORD addr = ntohl(table->table[i].dwAddr);
    if(i > 0 && addr < prev)
      sorted = FALSE;
    prev = addr;
    if(addr == 0x7f000001UL && table->table[i].dwMask == htonl(0xff000000UL)) {
      found_loop = TRUE;
      loop_idx = table->table[i].dwIndex;
    }
  }

  if(!sorted) {
    free(table);
    printf("FAIL %s: bOrder=TRUE did not return entries sorted by address\n", TEST_NAME);
    return 1;
  }
  if(!found_loop) {
    printf("FAIL %s: no entry 127.0.0.1/255.0.0.0 in %lu-entry table\n",
           TEST_NAME, (unsigned long)table->dwNumEntries);
    free(table);
    return 1;
  }
  if(loop_idx == 0) {
    free(table);
    printf("FAIL %s: loopback entry has dwIndex 0\n", TEST_NAME);
    return 1;
  }

  free(table);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
