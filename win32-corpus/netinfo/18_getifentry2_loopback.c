/*
 * Test: getifentry2_loopback
 * Area: netinfo
 * Purpose: Read the software loopback interface through the NETIOAPI
 *   interface (GetIfEntry2) that curl-adjacent resolvers use, and cross-check
 *   it against GetAdaptersAddresses and GetIfTable2.
 * APIs: GetIfEntry2, GetIfTable2, FreeMibTable, GetAdaptersAddresses.
 * Success means: the loopback adapter (IF_TYPE_SOFTWARE_LOOPBACK) opens with
 *   GetIfEntry2; Type == 24, OperStatus == IfOperStatusUp, MediaConnectState
 *   == MediaConnectStateConnected, PhysicalAddressLength == 0; GetIfTable2
 *   lists the same InterfaceIndex; a bogus InterfaceIndex fails with
 *   ERROR_FILE_NOT_FOUND (2); a zeroed row (no index, no LUID) fails with
 *   ERROR_INVALID_PARAMETER (87).
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

#define TEST_NAME "getifentry2_loopback"

int main(void)
{
  ULONG size = 32768, rc;
  IP_ADAPTER_ADDRESSES *all, *a;
  DWORD lidx = 0;
  MIB_IF_ROW2 row;
  MIB_IF_TABLE2 *tbl = NULL;
  ULONG i;
  int found = 0;

  all = (IP_ADAPTER_ADDRESSES *)malloc(size);
  rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, all, &size);
  if(rc == ERROR_BUFFER_OVERFLOW) { free(all); all = malloc(size); rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, all, &size); }
  EXPECT(rc == NO_ERROR, "GetAdaptersAddresses rc=%lu", rc);
  for(a = all; a; a = a->Next)
    if(a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) { lidx = a->IfIndex; break; }
  EXPECT(lidx != 0, "no loopback adapter");
  free(all);

  memset(&row, 0, sizeof(row));
  row.InterfaceIndex = lidx;
  rc = GetIfEntry2(&row);
  EXPECT(rc == NO_ERROR, "GetIfEntry2(%lu) rc=%lu", lidx, rc);
  INFO("type=%lu oper=%d media=%d physlen=%lu mtu=%lu alias=%ls", (unsigned long)row.Type, (int)row.OperStatus,
       (int)row.MediaConnectState, (unsigned long)row.PhysicalAddressLength, (unsigned long)row.Mtu, row.Alias);
  EXPECT(row.Type == IF_TYPE_SOFTWARE_LOOPBACK, "Type %lu", (unsigned long)row.Type);
  EXPECT(row.OperStatus == IfOperStatusUp, "OperStatus %d", (int)row.OperStatus);
  EXPECT(row.MediaConnectState == MediaConnectStateConnected, "MediaConnectState %d", (int)row.MediaConnectState);
  EXPECT(row.PhysicalAddressLength == 0, "PhysicalAddressLength %lu", (unsigned long)row.PhysicalAddressLength);

  rc = GetIfTable2(&tbl);
  EXPECT(rc == NO_ERROR && tbl, "GetIfTable2 rc=%lu", rc);
  for(i = 0; i < tbl->NumEntries; i++)
    if(tbl->Table[i].InterfaceIndex == lidx) found = 1;
  EXPECT(found, "loopback index %lu not in GetIfTable2 (%lu rows)", lidx, (unsigned long)tbl->NumEntries);
  FreeMibTable(tbl);

  memset(&row, 0, sizeof(row));
  row.InterfaceIndex = 0x7ffffff0;
  rc = GetIfEntry2(&row);
  EXPECT(rc == ERROR_FILE_NOT_FOUND, "GetIfEntry2(bogus) rc=%lu want 2", rc);
  memset(&row, 0, sizeof(row));
  rc = GetIfEntry2(&row);
  EXPECT(rc == ERROR_INVALID_PARAMETER, "GetIfEntry2(zero) rc=%lu want 87", rc);
  rc = GetIfEntry2(NULL);
  EXPECT(rc == ERROR_INVALID_PARAMETER, "GetIfEntry2(NULL) rc=%lu want 87", rc);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
