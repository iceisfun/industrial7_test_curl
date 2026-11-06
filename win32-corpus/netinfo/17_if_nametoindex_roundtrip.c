/*
 * Test: if_nametoindex_roundtrip
 * Area: netinfo
 * Purpose: curl resolves "--interface <name>" scope ids with if_nametoindex
 *   (lib/cf-socket.c, IPv6 scope) and the CONVERT* helpers behind it. Verify
 *   the round trip index -> LUID -> name -> index on every adapter reported by
 *   GetAdaptersAddresses, and the failure results.
 * APIs: GetAdaptersAddresses, ConvertInterfaceIndexToLuid,
 *   ConvertInterfaceLuidToNameA, ConvertInterfaceNameToLuidA,
 *   ConvertInterfaceLuidToIndex, if_nametoindex, if_indextoname.
 * Success means: for every adapter, ConvertInterfaceIndexToLuid is NO_ERROR,
 *   the LUID maps to a name that if_nametoindex maps back to IfIndex and
 *   if_indextoname(IfIndex) returns the same name (case-insensitive);
 *   if_nametoindex("no-such-if-0") == 0; if_indextoname(0x7ffffff0) == NULL;
 *   ConvertInterfaceIndexToLuid(0x7ffffff0) fails with ERROR_FILE_NOT_FOUND
 *   (2); a software-loopback adapter exists.
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

#define TEST_NAME "if_nametoindex_roundtrip"

int main(void)
{
  ULONG size = 32768, rc;
  IP_ADAPTER_ADDRESSES *all, *a;
  int n = 0, loop = 0;
  NET_LUID luid;
  char nm[IF_MAX_STRING_SIZE + 1], nm2[IF_NAMESIZE + 1];

  all = (IP_ADAPTER_ADDRESSES *)malloc(size);
  rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, all, &size);
  if(rc == ERROR_BUFFER_OVERFLOW) { free(all); all = malloc(size); rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, all, &size); }
  EXPECT(rc == NO_ERROR, "GetAdaptersAddresses rc=%lu", rc);
  for(a = all; a; a = a->Next) {
    DWORD idx = a->IfIndex;
    NET_LUID l2;
    NET_IFINDEX back = 0;
    char *r;
    if(idx == 0) continue;
    n++;
    if(a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) loop++;
    EXPECT(ConvertInterfaceIndexToLuid(idx, &luid) == NO_ERROR, "IndexToLuid(%lu)", idx);
    EXPECT(ConvertInterfaceLuidToNameA(&luid, nm, sizeof(nm)) == NO_ERROR, "LuidToName(%lu)", idx);
    EXPECT(ConvertInterfaceNameToLuidA(nm, &l2) == NO_ERROR && l2.Value == luid.Value, "NameToLuid('%s')", nm);
    EXPECT(ConvertInterfaceLuidToIndex(&luid, &back) == NO_ERROR && back == idx, "LuidToIndex %lu vs %lu", (unsigned long)back, idx);
    EXPECT(if_nametoindex(nm) == idx, "if_nametoindex('%s')=%lu want %lu", nm, (unsigned long)if_nametoindex(nm), idx);
    r = if_indextoname(idx, nm2);
    EXPECT(r == nm2 && _stricmp(nm2, nm) == 0, "if_indextoname(%lu)='%s' want '%s'", idx, r ? nm2 : "(null)", nm);
    INFO("if %lu type=%lu name='%s'", idx, (unsigned long)a->IfType, nm);
  }
  EXPECT(n > 0, "no adapters");
  EXPECT(loop >= 1, "no software loopback adapter");
  EXPECT(if_nametoindex("no-such-if-0") == 0, "unknown name nonzero");
  EXPECT(if_indextoname(0x7ffffff0, nm2) == NULL, "unknown index returned a name");
  rc = ConvertInterfaceIndexToLuid(0x7ffffff0, &luid);
  EXPECT(rc == ERROR_FILE_NOT_FOUND, "IndexToLuid(bad) rc=%lu want 2", rc);
  free(all);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
