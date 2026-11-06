/*
 * Test: gaa_flags_and_families
 * Area: netinfo
 * Purpose: GetAdaptersAddresses flag and family handling, as used when a
 *   client enumerates local addresses (curl --interface / --local-port address
 *   selection analogues, c-ares). Verifies the SKIP_* flags drop the
 *   respective lists, family filtering works, and the loopback adapter's
 *   address attributes.
 * APIs: GetAdaptersAddresses (GAA_FLAG_SKIP_UNICAST/ANYCAST/MULTICAST/DNS_SERVER,
 *   AF_INET, AF_INET6, AF_UNSPEC), IP_ADAPTER_UNICAST_ADDRESS.
 * Success means: AF_INET returns only adapters with IPv4 (Ipv6IfIndex ignored)
 *   and every unicast address is AF_INET; AF_INET6 every unicast is AF_INET6;
 *   with GAA_FLAG_SKIP_UNICAST FirstUnicastAddress is NULL on all adapters,
 *   likewise SKIP_ANYCAST/SKIP_MULTICAST/SKIP_DNS_SERVER for their lists; the
 *   loopback adapter's 127.0.0.1 has OnLinkPrefixLength 8, DadState
 *   IpDadStatePreferred, and on a host with IPv6 enabled its ::1 has
 *   OnLinkPrefixLength 128; Length >= 144; the adapter
 *   count with AF_UNSPEC is >= each single family.
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

#define TEST_NAME "gaa_flags_and_families"

static IP_ADAPTER_ADDRESSES *get(ULONG fam, ULONG flags)
{
  ULONG size = 32768, rc;
  IP_ADAPTER_ADDRESSES *p = (IP_ADAPTER_ADDRESSES *)malloc(size);
  rc = GetAdaptersAddresses(fam, flags, NULL, p, &size);
  if(rc == ERROR_BUFFER_OVERFLOW) { free(p); p = (IP_ADAPTER_ADDRESSES *)malloc(size); rc = GetAdaptersAddresses(fam, flags, NULL, p, &size); }
  if(rc != NO_ERROR) { printf("INFO GetAdaptersAddresses(%lu,0x%lx) rc=%lu\n", fam, flags, rc); free(p); return NULL; }
  return p;
}
static int count(IP_ADAPTER_ADDRESSES *p) { int n = 0; for(; p; p = p->Next) n++; return n; }

int main(void)
{
  IP_ADAPTER_ADDRESSES *all, *v4, *v6, *a, *x;
  int n4, n6, nall, saw_lo4 = 0, saw_lo6 = 0;
  IP_ADAPTER_UNICAST_ADDRESS *u;

  all = get(AF_UNSPEC, 0); v4 = get(AF_INET, 0); v6 = get(AF_INET6, 0);
  EXPECT(all && v4 && v6, "base queries failed");
  nall = count(all); n4 = count(v4); n6 = count(v6);
  INFO("adapters: all=%d v4=%d v6=%d", nall, n4, n6);
  EXPECT(nall >= n4 && nall >= n6 && n4 >= 1, "adapter counts inconsistent");
  for(a = v4; a; a = a->Next) {
    EXPECT(a->Length >= 144, "short Length %lu", a->Length);
    for(u = a->FirstUnicastAddress; u; u = u->Next) {
      EXPECT(u->Address.lpSockaddr->sa_family == AF_INET, "AF_INET query returned family %d", u->Address.lpSockaddr->sa_family);
      if(a->IfType == IF_TYPE_SOFTWARE_LOOPBACK && ((struct sockaddr_in *)u->Address.lpSockaddr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
        saw_lo4 = 1;
        INFO("127.0.0.1 prefix=%u dad=%d origin=%d suffix=%d flags=0x%lx", u->OnLinkPrefixLength, (int)u->DadState, (int)u->PrefixOrigin, (int)u->SuffixOrigin, u->Flags);
        EXPECT(u->OnLinkPrefixLength == 8, "127.0.0.1 OnLinkPrefixLength %u want 8", u->OnLinkPrefixLength);
        EXPECT(u->DadState == IpDadStatePreferred, "127.0.0.1 DadState %d", (int)u->DadState);
      }
    }
  }
  EXPECT(saw_lo4, "127.0.0.1 not found on loopback");
  for(a = v6; a; a = a->Next)
    for(u = a->FirstUnicastAddress; u; u = u->Next) {
      EXPECT(u->Address.lpSockaddr->sa_family == AF_INET6, "AF_INET6 query returned family %d", u->Address.lpSockaddr->sa_family);
      if(a->IfType == IF_TYPE_SOFTWARE_LOOPBACK && memcmp(&((struct sockaddr_in6 *)u->Address.lpSockaddr)->sin6_addr, &in6addr_loopback, 16) == 0) {
        saw_lo6 = 1;
        INFO("::1 prefix=%u dad=%d scope=%lu ipv6ifindex=%lu", u->OnLinkPrefixLength, (int)u->DadState,
             (unsigned long)((struct sockaddr_in6 *)u->Address.lpSockaddr)->sin6_scope_id, (unsigned long)a->Ipv6IfIndex);
        EXPECT(u->OnLinkPrefixLength == 128, "::1 OnLinkPrefixLength %u want 128", u->OnLinkPrefixLength);
        EXPECT(a->Ipv6IfIndex != 0, "loopback Ipv6IfIndex 0");
      }
    }
  INFO("::1 seen on loopback: %d", saw_lo6);

  x = get(AF_UNSPEC, GAA_FLAG_SKIP_UNICAST);
  EXPECT(x, "SKIP_UNICAST failed");
  for(a = x; a; a = a->Next) EXPECT(a->FirstUnicastAddress == NULL, "SKIP_UNICAST left unicast on if %lu", a->IfIndex);
  free(x);
  x = get(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST);
  for(a = x; a; a = a->Next) EXPECT(a->FirstAnycastAddress == NULL, "SKIP_ANYCAST left anycast");
  free(x);
  x = get(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST);
  for(a = x; a; a = a->Next) EXPECT(a->FirstMulticastAddress == NULL, "SKIP_MULTICAST left multicast");
  free(x);
  x = get(AF_UNSPEC, GAA_FLAG_SKIP_DNS_SERVER);
  for(a = x; a; a = a->Next) EXPECT(a->FirstDnsServerAddress == NULL, "SKIP_DNS_SERVER left DNS servers");
  free(x);
  /* sanity: without SKIP_UNICAST the loopback adapter does have unicast addresses */
  for(a = all; a; a = a->Next)
    if(a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) EXPECT(a->FirstUnicastAddress != NULL, "loopback has no unicast list");
  free(all); free(v4); free(v6);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
