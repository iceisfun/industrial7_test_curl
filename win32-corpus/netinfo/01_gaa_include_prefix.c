/*
 * Test: gaa_include_prefix
 *
 * Purpose: Enumerate adapters with GetAdaptersAddresses(AF_UNSPEC,
 *   GAA_FLAG_INCLUDE_PREFIX) using the documented two-call sizing pattern,
 *   and verify the loopback adapter reports 127.0.0.1 as a unicast address
 *   and 127.0.0.0/8 as a prefix entry.
 *
 * APIs: GetAdaptersAddresses (iphlpapi), IP_ADAPTER_ADDRESSES,
 *   IP_ADAPTER_UNICAST_ADDRESS, IP_ADAPTER_PREFIX.
 *
 * Success means: the call returns NO_ERROR, an adapter with
 *   IfType == IF_TYPE_SOFTWARE_LOOPBACK exists, it has an AF_INET unicast
 *   address 127.0.0.1 and at least one prefix entry 127.0.0.0 / 8.
 *   Every AF_INET prefix entry on the loopback adapter has a PrefixLength
 *   <= 32.
 *   If no loopback adapter is reported at all, the test SKIPs (77). If no
 *   loopback adapter reports any prefix entry and the host is wine (detected
 *   via ntdll!wine_get_version), it also SKIPs; on real Windows that FAILs.
 *
 * Source reference: curl has no direct Windows call site for
 *   GetAdaptersAddresses. This is the Windows counterpart of the
 *   getifaddrs() interface enumeration in lib/if2ip.c:94 (Curl_if2ip), which curl
 *   uses to resolve an --interface name to a local address (analogy only;
 *   curl itself does not call GetAdaptersAddresses).
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
#define TEST_NAME "gaa_include_prefix"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* curl detects wine through the exported ntdll!wine_get_version
   (lib/vtls/schannel.c:2625). Used only to classify a missing feature. */
static BOOL is_wine(void)
{
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  return ntdll && GetProcAddress(ntdll, "wine_get_version") != NULL;
}

static PIP_ADAPTER_ADDRESSES get_adapters(ULONG flags, ULONG *rc_out)
{
  ULONG size = 15000;
  int attempt;
  for(attempt = 0; attempt < 3; attempt++) {
    PIP_ADAPTER_ADDRESSES buf = (PIP_ADAPTER_ADDRESSES)malloc(size);
    ULONG rc;
    if(!buf) {
      *rc_out = ERROR_NOT_ENOUGH_MEMORY;
      return NULL;
    }
    rc = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, buf, &size);
    if(rc == NO_ERROR) {
      *rc_out = NO_ERROR;
      return buf;
    }
    free(buf);
    if(rc != ERROR_BUFFER_OVERFLOW) {
      *rc_out = rc;
      return NULL;
    }
  }
  *rc_out = ERROR_BUFFER_OVERFLOW;
  return NULL;
}

int main(void)
{
  ULONG rc = 0;
  PIP_ADAPTER_ADDRESSES adapters, a;
  BOOL found_loopback = FALSE, found_addr = FALSE, found_prefix = FALSE;
  ULONG prefix_count = 0;

  adapters = get_adapters(GAA_FLAG_INCLUDE_PREFIX, &rc);
  if(!adapters) {
    printf("FAIL %s: GetAdaptersAddresses(GAA_FLAG_INCLUDE_PREFIX) rc=%lu GetLastError=%lu\n",
           TEST_NAME, (unsigned long)rc, (unsigned long)GetLastError());
    return 1;
  }

  for(a = adapters; a; a = a->Next) {
    PIP_ADAPTER_UNICAST_ADDRESS ua;
    PIP_ADAPTER_PREFIX pfx;

    if(a->IfType != IF_TYPE_SOFTWARE_LOOPBACK)
      continue;
    found_loopback = TRUE;

    for(ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
      if(ua->Address.lpSockaddr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ua->Address.lpSockaddr;
        if(sin->sin_addr.S_un.S_addr == htonl(0x7f000001UL))
          found_addr = TRUE;
      }
    }

    for(pfx = a->FirstPrefix; pfx; pfx = pfx->Next) {
      struct sockaddr_in *sin;
      prefix_count++;
      if(pfx->Address.lpSockaddr->sa_family != AF_INET)
        continue;
      sin = (struct sockaddr_in *)pfx->Address.lpSockaddr;
      if(sin->sin_addr.S_un.S_addr == htonl(0x7f000000UL) &&
         pfx->PrefixLength == 8)
        found_prefix = TRUE;
      if(pfx->PrefixLength > 32) {
        printf("FAIL %s: loopback AF_INET prefix length %lu > 32\n",
               TEST_NAME, (unsigned long)pfx->PrefixLength);
        free(adapters);
        return 1;
      }
    }
  }

  if(!found_loopback) {
    free(adapters);
    printf("SKIP %s: no IF_TYPE_SOFTWARE_LOOPBACK adapter reported\n", TEST_NAME);
    return 77;
  }
  if(!found_addr) {
    free(adapters);
    printf("FAIL %s: loopback adapter has no AF_INET unicast 127.0.0.1\n", TEST_NAME);
    return 1;
  }
  if(prefix_count == 0) {
    free(adapters);
    if(is_wine()) {
      printf("SKIP %s: wine does not populate the prefix list (GAA_FLAG_INCLUDE_PREFIX)\n",
             TEST_NAME);
      return 77;
    }
    printf("FAIL %s: GAA_FLAG_INCLUDE_PREFIX returned no prefix entries on any loopback adapter\n",
           TEST_NAME);
    return 1;
  }
  if(!found_prefix) {
    free(adapters);
    printf("FAIL %s: loopback adapter has no prefix 127.0.0.0/8 (prefix entries=%lu)\n",
           TEST_NAME, (unsigned long)prefix_count);
    return 1;
  }

  free(adapters);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
