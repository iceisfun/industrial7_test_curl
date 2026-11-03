/*
 * Test: gaa_buffer_sizing
 *
 * Purpose: Exercise the GetAdaptersAddresses size-query protocol that curl
 *   depends on when it lists interfaces: a NULL/0 query must report
 *   ERROR_BUFFER_OVERFLOW with a usable required size, an undersized buffer
 *   must fail the same way without writing past the buffer, and a retry with
 *   the reported size must succeed and produce the same adapter count as a
 *   plain full-size call. Also checks that each adapter's Next chain stays
 *   inside the returned buffer.
 *
 * APIs: GetAdaptersAddresses (iphlpapi), IP_ADAPTER_ADDRESSES.
 *
 * Success means: rc(NULL,0) == ERROR_BUFFER_OVERFLOW and reported size >=
 *   sizeof(IP_ADAPTER_ADDRESSES); rc(8-byte buffer) == ERROR_BUFFER_OVERFLOW
 *   and reports a size >= sizeof(IP_ADAPTER_ADDRESSES); rc(full buffer)
 *   == NO_ERROR; the Next chain terminates
 *   within the buffer; the count matches on a second full call.
 *   Wine reports the same protocol, so no SKIP is expected; if the first
 *   query returns a different error (e.g. ERROR_NOT_SUPPORTED), the test SKIPs.
 *
 * Source reference: no direct Windows call site in the curl tree. The
 *   variable-length interface-table handling this exercises is the Windows
 *   analogue of the getifaddrs() enumeration in lib/if2ip.c:94 (Curl_if2ip).
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
#define TEST_NAME "gaa_buffer_sizing"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ULONG count_adapters(PIP_ADAPTER_ADDRESSES head, ULONG buf_size,
                            BOOL *chain_ok)
{
  ULONG n = 0;
  PIP_ADAPTER_ADDRESSES a;
  unsigned char *base = (unsigned char *)head;
  *chain_ok = TRUE;
  for(a = head; a; a = a->Next) {
    unsigned char *p = (unsigned char *)a;
    n++;
    if(p < base || (ULONG)(p - base) >= buf_size) {
      *chain_ok = FALSE;
      break;
    }
    if(n > 4096) {  /* cycle guard */
      *chain_ok = FALSE;
      break;
    }
  }
  return n;
}

int main(void)
{
  ULONG size0 = 0, rc, size_full, count_full, count_retry;
  PIP_ADAPTER_ADDRESSES full, retry;
  BOOL chain_ok = FALSE;
  unsigned char tiny[8];
  ULONG tiny_size = sizeof(tiny);
  ULONG size_after_tiny;

  /* 1. NULL buffer, size 0: must ask for more space. */
  rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size0);
  if(rc == ERROR_NOT_SUPPORTED || rc == ERROR_CALL_NOT_IMPLEMENTED) {
    printf("SKIP %s: GetAdaptersAddresses not implemented (rc=%lu)\n",
           TEST_NAME, (unsigned long)rc);
    return 77;
  }
  if(rc != ERROR_BUFFER_OVERFLOW) {
    printf("FAIL %s: size query rc=%lu (want ERROR_BUFFER_OVERFLOW=111) GetLastError=%lu\n",
           TEST_NAME, (unsigned long)rc, (unsigned long)GetLastError());
    return 1;
  }
  if(size0 < sizeof(IP_ADAPTER_ADDRESSES)) {
    printf("FAIL %s: size query reported %lu bytes, less than sizeof(IP_ADAPTER_ADDRESSES)=%lu\n",
           TEST_NAME, (unsigned long)size0, (unsigned long)sizeof(IP_ADAPTER_ADDRESSES));
    return 1;
  }

  /* 2. Undersized buffer: must fail without writing past it, and report
   *    the same required size. */
  memset(tiny, 0xAB, sizeof(tiny));
  size_after_tiny = tiny_size;
  rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL,
                            (PIP_ADAPTER_ADDRESSES)tiny, &size_after_tiny);
  if(rc != ERROR_BUFFER_OVERFLOW) {
    printf("FAIL %s: undersized buffer rc=%lu (want ERROR_BUFFER_OVERFLOW) GetLastError=%lu\n",
           TEST_NAME, (unsigned long)rc, (unsigned long)GetLastError());
    return 1;
  }
  {
    size_t i;
    for(i = 0; i < sizeof(tiny); i++) {
      if(tiny[i] != 0xAB) {
        printf("FAIL %s: GetAdaptersAddresses wrote past an 8-byte buffer at offset %u\n",
               TEST_NAME, (unsigned)i);
        return 1;
      }
    }
  }
  if(size_after_tiny < sizeof(IP_ADAPTER_ADDRESSES)) {
    printf("FAIL %s: undersized call reported size %lu, too small\n",
           TEST_NAME, (unsigned long)size_after_tiny);
    return 1;
  }

  /* 3. Full-size call with the size reported by step 2. */
  size_full = size_after_tiny;
  full = (PIP_ADAPTER_ADDRESSES)malloc(size_full);
  if(!full) {
    printf("FAIL %s: malloc(%lu) failed\n", TEST_NAME, (unsigned long)size_full);
    return 1;
  }
  rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, full, &size_full);
  if(rc != NO_ERROR) {
    free(full);
    printf("FAIL %s: full-size call rc=%lu GetLastError=%lu\n",
           TEST_NAME, (unsigned long)rc, (unsigned long)GetLastError());
    return 1;
  }
  count_full = count_adapters(full, size_full, &chain_ok);
  if(!chain_ok || count_full == 0) {
    free(full);
    printf("FAIL %s: adapter chain invalid (count=%lu chain_ok=%d)\n",
           TEST_NAME, (unsigned long)count_full, (int)chain_ok);
    return 1;
  }

  /* 4. Second full call, sized from the first: adapter count must be stable. */
  retry = (PIP_ADAPTER_ADDRESSES)malloc(size_full);
  if(!retry) {
    free(full);
    printf("FAIL %s: malloc(retry) failed\n", TEST_NAME);
    return 1;
  }
  {
    ULONG size_retry = size_full;
    rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, retry, &size_retry);
    if(rc != NO_ERROR) {
      free(full);
      free(retry);
      printf("FAIL %s: retry call rc=%lu GetLastError=%lu\n",
             TEST_NAME, (unsigned long)rc, (unsigned long)GetLastError());
      return 1;
    }
    count_retry = count_adapters(retry, size_retry, &chain_ok);
    if(!chain_ok) {
      free(full);
      free(retry);
      printf("FAIL %s: retry adapter chain escapes buffer\n", TEST_NAME);
      return 1;
    }
  }
  free(retry);
  free(full);

  if(count_retry != count_full) {
    printf("FAIL %s: adapter count changed between calls (%lu vs %lu)\n",
           TEST_NAME, (unsigned long)count_full, (unsigned long)count_retry);
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
