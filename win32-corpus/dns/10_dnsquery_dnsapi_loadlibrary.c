/*
 * Test 10_dnsquery_dnsapi_loadlibrary
 *
 * Purpose: the dnsapi.dll query surface (DnsQuery_A, DnsQuery_W, DnsFree),
 * loaded with LoadLibrary/GetProcAddress as the corpus rules require. Uses
 * DNS_QUERY_NO_WIRE_QUERY so that nothing is sent to a DNS server: "localhost"
 * must come from the local hosts data, and an unknown ".invalid" name must
 * fail without any network traffic.
 *
 * APIs: LoadLibraryW, GetProcAddress, DnsQuery_A, DnsQuery_W, DnsFree,
 *       FreeLibrary.
 *
 * Success: if dnsapi.dll or an export is missing, or DnsQuery_A returns
 * ERROR_CALL_NOT_IMPLEMENTED, the test SKIPs. The query for
 * "corpus-nx-test.invalid" under DNS_QUERY_NO_WIRE_QUERY (ANSI and wide)
 * returns non-zero with a NULL record list. Then DnsQuery_A and DnsQuery_W
 * for "localhost" type A with the same options return 0 and a DNS_TYPE_A
 * record whose IPv4 bytes are 127.0.0.1. Under wine only, if the localhost
 * query fails with ERROR_INVALID_NAME, the test SKIPs after the NXDOMAIN
 * checks, because wine's DnsQuery does not resolve localhost here.
 *
 * Source: no direct curl call site; curl resolves through getaddrinfo()
 *         (lib/curl_addrinfo.c:111-130). This covers the dnsapi surface the
 *         corpus requires. Flags come from the mingw windns.h definitions.
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
#include <windows.h>
#include <windns.h>
#include <stdio.h>
#include <string.h>

#define T "10_dnsquery_dnsapi_loadlibrary"

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [GLE=%lu]\n", (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

#define SKIPF(msg) do { \
    printf("SKIP %s: %s\n", T, msg); status = 77; goto out; } while(0)

typedef DNS_STATUS (WINAPI *PFN_DnsQuery_A)(PCSTR, WORD, DWORD, PVOID,
                                            PDNS_RECORDA *, PVOID *);
typedef DNS_STATUS (WINAPI *PFN_DnsQuery_W)(PCWSTR, WORD, DWORD, PVOID,
                                            PDNS_RECORDW *, PVOID *);
/* DNS_FREE_TYPE: DnsFreeRecordList == 1 */
typedef void (WINAPI *PFN_DnsFree)(PVOID, int);

#define CORPUS_DNS_FREE_RECORD_LIST 1

static int record_is_loopback_a(const DNS_RECORDA *r)
{
  const unsigned char *b;
  if(!r || r->wType != DNS_TYPE_A)
    return 0;
  b = (const unsigned char *)&r->Data.A.IpAddress;
  return b[0] == 127 && b[1] == 0 && b[2] == 0 && b[3] == 1;
}

static int record_is_loopback_w(const DNS_RECORDW *r)
{
  const unsigned char *b;
  if(!r || r->wType != DNS_TYPE_A)
    return 0;
  b = (const unsigned char *)&r->Data.A.IpAddress;
  return b[0] == 127 && b[1] == 0 && b[2] == 0 && b[3] == 1;
}

/* Wine exports wine_get_version from ntdll; real Windows does not. */
static int is_wine(void)
{
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  return nt != NULL && GetProcAddress(nt, "wine_get_version") != NULL;
}

int main(void)
{
  HMODULE dns;
  PFN_DnsQuery_A pQa;
  PFN_DnsQuery_W pQw;
  PFN_DnsFree pFree;
  PDNS_RECORDA ra = NULL;
  PDNS_RECORDW rw = NULL;
  DNS_STATUS st;
  const DWORD opts = DNS_QUERY_NO_WIRE_QUERY;

  dns = LoadLibraryW(L"dnsapi.dll");
  if(!dns)
    SKIPF("dnsapi.dll not loadable");
  pQa = (PFN_DnsQuery_A)(void *)GetProcAddress(dns, "DnsQuery_A");
  pQw = (PFN_DnsQuery_W)(void *)GetProcAddress(dns, "DnsQuery_W");
  pFree = (PFN_DnsFree)(void *)GetProcAddress(dns, "DnsFree");
  if(!pQa || !pQw || !pFree)
    SKIPF("dnsapi.dll is missing DnsQuery_A/DnsQuery_W/DnsFree");

  /* Unknown name, cache only: must fail and return no records. Run first
     so that the negative contract is checked even when the positive
     localhost check is skipped below. */
  st = pQa("corpus-nx-test.invalid", DNS_TYPE_A, opts, NULL, &ra, NULL);
  if(st == ERROR_CALL_NOT_IMPLEMENTED)
    SKIPF("DnsQuery_A not implemented by this runtime");
  if(st == 0)
    FAILF("DnsQuery_A(corpus-nx-test.invalid) with NO_WIRE_QUERY succeeded");
  if(ra)
    FAILF("DnsQuery_A failed but still returned a record list");

  st = pQw(L"corpus-nx-test.invalid", DNS_TYPE_A, opts, NULL, &rw, NULL);
  if(st == 0)
    FAILF("DnsQuery_W(corpus-nx-test.invalid) with NO_WIRE_QUERY succeeded");
  if(rw)
    FAILF("DnsQuery_W failed but still returned a record list");

  /* ANSI query for localhost, cache/hosts only. */
  st = pQa("localhost", DNS_TYPE_A, opts, NULL, &ra, NULL);
  if(st == ERROR_INVALID_NAME && is_wine())
    SKIPF("wine DnsQuery_A cannot resolve localhost with NO_WIRE_QUERY "
          "(ERROR_INVALID_NAME); the NXDOMAIN checks above passed");
  if(st != 0)
    FAILF("DnsQuery_A(localhost) returned %lu", (unsigned long)st);
  if(!ra)
    FAILF("DnsQuery_A(localhost) returned success with no records");
  if(!record_is_loopback_a(ra))
    FAILF("DnsQuery_A(localhost) first record is not an A 127.0.0.1");
  pFree(ra, CORPUS_DNS_FREE_RECORD_LIST);
  ra = NULL;

  /* Wide query for localhost. */
  st = pQw(L"localhost", DNS_TYPE_A, opts, NULL, &rw, NULL);
  if(st != 0)
    FAILF("DnsQuery_W(localhost) returned %lu", (unsigned long)st);
  if(!rw)
    FAILF("DnsQuery_W(localhost) returned no records");
  if(!record_is_loopback_w(rw))
    FAILF("DnsQuery_W(localhost) first record is not an A 127.0.0.1");
  pFree(rw, CORPUS_DNS_FREE_RECORD_LIST);
  rw = NULL;

out:
  if(dns)
    FreeLibrary(dns);
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
