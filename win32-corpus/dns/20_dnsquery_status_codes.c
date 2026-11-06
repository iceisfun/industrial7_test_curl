/*
 * Test 20_dnsquery_status_codes
 *
 * Purpose: the DNS_STATUS values dnsapi.dll's DnsQuery_A returns for local
 * names, IP literals and malformed names. curl does not call DnsQuery (it
 * uses getaddrinfo), but programs that bypass the system resolver (and
 * libraries linked next to curl, such as c-ares configured with the system
 * DNS) classify failures by these codes. Every query uses
 * DNS_QUERY_NO_WIRE_QUERY, so nothing leaves the machine.
 *
 * APIs: LoadLibraryW(dnsapi.dll), GetProcAddress, DnsQuery_A, DnsFree.
 *
 * Success (probed on Windows 10 22H2; the same in std and adm sessions):
 *   "localhost" type A -> 0 with one A record 127.0.0.1; type AAAA -> 0 with
 *   one AAAA record ::1; "localhost." (trailing dot) behaves the same.
 *   "127.0.0.1" type A -> 0 with that address; type AAAA -> 123
 *   (ERROR_INVALID_NAME). "::1" type AAAA -> 0 with that address; type A ->
 *   9560 (DNS_ERROR_INVALID_IP_ADDRESS). "corpus-nx.invalid" (A and AAAA) ->
 *   9701 (DNS_ERROR_RECORD_DOES_NOT_EXIST) with no record list. A name with an
 *   empty label ("a..b") -> 123. Failed calls leave the record list NULL.
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

#define T "20_dnsquery_status_codes"

typedef DNS_STATUS (WINAPI *PFN_DnsQuery_A)(PCSTR, WORD, DWORD, PVOID, PDNS_RECORDA *, PVOID *);
typedef void (WINAPI *PFN_DnsFree)(PVOID, int);

static PFN_DnsQuery_A pQuery;
static PFN_DnsFree pFree;
static int status = 0;
#define NOTE_FAIL(...) do { printf("FAIL %s: ", T); printf(__VA_ARGS__); printf("\n"); status = 1; } while(0)

/* want_kind: 0 none, 'A' one A record = want_addr, '6' one AAAA record ::1 */
static void q(const char *name, WORD type, DWORD want_status, char want_kind, const unsigned char *want_addr)
{
  PDNS_RECORDA rec = NULL;
  DNS_STATUS st = pQuery(name, type, DNS_QUERY_NO_WIRE_QUERY, NULL, &rec, NULL);
  if((DWORD)st != want_status)
    NOTE_FAIL("DnsQuery_A(%s, type %u) returned %lu, expected %lu", name, type, (unsigned long)st,
              (unsigned long)want_status);
  else if(want_status != 0) {
    if(rec)
      NOTE_FAIL("DnsQuery_A(%s, type %u) failed but returned records", name, type);
  }
  else {
    int n = 0;
    PDNS_RECORDA p;
    for(p = rec; p; p = p->pNext)
      n++;
    if(n != 1)
      NOTE_FAIL("DnsQuery_A(%s, type %u) returned %d records, expected 1", name, type, n);
    else if(want_kind == 'A') {
      if(rec->wType != DNS_TYPE_A || memcmp(&rec->Data.A.IpAddress, want_addr, 4) != 0)
        NOTE_FAIL("DnsQuery_A(%s, A) record is not the expected address", name);
    }
    else if(want_kind == '6') {
      static const unsigned char loop6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
      if(rec->wType != DNS_TYPE_AAAA || memcmp(&rec->Data.AAAA.Ip6Address, loop6, 16) != 0)
        NOTE_FAIL("DnsQuery_A(%s, AAAA) record is not ::1", name);
    }
  }
  if(rec)
    pFree(rec, DnsFreeRecordList);
}

int main(void)
{
  HMODULE dns = LoadLibraryW(L"dnsapi.dll");
  static const unsigned char lo4[4] = { 127, 0, 0, 1 };

  if(!dns) {
    printf("FAIL %s: dnsapi.dll not loadable\n", T);
    return 1;
  }
  pQuery = (PFN_DnsQuery_A)(void *)GetProcAddress(dns, "DnsQuery_A");
  pFree = (PFN_DnsFree)(void *)GetProcAddress(dns, "DnsFree");
  if(!pQuery || !pFree) {
    printf("FAIL %s: DnsQuery_A/DnsFree not exported\n", T);
    return 1;
  }

  q("localhost", DNS_TYPE_A, 0, 'A', lo4);
  q("localhost", DNS_TYPE_AAAA, 0, '6', NULL);
  q("localhost.", DNS_TYPE_A, 0, 'A', lo4);
  q("localhost.", DNS_TYPE_AAAA, 0, '6', NULL);
  q("127.0.0.1", DNS_TYPE_A, 0, 'A', lo4);
  q("127.0.0.1", DNS_TYPE_AAAA, 123, 0, NULL);
  q("::1", DNS_TYPE_AAAA, 0, '6', NULL);
  q("::1", DNS_TYPE_A, 9560, 0, NULL);
  q("corpus-nx.invalid", DNS_TYPE_A, 9701, 0, NULL);
  q("corpus-nx.invalid", DNS_TYPE_AAAA, 9701, 0, NULL);
  q("a..b", DNS_TYPE_A, 123, 0, NULL);
  q("a..b", DNS_TYPE_AAAA, 123, 0, NULL);

  FreeLibrary(dns);
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
