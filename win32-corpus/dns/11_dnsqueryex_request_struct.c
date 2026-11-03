/*
 * Test 11_dnsqueryex_request_struct
 *
 * Purpose: the DNS_QUERY_REQUEST / DNS_QUERY_RESULT structure protocol of
 * DnsQueryEx() (Windows 8+), in both synchronous mode (no completion
 * callback) and asynchronous mode (callback plus a wait event). The request
 * structure is declared locally with the Win8 SDK layout (Version 1 fields)
 * because mingw's windns.h does not expose it. DnsQueryEx and DnsFree are
 * resolved with LoadLibrary/GetProcAddress, and the test SKIPs when
 * resolution fails.
 *
 * APIs: LoadLibraryW, GetProcAddress, DnsQueryEx, DnsFree, CreateEventW,
 *       WaitForSingleObject, FreeLibrary.
 *
 * Success: synchronous DnsQueryEx with Version=DNS_QUERY_REQUEST_VERSION1,
 * QueryName=L"localhost", QueryType=DNS_TYPE_A, QueryOptions=
 * DNS_QUERY_NO_WIRE_QUERY, returns 0 and the result's QueryStatus is 0 with
 * an A record for 127.0.0.1. Asynchronous mode returns 0 or DNS_REQUEST_PENDING
 * (9506); the completion callback fires within 10 seconds with the same
 * record. Result lists are freed with DnsFree(DnsFreeRecordList). An
 * ERROR_CALL_NOT_IMPLEMENTED return SKIPs. Under wine only, the stub return
 * DNS_ERROR_RCODE_NOT_IMPLEMENTED (9004) also SKIPs; on any other runtime
 * that status is a FAIL.
 *
 * Source: no direct curl call site. The DNS_QUERY_REQUEST layout is the
 *         Win8 SDK definition; the result feeds the same loopback check as
 *         lib/vdns/asyn-thrdd.c:415 (resolver result handling).
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

#define T "11_dnsqueryex_request_struct"

#define CORPUS_REQUEST_VERSION1 1
#define CORPUS_RESULTS_VERSION1 1
#define CORPUS_DNS_REQUEST_PENDING 9506
#define CORPUS_DNS_FREE_RECORD_LIST 1

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [GLE=%lu]\n", (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

#define SKIPF(msg) do { \
    printf("SKIP %s: %s\n", T, msg); status = 77; goto out; } while(0)

/* Win8 SDK layout of DNS_QUERY_REQUEST (x64: 64 bytes). */
typedef struct corpus_dns_query_request {
  ULONG Version;
  PCWSTR QueryName;
  WORD QueryType;
  ULONG64 QueryOptions;
  PVOID pDnsServerList;
  ULONG InterfaceIndex;
  PVOID pQueryCompletionCallback;
  PVOID pQueryContext;
} CORPUS_DNS_QUERY_REQUEST;

typedef struct corpus_dns_query_result {
  ULONG Version;
  DNS_STATUS QueryStatus;
  ULONG64 QueryOptions;
  PDNS_RECORDW pQueryRecords;
  PVOID Reserved;
} CORPUS_DNS_QUERY_RESULT;

typedef VOID (WINAPI *CORPUS_QUERY_COMPLETION)(PVOID, CORPUS_DNS_QUERY_RESULT *);

typedef DNS_STATUS (WINAPI *PFN_DnsQueryEx)(CORPUS_DNS_QUERY_REQUEST *,
                                            CORPUS_DNS_QUERY_RESULT *, PVOID);
typedef void (WINAPI *PFN_DnsFree)(PVOID, int);

#define CORPUS_DNS_RCODE_NOT_IMPLEMENTED 9004

/* Wine exports wine_get_version from ntdll; real Windows does not. */
static int is_wine(void)
{
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  return nt != NULL && GetProcAddress(nt, "wine_get_version") != NULL;
}

static volatile LONG cb_calls = 0;
static DNS_STATUS cb_status = 0xFFFFFFFF;
static PDNS_RECORDW cb_records = NULL;
static HANDLE cb_event = NULL;

static VOID WINAPI query_done(PVOID ctx, CORPUS_DNS_QUERY_RESULT *res)
{
  (void)ctx;
  cb_status = res->QueryStatus;
  cb_records = res->pQueryRecords;
  InterlockedIncrement(&cb_calls);
  SetEvent(cb_event);
}

static int first_is_loopback(const DNS_RECORDW *r)
{
  const unsigned char *b;
  if(!r || r->wType != DNS_TYPE_A)
    return 0;
  b = (const unsigned char *)&r->Data.A.IpAddress;
  return b[0] == 127 && b[1] == 0 && b[2] == 0 && b[3] == 1;
}

int main(void)
{
  HMODULE dns;
  PFN_DnsQueryEx pQueryEx;
  PFN_DnsFree pFree;
  CORPUS_DNS_QUERY_REQUEST req;
  CORPUS_DNS_QUERY_RESULT res;
  DNS_STATUS st;
  int wait_ok;

  dns = LoadLibraryW(L"dnsapi.dll");
  if(!dns)
    SKIPF("dnsapi.dll not loadable");
  pQueryEx = (PFN_DnsQueryEx)(void *)GetProcAddress(dns, "DnsQueryEx");
  pFree = (PFN_DnsFree)(void *)GetProcAddress(dns, "DnsFree");
  if(!pQueryEx || !pFree)
    SKIPF("DnsQueryEx/DnsFree not exported (pre-Win8 dnsapi)");

  /* Synchronous: callback NULL. */
  memset(&req, 0, sizeof(req));
  memset(&res, 0, sizeof(res));
  req.Version = CORPUS_REQUEST_VERSION1;
  req.QueryName = L"localhost";
  req.QueryType = DNS_TYPE_A;
  req.QueryOptions = DNS_QUERY_NO_WIRE_QUERY;
  res.Version = CORPUS_RESULTS_VERSION1;

  st = pQueryEx(&req, &res, NULL);
  if(st == ERROR_CALL_NOT_IMPLEMENTED)
    SKIPF("DnsQueryEx not implemented by this runtime");
  if(st == CORPUS_DNS_RCODE_NOT_IMPLEMENTED && is_wine())
    SKIPF("wine DnsQueryEx is a stub returning DNS_ERROR_RCODE_NOT_IMPLEMENTED (9004)");
  if(st != 0)
    FAILF("sync DnsQueryEx returned %lu", (unsigned long)st);
  if(res.QueryStatus != 0)
    FAILF("sync result QueryStatus=%lu", (unsigned long)res.QueryStatus);
  if(!first_is_loopback(res.pQueryRecords))
    FAILF("sync DnsQueryEx(localhost) did not return A 127.0.0.1");
  pFree(res.pQueryRecords, CORPUS_DNS_FREE_RECORD_LIST);
  res.pQueryRecords = NULL;

  /* Asynchronous: callback set, must report pending or complete at once. */
  cb_event = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!cb_event)
    FAILF("CreateEventW failed");
  memset(&res, 0, sizeof(res));
  res.Version = CORPUS_RESULTS_VERSION1;
  req.pQueryCompletionCallback = (PVOID)(CORPUS_QUERY_COMPLETION)query_done;
  req.pQueryContext = (PVOID)&cb_event;

  st = pQueryEx(&req, &res, NULL);
  if(st == CORPUS_DNS_REQUEST_PENDING) {
    wait_ok = WaitForSingleObject(cb_event, 10000) == WAIT_OBJECT_0;
    if(!wait_ok)
      FAILF("async DnsQueryEx callback did not fire within 10 seconds");
    if(InterlockedCompareExchange(&cb_calls, 0, 0) != 1)
      FAILF("completion callback ran %ld times, expected 1",
            (long)InterlockedCompareExchange(&cb_calls, 0, 0));
    if(cb_status != 0)
      FAILF("async completion status=%lu", (unsigned long)cb_status);
    if(!first_is_loopback(cb_records))
      FAILF("async completion did not return A 127.0.0.1");
    pFree(cb_records, CORPUS_DNS_FREE_RECORD_LIST);
  }
  else if(st == 0) {
    /* Completed inline: the callback may or may not have been used. The
       result structure itself must carry the answer. */
    if(res.QueryStatus != 0 || !first_is_loopback(res.pQueryRecords))
      FAILF("inline async DnsQueryEx did not return A 127.0.0.1");
    pFree(res.pQueryRecords, CORPUS_DNS_FREE_RECORD_LIST);
  }
  else
    FAILF("async DnsQueryEx returned %lu, expected 0 or DNS_REQUEST_PENDING",
          (unsigned long)st);

out:
  if(cb_event)
    CloseHandle(cb_event);
  if(dns)
    FreeLibrary(dns);
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
