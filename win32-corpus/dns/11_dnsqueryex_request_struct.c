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
 * Success (probed on Windows 10 22H2, 20+ repetitions): synchronous DnsQueryEx
 * (callback NULL) with Version=DNS_QUERY_REQUEST_VERSION1, QueryName=
 * L"localhost", QueryType=DNS_TYPE_A, QueryOptions=DNS_QUERY_NO_WIRE_QUERY
 * returns 0 with QueryStatus 0 and an A record for 127.0.0.1. With a
 * completion callback set and a locally answered name (localhost, 127.0.0.1)
 * DnsQueryEx returns 0 with QueryStatus 0 and NO record list and never calls
 * the callback. A name that needs the resolver (example.invalid, no
 * NO_WIRE_QUERY) returns DNS_REQUEST_PENDING (9506) and the callback fires
 * exactly once; DnsCancelQuery on such a request returns 0 and the callback
 * reports ERROR_CANCELLED (1223). Bad arguments (Version 7, NULL QueryName,
 * result Version 9) return ERROR_INVALID_PARAMETER (87). A type-A query for
 * "::1" returns 9560 (DNS_ERROR_INVALID_IP_ADDRESS). Result lists are freed
 * with DnsFree(DnsFreeRecordList).
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

/* DNS_QUERY_CANCEL: opaque 32 bytes */
typedef struct { char Reserved[32]; } CORPUS_DNS_CANCEL;

typedef VOID (WINAPI *CORPUS_QUERY_COMPLETION)(PVOID, CORPUS_DNS_QUERY_RESULT *);

typedef DNS_STATUS (WINAPI *PFN_DnsQueryEx)(CORPUS_DNS_QUERY_REQUEST *,
                                            CORPUS_DNS_QUERY_RESULT *, CORPUS_DNS_CANCEL *);
typedef void (WINAPI *PFN_DnsFree)(PVOID, int);
typedef DNS_STATUS (WINAPI *PFN_DnsCancelQuery)(CORPUS_DNS_CANCEL *);

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
  PFN_DnsCancelQuery pCancelQuery;
  CORPUS_DNS_CANCEL cancel;
  int i;

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
  if(st != 0)
    FAILF("sync DnsQueryEx returned %lu", (unsigned long)st);
  if(res.QueryStatus != 0)
    FAILF("sync result QueryStatus=%lu", (unsigned long)res.QueryStatus);
  if(!first_is_loopback(res.pQueryRecords))
    FAILF("sync DnsQueryEx(localhost) did not return A 127.0.0.1");
  pFree(res.pQueryRecords, CORPUS_DNS_FREE_RECORD_LIST);
  res.pQueryRecords = NULL;

  /* Callback set but the name is answered locally: Windows returns 0 with
     no records and never invokes the callback. */
  cb_event = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!cb_event)
    FAILF("CreateEventW failed");
  for(i = 0; i < 20; i++) {
    static const PCWSTR local_names[] = { L"localhost", L"127.0.0.1" };
    memset(&res, 0, sizeof(res));
    res.Version = CORPUS_RESULTS_VERSION1;
    req.QueryName = local_names[i & 1];
    req.pQueryCompletionCallback = (PVOID)(CORPUS_QUERY_COMPLETION)query_done;
    req.pQueryContext = (PVOID)&cb_event;
    cb_calls = 0;
    st = pQueryEx(&req, &res, &cancel);
    if(st != 0 || res.QueryStatus != 0 || res.pQueryRecords != NULL) {
      FAILF("callback-mode local query #%d: st=%lu QueryStatus=%lu records=%p, expected 0/0/NULL",
            i, (unsigned long)st, (unsigned long)res.QueryStatus, (void *)res.pQueryRecords);
    }
    Sleep(20);
    if(InterlockedCompareExchange(&cb_calls, 0, 0) != 0)
      FAILF("callback ran for a locally answered query #%d", i);
  }

  /* A name that needs the resolver: pending, then cancelled. */
  pCancelQuery = (PFN_DnsCancelQuery)(void *)GetProcAddress(dns, "DnsCancelQuery");
  if(!pCancelQuery)
    SKIPF("DnsCancelQuery not exported");
  for(i = 0; i < 5; i++) {
    memset(&res, 0, sizeof(res));
    memset(&cancel, 0, sizeof(cancel));
    res.Version = CORPUS_RESULTS_VERSION1;
    req.QueryName = L"cancel.example.invalid";
    req.QueryOptions = 0;
    req.pQueryCompletionCallback = (PVOID)(CORPUS_QUERY_COMPLETION)query_done;
    cb_calls = 0;
    cb_status = 0xFFFFFFFF;
    ResetEvent(cb_event);
    st = pQueryEx(&req, &res, &cancel);
    if(st != CORPUS_DNS_REQUEST_PENDING)
      FAILF("resolver query returned %lu, expected DNS_REQUEST_PENDING", (unsigned long)st);
    st = pCancelQuery(&cancel);
    if(st != 0)
      FAILF("DnsCancelQuery returned %lu, expected 0", (unsigned long)st);
    if(WaitForSingleObject(cb_event, 10000) != WAIT_OBJECT_0)
      FAILF("callback did not run after DnsCancelQuery");
    Sleep(20);
    if(InterlockedCompareExchange(&cb_calls, 0, 0) != 1 || cb_status != ERROR_CANCELLED)
      FAILF("cancelled query: callback ran %ld times with status %lu, expected once with 1223",
            (long)cb_calls, (unsigned long)cb_status);
    if(cb_records)
      FAILF("cancelled query returned records");
  }

  /* Argument validation. */
  memset(&req, 0, sizeof(req));
  memset(&res, 0, sizeof(res));
  req.Version = 7;
  req.QueryName = L"localhost";
  req.QueryType = DNS_TYPE_A;
  res.Version = CORPUS_RESULTS_VERSION1;
  st = pQueryEx(&req, &res, NULL);
  if(st != ERROR_INVALID_PARAMETER)
    FAILF("request Version 7 returned %lu, expected 87", (unsigned long)st);
  req.Version = CORPUS_REQUEST_VERSION1;
  req.QueryName = NULL;
  st = pQueryEx(&req, &res, NULL);
  if(st != ERROR_INVALID_PARAMETER)
    FAILF("NULL QueryName returned %lu, expected 87", (unsigned long)st);
  req.QueryName = L"localhost";
  req.QueryOptions = DNS_QUERY_NO_WIRE_QUERY;
  res.Version = 9;
  st = pQueryEx(&req, &res, NULL);
  if(st != ERROR_INVALID_PARAMETER)
    FAILF("result Version 9 returned %lu, expected 87", (unsigned long)st);
  res.Version = CORPUS_RESULTS_VERSION1;
  req.QueryName = L"::1";
  st = pQueryEx(&req, &res, NULL);
  if(st != 9560)
    FAILF("A query for ::1 returned %lu, expected 9560", (unsigned long)st);

out:
  if(cb_event)
    CloseHandle(cb_event);
  if(dns)
    FreeLibrary(dns);
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
