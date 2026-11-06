/*
 * Test 07_getaddrinfoexw_sync_async
 *
 * Purpose: GetAddrInfoExW (the Windows 8+ extended resolver that curl's
 * newer resolver paths can use) in both synchronous mode and overlapped
 * (asynchronous) mode. GetAddrInfoExW, FreeAddrInfoExW and
 * GetAddrInfoExOverlappedResult are resolved with LoadLibrary/GetProcAddress
 * from ws2_32.dll, so a stack without them FAILs.
 *
 * APIs: WSAStartup, LoadLibraryW, GetProcAddress, GetAddrInfoExW,
 *       GetAddrInfoExOverlappedResult, GetAddrInfoExCancel,
 *       FreeAddrInfoExW, CreateEventW, WaitForSingleObject, WSACleanup.
 *
 * Success (probed on Windows 10 22H2, 20 repetitions each):
 *   synchronous GetAddrInfoExW(L"127.0.0.1", L"80", NS_DNS) returns 0 with one
 *   AF_INET entry on sin_port 80. The overlapped form with a numeric host
 *   completes synchronously: it returns 0, fills the result list, does NOT
 *   signal the event, and GetAddrInfoExOverlappedResult then returns
 *   WSAEINPROGRESS (10036). The overlapped form with L"localhost" returns
 *   WSA_IO_PENDING (997), signals the event, GetAddrInfoExOverlappedResult
 *   returns 0 and the list holds ::1 then 127.0.0.1. A lookup of a
 *   nonexistent ".invalid" name returns WSA_IO_PENDING and completes with
 *   WSAHOST_NOT_FOUND (11001) and no list. A missing export is a FAIL.
 *
 * Source: no direct curl call site (curl uses the ANSI getaddrinfo() path,
 *         lib/vdns/asyn-thrdd.c:415). This covers the extended resolver
 *         surface requested for the corpus.
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
#include <windows.h>
#include <stdio.h>
#include <string.h>

#ifndef NS_DNS
#define NS_DNS 12
#endif
#ifndef NS_ALL
#define NS_ALL 0
#endif

#define T "07_getaddrinfoexw_sync_async"

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [WSA=%d GLE=%lu]\n", WSAGetLastError(), (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

#define SKIPF(msg) do { \
    printf("SKIP %s: %s\n", T, msg); status = 77; goto out; } while(0)

typedef int (WSAAPI *PFN_GetAddrInfoExW)(PCWSTR, PCWSTR, DWORD, LPGUID,
                                         const ADDRINFOEXW *, PADDRINFOEXW *,
                                         PTIMEVAL, LPOVERLAPPED,
                                         LPLOOKUPSERVICE_COMPLETION_ROUTINE,
                                         LPHANDLE);
typedef void (WSAAPI *PFN_FreeAddrInfoExW)(PADDRINFOEXW);
typedef int (WSAAPI *PFN_GetAddrInfoExOverlappedResult)(LPOVERLAPPED);
typedef int (WSAAPI *PFN_GetAddrInfoExCancel)(LPHANDLE);

static volatile LONG cb_calls = 0;
static volatile DWORD cb_error = 0xFFFFFFFF;

static void CALLBACK completion(DWORD err, DWORD bytes, LPWSAOVERLAPPED o)
{
  (void)bytes;
  (void)o;
  cb_error = err;
  InterlockedIncrement(&cb_calls);
}

static int check_entry(const ADDRINFOEXW *ai, const char *what)
{
  const struct sockaddr_in *s4;
  if(!ai)
    return 0;
  if(ai->ai_family != AF_INET)
    return 0;
  if(ai->ai_addrlen < (size_t)sizeof(struct sockaddr_in))
    return 0;
  s4 = (const struct sockaddr_in *)ai->ai_addr;
  (void)what;
  return ntohl(s4->sin_addr.S_un.S_addr) == 0x7F000001UL &&
         s4->sin_port == htons(80);
}

int main(void)
{
  WSADATA wsa;
  HMODULE ws2 = NULL;
  PFN_GetAddrInfoExW pGetAddrInfoExW;
  PFN_FreeAddrInfoExW pFreeAddrInfoExW;
  PFN_GetAddrInfoExOverlappedResult pResult;
  PFN_GetAddrInfoExCancel pCancel;
  ADDRINFOEXW hints, *res = NULL, *ai;
  HANDLE ev = NULL;
  OVERLAPPED ov;
  HANDLE cancel = NULL;
  int rc, n = 0, wsa_ok = 0, i;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

  ws2 = LoadLibraryW(L"ws2_32.dll");
  if(!ws2)
    FAILF("ws2_32.dll could not be loaded");
  pGetAddrInfoExW = (PFN_GetAddrInfoExW)(void *)GetProcAddress(ws2, "GetAddrInfoExW");
  pFreeAddrInfoExW = (PFN_FreeAddrInfoExW)(void *)GetProcAddress(ws2, "FreeAddrInfoExW");
  pResult = (PFN_GetAddrInfoExOverlappedResult)(void *)GetProcAddress(ws2,
              "GetAddrInfoExOverlappedResult");
  pCancel = (PFN_GetAddrInfoExCancel)(void *)GetProcAddress(ws2, "GetAddrInfoExCancel");
  if(!pGetAddrInfoExW || !pFreeAddrInfoExW)
    FAILF("GetAddrInfoExW/FreeAddrInfoExW not exported (pre-Win8 stack)");
  if(!pResult)
    FAILF("GetAddrInfoExOverlappedResult not exported");

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

  /* Synchronous: no overlapped, no timeout. */
  rc = pGetAddrInfoExW(L"127.0.0.1", L"80", NS_DNS, NULL, &hints, &res,
                       NULL, NULL, NULL, NULL);
  if(rc != 0)
    FAILF("sync GetAddrInfoExW returned %d", rc);
  for(ai = res; ai; ai = ai->ai_next)
    n++;
  if(n != 1)
    FAILF("sync GetAddrInfoExW returned %d entries, expected 1", n);
  if(!check_entry(res, "sync"))
    FAILF("sync entry is not AF_INET 127.0.0.1:80");
  pFreeAddrInfoExW(res);
  res = NULL;

  /* Overlapped, numeric host: Windows completes it synchronously. */
  ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!ev)
    FAILF("CreateEventW failed");
  memset(&ov, 0, sizeof(ov));
  ov.hEvent = ev;
  rc = pGetAddrInfoExW(L"127.0.0.1", L"80", NS_DNS, NULL, &hints, &res,
                       NULL, &ov, NULL, &cancel);
  if(rc != 0)
    FAILF("overlapped numeric GetAddrInfoExW returned %d, expected 0", rc);
  if(!res || !check_entry(res, "overlapped"))
    FAILF("overlapped numeric entry is not AF_INET 127.0.0.1:80");
  if(WaitForSingleObject(ev, 100) != WAIT_TIMEOUT)
    FAILF("event was signalled for a synchronously completed request");
  rc = pResult(&ov);
  if(rc != WSAEINPROGRESS)
    FAILF("GetAddrInfoExOverlappedResult on a synchronous completion "
          "returned %d, expected 10036", rc);
  pFreeAddrInfoExW(res);
  res = NULL;

  /* Overlapped, localhost: pending, then ::1 and 127.0.0.1. */
  for(i = 0; i < 20; i++) {
    ADDRINFOEXW lh;
    memset(&lh, 0, sizeof(lh));
    lh.ai_family = AF_UNSPEC;
    lh.ai_socktype = SOCK_STREAM;
    ResetEvent(ev);
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = ev;
    cancel = NULL;
    rc = pGetAddrInfoExW(L"localhost", L"80", NS_DNS, NULL, &lh, &res,
                         NULL, &ov, NULL, &cancel);
    if(rc != WSA_IO_PENDING)
      FAILF("overlapped localhost #%d returned %d, expected WSA_IO_PENDING", i, rc);
    if(WaitForSingleObject(ev, 10000) != WAIT_OBJECT_0)
      FAILF("overlapped localhost #%d did not signal within 10 seconds", i);
    rc = pResult(&ov);
    if(rc != 0)
      FAILF("GetAddrInfoExOverlappedResult #%d returned %d", i, rc);
    n = 0;
    for(ai = res; ai; ai = ai->ai_next)
      n++;
    if(n != 2 || res->ai_family != AF_INET6 || res->ai_next->ai_family != AF_INET)
      FAILF("localhost #%d: %d entries, expected ::1 then 127.0.0.1", i, n);
    pFreeAddrInfoExW(res);
    res = NULL;
  }

  /* Overlapped, nonexistent name: pending, completes with 11001 and no list.
     11002 (WSATRY_AGAIN) would mean the resolver is unreachable here. */
  ResetEvent(ev);
  memset(&ov, 0, sizeof(ov));
  ov.hEvent = ev;
  cancel = NULL;
  {
    ADDRINFOEXW nh;
    memset(&nh, 0, sizeof(nh));
    nh.ai_family = AF_INET;
    nh.ai_socktype = SOCK_STREAM;
    rc = pGetAddrInfoExW(L"corpus-nx.invalid", L"80", NS_DNS, NULL, &nh, &res,
                         NULL, &ov, NULL, &cancel);
  }
  if(rc != WSA_IO_PENDING)
    FAILF("overlapped .invalid lookup returned %d, expected WSA_IO_PENDING", rc);
  if(WaitForSingleObject(ev, 30000) != WAIT_OBJECT_0)
    FAILF("overlapped .invalid lookup did not signal within 30 seconds");
  rc = pResult(&ov);
  if(rc == WSATRY_AGAIN)
    SKIPF("resolver unreachable (WSATRY_AGAIN) in this environment");
  if(rc != WSAHOST_NOT_FOUND)
    FAILF("overlapped .invalid completion %d, expected 11001", rc);
  if(res)
    FAILF("failed lookup left a result list");

  /* Completion-routine mode: hEvent must be NULL, the routine runs once. */
  {
    ADDRINFOEXW lh;
    memset(&lh, 0, sizeof(lh));
    lh.ai_family = AF_INET;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = ev;
    cancel = NULL;
    rc = pGetAddrInfoExW(L"localhost", L"80", NS_DNS, NULL, &lh, &res,
                         NULL, &ov, completion, &cancel);
    if(rc != WSAEINVAL)
      FAILF("routine together with hEvent returned %d, expected 10022", rc);
    memset(&ov, 0, sizeof(ov));
    cb_calls = 0;
    rc = pGetAddrInfoExW(L"localhost", L"80", NS_DNS, NULL, &lh, &res,
                         NULL, &ov, completion, &cancel);
    if(rc != WSA_IO_PENDING)
      FAILF("routine mode returned %d, expected WSA_IO_PENDING", rc);
    for(i = 0; i < 1000 && cb_calls == 0; i++)
      SleepEx(10, TRUE);
    if(cb_calls != 1 || cb_error != 0)
      FAILF("completion routine ran %ld times with error %lu", (long)cb_calls,
            (unsigned long)cb_error);
    if(!res || res->ai_family != AF_INET)
      FAILF("routine mode produced no AF_INET result");
    pFreeAddrInfoExW(res);
    res = NULL;
  }

  /* A non-NULL timeout is rejected with WSAEINVAL. */
  {
    TIMEVAL tv = {5, 0};
    rc = pGetAddrInfoExW(L"127.0.0.1", L"80", NS_DNS, NULL, &hints, &res,
                         &tv, NULL, NULL, NULL);
    if(rc != WSAEINVAL)
      FAILF("lpTimeout set: returned %d, expected 10022", rc);
  }

  /* NS_ALL is accepted for a numeric host. */
  rc = pGetAddrInfoExW(L"127.0.0.1", L"80", NS_ALL, NULL, &hints, &res,
                       NULL, NULL, NULL, NULL);
  if(rc != 0 || !check_entry(res, "NS_ALL"))
    FAILF("NS_ALL lookup returned %d", rc);
  pFreeAddrInfoExW(res);
  res = NULL;

  /* Cancellation (GetAddrInfoExCancel) is covered by test 19. */
  (void)pCancel;

out:
  if(res && pFreeAddrInfoExW)
    pFreeAddrInfoExW(res);
  if(ev)
    CloseHandle(ev);
  if(ws2)
    FreeLibrary(ws2);
  if(wsa_ok)
    WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
