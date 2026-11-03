/*
 * Test 07_getaddrinfoexw_sync_async
 *
 * Purpose: GetAddrInfoExW (the Windows 8+ extended resolver that curl's
 * newer resolver paths can use) in both synchronous mode and overlapped
 * (asynchronous) mode. GetAddrInfoExW, FreeAddrInfoExW and
 * GetAddrInfoExOverlappedResult are resolved with LoadLibrary/GetProcAddress
 * from ws2_32.dll, so a stack without them SKIPs.
 *
 * APIs: WSAStartup, LoadLibraryW, GetProcAddress, GetAddrInfoExW,
 *       GetAddrInfoExOverlappedResult, GetAddrInfoExCancel,
 *       FreeAddrInfoExW, CreateEventW, WaitForSingleObject, WSACleanup.
 *
 * Success: synchronous GetAddrInfoExW(L"127.0.0.1", L"80", NS_DNS) returns 0
 * with one AF_INET entry on sin_port 80. Overlapped mode with a manual reset
 * event either completes immediately with 0, or returns WSA_IO_PENDING, then
 * the event signals within 10 seconds and GetAddrInfoExOverlappedResult
 * returns 0 and fills the result list with the same 127.0.0.1:80 entry.
 * A missing export is a SKIP.
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
  int rc, n = 0, wsa_ok = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

  ws2 = LoadLibraryW(L"ws2_32.dll");
  if(!ws2)
    SKIPF("ws2_32.dll could not be loaded");
  pGetAddrInfoExW = (PFN_GetAddrInfoExW)(void *)GetProcAddress(ws2, "GetAddrInfoExW");
  pFreeAddrInfoExW = (PFN_FreeAddrInfoExW)(void *)GetProcAddress(ws2, "FreeAddrInfoExW");
  pResult = (PFN_GetAddrInfoExOverlappedResult)(void *)GetProcAddress(ws2,
              "GetAddrInfoExOverlappedResult");
  pCancel = (PFN_GetAddrInfoExCancel)(void *)GetProcAddress(ws2, "GetAddrInfoExCancel");
  if(!pGetAddrInfoExW || !pFreeAddrInfoExW)
    SKIPF("GetAddrInfoExW/FreeAddrInfoExW not exported (pre-Win8 stack)");
  if(!pResult)
    SKIPF("GetAddrInfoExOverlappedResult not exported");

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

  /* Overlapped: must complete with the same answer. */
  ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!ev)
    FAILF("CreateEventW failed");
  memset(&ov, 0, sizeof(ov));
  ov.hEvent = ev;

  rc = pGetAddrInfoExW(L"127.0.0.1", L"80", NS_DNS, NULL, &hints, &res,
                       NULL, &ov, NULL, &cancel);
  if(rc == WSA_IO_PENDING) {
    if(WaitForSingleObject(ev, 10000) != WAIT_OBJECT_0)
      FAILF("overlapped GetAddrInfoExW did not signal within 10 seconds");
  }
  else if(rc != 0)
    FAILF("overlapped GetAddrInfoExW returned %d", rc);

  rc = pResult(&ov);
  if(rc != 0)
    FAILF("GetAddrInfoExOverlappedResult returned %d", rc);
  if(!res)
    FAILF("overlapped completion produced no result list");
  if(!check_entry(res, "overlapped"))
    FAILF("overlapped entry is not AF_INET 127.0.0.1:80");

  /* Exercises GetAddrInfoExCancel on a request that already completed.
     Its return code is intentionally not asserted; the result list above
     is the outcome that is checked. */
  if(pCancel && cancel) {
    (void)pCancel(&cancel);
  }

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
