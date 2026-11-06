/*
 * Test 19_getaddrinfoex_cancel
 *
 * Purpose: cancelling a pending GetAddrInfoExW() lookup, the only way on
 * Windows to abort an in-flight name resolution (curl's threaded resolver
 * built on getaddrinfo() cannot cancel; it detaches or waits for the worker,
 * see lib/vdns/asyn-thrdd.c). Pins the return values of
 * GetAddrInfoExCancel() and the completion status the cancelled request
 * reports, in event mode and in completion-routine mode.
 *
 * APIs: LoadLibraryW(ws2_32.dll), GetProcAddress, GetAddrInfoExW,
 *       GetAddrInfoExCancel, GetAddrInfoExOverlappedResult, FreeAddrInfoExW,
 *       CreateEventW, WaitForSingleObject, WSAGetLastError.
 *
 * Success (probed on Windows 10 22H2, 20 consecutive repetitions each):
 *   an overlapped lookup of "localhost" and of "cancel-test.example.invalid"
 *   returns WSA_IO_PENDING (997); GetAddrInfoExCancel on its handle returns
 *   0 immediately; the event is already signalled, GetAddrInfoExOverlappedResult
 *   returns WSA_E_CANCELLED (10111) and the result list pointer stays NULL.
 *   In completion-routine mode (hEvent NULL) the routine runs exactly once
 *   with error 10111. GetAddrInfoExCancel on a NULL handle or a bogus handle
 *   value (0x1234) returns 6 (WSA_INVALID_HANDLE). GetAddrInfoExW with a
 *   routine while hEvent is non-NULL returns 10022 (WSAEINVAL).
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

#define T "19_getaddrinfoex_cancel"

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); printf("\n"); \
    return 1; } while(0)

typedef int (WSAAPI *PFN_GetAddrInfoExW)(PCWSTR, PCWSTR, DWORD, LPGUID,
                                         const ADDRINFOEXW *, PADDRINFOEXW *,
                                         PTIMEVAL, LPOVERLAPPED,
                                         LPLOOKUPSERVICE_COMPLETION_ROUTINE,
                                         LPHANDLE);
typedef void (WSAAPI *PFN_FreeAddrInfoExW)(PADDRINFOEXW);
typedef int (WSAAPI *PFN_Result)(LPOVERLAPPED);
typedef int (WSAAPI *PFN_Cancel)(LPHANDLE);

static volatile LONG cb_calls;
static volatile DWORD cb_error = 0xFFFFFFFF;
static HANDLE cb_event;

static void CALLBACK completion(DWORD err, DWORD bytes, LPWSAOVERLAPPED o)
{
  (void)bytes;
  (void)o;
  cb_error = err;
  InterlockedIncrement(&cb_calls);
  SetEvent(cb_event);
}

int main(void)
{
  WSADATA wsa;
  HMODULE ws2;
  PFN_GetAddrInfoExW pGet;
  PFN_FreeAddrInfoExW pFree;
  PFN_Result pResult;
  PFN_Cancel pCancel;
  static const wchar_t *const names[] = { L"localhost", L"cancel-test.example.invalid", NULL };
  HANDLE ev;
  int i, k;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  ws2 = LoadLibraryW(L"ws2_32.dll");
  pGet = ws2 ? (PFN_GetAddrInfoExW)(void *)GetProcAddress(ws2, "GetAddrInfoExW") : NULL;
  pFree = ws2 ? (PFN_FreeAddrInfoExW)(void *)GetProcAddress(ws2, "FreeAddrInfoExW") : NULL;
  pResult = ws2 ? (PFN_Result)(void *)GetProcAddress(ws2, "GetAddrInfoExOverlappedResult") : NULL;
  pCancel = ws2 ? (PFN_Cancel)(void *)GetProcAddress(ws2, "GetAddrInfoExCancel") : NULL;
  if(!pGet || !pFree || !pResult || !pCancel) {
    printf("SKIP %s: GetAddrInfoEx family not exported\n", T);
    return 77;
  }
  ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  cb_event = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!ev || !cb_event)
    FAILF("CreateEventW failed");

  for(k = 0; names[k]; k++) {
    /* event mode */
    for(i = 0; i < 20; i++) {
      ADDRINFOEXW h;
      PADDRINFOEXW res = NULL;
      OVERLAPPED ov;
      HANDLE ch = NULL;
      int rc, cr, orr;
      memset(&h, 0, sizeof(h));
      h.ai_family = AF_UNSPEC;
      memset(&ov, 0, sizeof(ov));
      ResetEvent(ev);
      ov.hEvent = ev;
      rc = pGet(names[k], L"80", NS_DNS, NULL, &h, &res, NULL, &ov, NULL, &ch);
      if(rc != WSA_IO_PENDING)
        FAILF("%ls #%d: overlapped lookup returned %d, expected 997", names[k], i, rc);
      cr = pCancel(&ch);
      if(cr != 0)
        FAILF("%ls #%d: GetAddrInfoExCancel returned %d, expected 0", names[k], i, cr);
      if(WaitForSingleObject(ev, 10000) != WAIT_OBJECT_0)
        FAILF("%ls #%d: event not signalled after cancel", names[k], i);
      orr = pResult(&ov);
      if(orr != WSA_E_CANCELLED)
        FAILF("%ls #%d: cancelled request completed with %d, expected 10111", names[k], i, orr);
      if(res)
        FAILF("%ls #%d: cancelled request returned a result list", names[k], i);
    }
    /* completion-routine mode */
    for(i = 0; i < 20; i++) {
      ADDRINFOEXW h;
      PADDRINFOEXW res = NULL;
      OVERLAPPED ov;
      HANDLE ch = NULL;
      int rc, cr;
      memset(&h, 0, sizeof(h));
      h.ai_family = AF_UNSPEC;
      memset(&ov, 0, sizeof(ov));
      ResetEvent(cb_event);
      cb_calls = 0;
      cb_error = 0xFFFFFFFF;
      rc = pGet(names[k], L"80", NS_DNS, NULL, &h, &res, NULL, &ov, completion, &ch);
      if(rc != WSA_IO_PENDING)
        FAILF("%ls #%d: routine-mode lookup returned %d, expected 997", names[k], i, rc);
      cr = pCancel(&ch);
      if(cr != 0)
        FAILF("%ls #%d: routine-mode cancel returned %d", names[k], i, cr);
      if(WaitForSingleObject(cb_event, 10000) != WAIT_OBJECT_0)
        FAILF("%ls #%d: completion routine did not run after cancel", names[k], i);
      Sleep(20);
      if(cb_calls != 1 || cb_error != (DWORD)WSA_E_CANCELLED)
        FAILF("%ls #%d: routine ran %ld times with error %lu, expected once with 10111",
              names[k], i, (long)cb_calls, (unsigned long)cb_error);
      if(res)
        FAILF("%ls #%d: cancelled routine-mode request returned a result list", names[k], i);
    }
  }

  /* invalid handles */
  {
    HANDLE nul = NULL, bogus = (HANDLE)(ULONG_PTR)0x1234;
    if(pCancel(&nul) != WSA_INVALID_HANDLE)
      FAILF("cancel of a NULL handle did not return 6");
    if(pCancel(&bogus) != WSA_INVALID_HANDLE)
      FAILF("cancel of a bogus handle did not return 6");
  }

  /* a routine together with hEvent is rejected */
  {
    ADDRINFOEXW h;
    PADDRINFOEXW res = NULL;
    OVERLAPPED ov;
    HANDLE ch = NULL;
    int rc;
    memset(&h, 0, sizeof(h));
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = ev;
    rc = pGet(L"localhost", L"80", NS_DNS, NULL, &h, &res, NULL, &ov, completion, &ch);
    if(rc != WSAEINVAL)
      FAILF("routine + hEvent returned %d, expected 10022", rc);
  }

  CloseHandle(ev);
  CloseHandle(cb_event);
  FreeLibrary(ws2);
  WSACleanup();
  printf("PASS %s\n", T);
  return 0;
}
