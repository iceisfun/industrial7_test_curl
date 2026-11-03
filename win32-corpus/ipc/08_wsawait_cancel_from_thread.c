/*
 * Test: wsawait_cancel_from_thread
 *
 * Purpose: cancel a long blocking WSAWaitForMultipleEvents from another
 *   thread by signaling a WSA event, the way curl_multi_wakeup() interrupts
 *   curl_multi_poll(). Also verifies the manual-reset semantics that curl
 *   depends on: the wakeup stays signaled until explicitly reset.
 *
 * APIs: WSACreateEvent, WSASetEvent, WSAResetEvent, WSACloseEvent,
 *       WSAWaitForMultipleEvents, CreateThread, WaitForSingleObject,
 *       GetExitCodeThread, CloseHandle, GetTickCount64.
 *
 * Success means:
 *   - A 10 s wait is ended by the worker thread's WSASetEvent after about
 *     150 ms: result is WSA_WAIT_EVENT_0, elapsed is between 100 ms and
 *     5000 ms.
 *   - The worker reported WSASetEvent success (thread exit code 0).
 *   - The event remains signaled: an immediate zero-timeout wait still
 *     returns WSA_WAIT_EVENT_0.
 *   - After WSAResetEvent a zero-timeout wait returns WSA_WAIT_TIMEOUT.
 *   - A second cancellation is delivered the same way (repeatable wakeup).
 *
 * Source: curl lib/multi.c:1697 (WSASetEvent in curl_multi_wakeup, called
 *   from another thread), lib/multi.c:1409 (the blocking
 *   WSAWaitForMultipleEvents it interrupts), lib/multi.c:1460 (WSAResetEvent
 *   after the wait so the next poll blocks again).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "wsawait_cancel_from_thread"

#define CHECK(c, ...)                                  \
  do {                                                 \
    if(!(c)) {                                         \
      snprintf(msg, msz, __VA_ARGS__);                 \
      rc = 1;                                          \
      goto done;                                       \
    }                                                  \
  } while(0)

struct signal_arg {
  WSAEVENT ev;
  DWORD delay_ms;
};

static DWORD WINAPI signal_thread(LPVOID p)
{
  struct signal_arg *a = (struct signal_arg *)p;
  Sleep(a->delay_ms);
  return WSASetEvent(a->ev) ? 0 : 1;
}

static int body(char *msg, size_t msz)
{
  WSADATA wd;
  WSAEVENT ev = WSA_INVALID_EVENT;
  struct signal_arg sa;
  HANDLE th = NULL;
  DWORD w, code = 99;
  ULONGLONG t0, t1;
  int e, rc = 0;

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) {
    snprintf(msg, msz, "WSAStartup failed: %d", e);
    return 1;
  }

  ev = WSACreateEvent();
  CHECK(ev != WSA_INVALID_EVENT, "WSACreateEvent failed: %d", WSAGetLastError());

  /* Round 1: long wait ended from another thread. */
  sa.ev = ev;
  sa.delay_ms = 150;
  th = CreateThread(NULL, 0, signal_thread, &sa, 0, NULL);
  CHECK(th != NULL, "CreateThread failed: %lu", (unsigned long)GetLastError());

  t0 = GetTickCount64();
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 10000, FALSE);
  t1 = GetTickCount64();
  CHECK(w == WSA_WAIT_EVENT_0,
        "cancelled wait: expected WSA_WAIT_EVENT_0, got %lu (err=%d)",
        (unsigned long)w, WSAGetLastError());
  CHECK(t1 - t0 >= 100, "wait returned after %llu ms, before the signal",
        (unsigned long long)(t1 - t0));
  CHECK(t1 - t0 < 5000, "wait took %llu ms; cancel was not delivered promptly",
        (unsigned long long)(t1 - t0));

  CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0,
        "worker thread did not finish");
  CHECK(GetExitCodeThread(th, &code) && code == 0,
        "worker WSASetEvent failed (exit code %lu)", (unsigned long)code);
  CloseHandle(th);
  th = NULL;

  /* Manual-reset: the wakeup stays set until WSAResetEvent. */
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0,
        "signal should persist after the wait, got %lu", (unsigned long)w);

  CHECK(WSAResetEvent(ev), "WSAResetEvent failed: %d", WSAGetLastError());
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT,
        "after WSAResetEvent: expected WSA_WAIT_TIMEOUT, got %lu",
        (unsigned long)w);

  /* Round 2: the same event can be used to cancel again. */
  sa.delay_ms = 50;
  code = 99;
  th = CreateThread(NULL, 0, signal_thread, &sa, 0, NULL);
  CHECK(th != NULL, "CreateThread(2) failed: %lu", (unsigned long)GetLastError());
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 5000, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0,
        "second cancel: expected WSA_WAIT_EVENT_0, got %lu", (unsigned long)w);
  CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0,
        "worker thread(2) did not finish");
  CHECK(GetExitCodeThread(th, &code) && code == 0,
        "worker(2) WSASetEvent failed (exit code %lu)", (unsigned long)code);
  CloseHandle(th);
  th = NULL;
  CHECK(WSAResetEvent(ev), "WSAResetEvent(2) failed");

done:
  /* The worker reads the stack-allocated sa and signals ev, so it must finish
     before this frame returns and before ev is closed. Its only work is a
     Sleep of at most 150 ms plus WSASetEvent. */
  if(th) {
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
  }
  if(ev != WSA_INVALID_EVENT)
    WSACloseEvent(ev);
  WSACleanup();
  return rc;
}

int main(void)
{
  char msg[512];
  int rc;

  msg[0] = '\0';
  rc = body(msg, sizeof(msg));
  if(rc == 0)
    printf("PASS %s\n", TEST_NAME);
  else if(rc == 77)
    printf("SKIP %s: %s\n", TEST_NAME, msg);
  else
    printf("FAIL %s: %s\n", TEST_NAME, msg);
  return rc;
}
