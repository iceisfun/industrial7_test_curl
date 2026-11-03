/*
 * Test: wsacreateevent_close
 *
 * Purpose: exercise the manual-reset WSA event lifecycle that curl's multi
 *   handle uses as its wakeup object (multi->wsa_event): create, signal,
 *   observe, reset, close.
 *
 * APIs: WSACreateEvent, WSASetEvent, WSAResetEvent,
 *       WSAWaitForMultipleEvents, WSACloseEvent, WSAStartup, WSACleanup.
 *
 * Success means:
 *   - WSACreateEvent returns a handle that is not WSA_INVALID_EVENT.
 *   - A fresh (unsignaled) event times out with WSA_WAIT_TIMEOUT when waited
 *     on with a zero timeout.
 *   - After WSASetEvent the wait returns WSA_WAIT_EVENT_0.
 *   - The event is manual-reset: it stays signaled across further waits
 *     until WSAResetEvent is called.
 *   - WSAResetEvent makes the next zero-timeout wait time out again.
 *   - Two distinct events do not affect each other.
 *   - WSACloseEvent returns TRUE.
 *
 * Source: curl lib/multi.c:311-312 (WSACreateEvent + WSA_INVALID_EVENT
 *   check), lib/multi.c:1697 (WSASetEvent in curl_multi_wakeup),
 *   lib/multi.c:1460 (WSAResetEvent after the wait), lib/multi.c:3058
 *   (WSACloseEvent on multi cleanup).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "wsacreateevent_close"

#define CHECK(c, ...)                                  \
  do {                                                 \
    if(!(c)) {                                         \
      snprintf(msg, msz, __VA_ARGS__);                 \
      return 1;                                        \
    }                                                  \
  } while(0)

static int body(char *msg, size_t msz)
{
  WSADATA wd;
  WSAEVENT ev, ev2;
  DWORD w;
  int rc;

  rc = WSAStartup(MAKEWORD(2, 2), &wd);
  CHECK(rc == 0, "WSAStartup failed: %d", rc);

  ev = WSACreateEvent();
  CHECK(ev != WSA_INVALID_EVENT, "WSACreateEvent failed, WSAGetLastError=%d",
        WSAGetLastError());

  /* Freshly created event is unsignaled. */
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT,
        "unsignaled event: expected WSA_WAIT_TIMEOUT, got %lu (WSAGetLastError=%d)",
        (unsigned long)w, WSAGetLastError());

  /* Signal it; the wait must now report index 0. */
  CHECK(WSASetEvent(ev), "WSASetEvent failed, WSAGetLastError=%d",
        WSAGetLastError());
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0,
        "signaled event: expected WSA_WAIT_EVENT_0, got %lu", (unsigned long)w);

  /* Manual-reset: the signal persists across waits. */
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0,
        "manual-reset: signal should persist, got %lu", (unsigned long)w);

  /* Reset and verify it times out again. */
  CHECK(WSAResetEvent(ev), "WSAResetEvent failed, WSAGetLastError=%d",
        WSAGetLastError());
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT,
        "after WSAResetEvent: expected WSA_WAIT_TIMEOUT, got %lu",
        (unsigned long)w);

  /* A second event is independent of the first. */
  ev2 = WSACreateEvent();
  CHECK(ev2 != WSA_INVALID_EVENT && ev2 != ev,
        "second WSACreateEvent returned invalid or duplicate handle");
  CHECK(WSASetEvent(ev2), "WSASetEvent(ev2) failed");
  w = WSAWaitForMultipleEvents(1, &ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT,
        "ev must not be signaled by ev2, got %lu", (unsigned long)w);
  w = WSAWaitForMultipleEvents(1, &ev2, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0, "ev2 should be signaled, got %lu",
        (unsigned long)w);

  CHECK(WSACloseEvent(ev), "WSACloseEvent(ev) failed, WSAGetLastError=%d",
        WSAGetLastError());
  CHECK(WSACloseEvent(ev2), "WSACloseEvent(ev2) failed, WSAGetLastError=%d",
        WSAGetLastError());

  WSACleanup();
  return 0;
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
