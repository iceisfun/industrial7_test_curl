/*
 * Test: wsawait_max_64_events
 *
 * Purpose: check the WSA_MAXIMUM_WAIT_EVENTS boundary (64) of
 *   WSAWaitForMultipleEvents. An embedder that multiplexes many sockets onto
 *   one curl_multi wait set must keep the number of event handles at 64 or
 *   fewer per wait; this test confirms the exact limit and the index mapping
 *   at the last slot, and the failure for 65.
 *
 * APIs: WSACreateEvent, WSASetEvent, WSAResetEvent, WSACloseEvent,
 *       WSAWaitForMultipleEvents, WSAGetLastError.
 *
 * Success means:
 *   - WSA_MAXIMUM_WAIT_EVENTS == 64.
 *   - 64 unsignaled events: zero-timeout wait -> WSA_WAIT_TIMEOUT.
 *   - Only event index 63 signaled -> WSA_WAIT_EVENT_0 + 63.
 *   - All 64 signaled -> fWaitAll=FALSE returns WSA_WAIT_EVENT_0 and
 *     fWaitAll=TRUE returns WSA_WAIT_EVENT_0.
 *   - Only event index 17 signaled -> WSA_WAIT_EVENT_0 + 17.
 *   - 65 handles -> WSA_WAIT_FAILED with WSAGetLastError() ==
 *     WSA_INVALID_PARAMETER (87).
 *
 * Source: curl lib/multi.c:1409 (one WSA event per multi handle), and
 *   curl's multi wait only ever passes a single event (curl_multi_wait
 *   therefore never reaches the 64 limit itself, so this test documents the
 *   limit an embedder that adds events to the same wait would hit).
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "wsawait_max_64_events"

#define NEV 65

#define CHECK(c, ...)                                  \
  do {                                                 \
    if(!(c)) {                                         \
      snprintf(msg, msz, __VA_ARGS__);                 \
      rc = 1;                                          \
      goto done;                                       \
    }                                                  \
  } while(0)

static int body(char *msg, size_t msz)
{
  WSADATA wd;
  WSAEVENT ev[NEV];
  DWORD w;
  int i, created = 0, e, rc = 0;

  e = WSAStartup(MAKEWORD(2, 2), &wd);
  if(e) {
    snprintf(msg, msz, "WSAStartup failed: %d", e);
    return 1;
  }

  CHECK(WSA_MAXIMUM_WAIT_EVENTS == 64,
        "WSA_MAXIMUM_WAIT_EVENTS is %d, expected 64", WSA_MAXIMUM_WAIT_EVENTS);

  for(i = 0; i < NEV; i++) {
    ev[i] = WSACreateEvent();
    CHECK(ev[i] != WSA_INVALID_EVENT, "WSACreateEvent #%d failed: %d", i,
          WSAGetLastError());
    created++;
  }

  /* 64 handles: nothing signaled. */
  w = WSAWaitForMultipleEvents(64, ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_TIMEOUT, "64 unsignaled: expected WSA_WAIT_TIMEOUT, got %lu",
        (unsigned long)w);

  /* Only the last slot (index 63) signaled. */
  CHECK(WSASetEvent(ev[63]), "WSASetEvent(63) failed: %d", WSAGetLastError());
  w = WSAWaitForMultipleEvents(64, ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0 + 63,
        "last slot: expected WSA_WAIT_EVENT_0+63, got %lu", (unsigned long)w);
  CHECK(WSAResetEvent(ev[63]), "WSAResetEvent(63) failed");

  /* Every slot signaled: lowest index wins; fWaitAll also succeeds. */
  for(i = 0; i < 64; i++)
    CHECK(WSASetEvent(ev[i]), "WSASetEvent(%d) failed", i);
  w = WSAWaitForMultipleEvents(64, ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0, "all set: expected WSA_WAIT_EVENT_0, got %lu",
        (unsigned long)w);
  w = WSAWaitForMultipleEvents(64, ev, TRUE, 0, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0, "all set fWaitAll: expected WSA_WAIT_EVENT_0, got %lu",
        (unsigned long)w);

  /* Reset everything, then only slot 17 signaled. */
  for(i = 0; i < 64; i++)
    CHECK(WSAResetEvent(ev[i]), "WSAResetEvent(%d) failed", i);
  CHECK(WSASetEvent(ev[17]), "WSASetEvent(17) failed");
  w = WSAWaitForMultipleEvents(64, ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_EVENT_0 + 17,
        "slot 17: expected WSA_WAIT_EVENT_0+17, got %lu", (unsigned long)w);
  CHECK(WSAResetEvent(ev[17]), "WSAResetEvent(17) failed");

  /* 65 handles exceeds the limit. */
  w = WSAWaitForMultipleEvents(65, ev, FALSE, 0, FALSE);
  CHECK(w == WSA_WAIT_FAILED, "65 handles: expected WSA_WAIT_FAILED, got %lu",
        (unsigned long)w);
  CHECK(WSAGetLastError() == WSA_INVALID_PARAMETER,
        "65 handles: WSAGetLastError=%d, expected WSA_INVALID_PARAMETER (%d)",
        WSAGetLastError(), (int)WSA_INVALID_PARAMETER);

done:
  for(i = 0; i < created; i++)
    WSACloseEvent(ev[i]);
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
