/*
 * 03_post_queued_status_timeouts
 *
 * Purpose: exercise PostQueuedCompletionStatus as a user-level wakeup
 *   channel and check the empty-queue and wakeup return conventions of
 *   GetQueuedCompletionStatus.
 * APIs: CreateIoCompletionPort (port only, INVALID_HANDLE_VALUE),
 *   PostQueuedCompletionStatus, GetQueuedCompletionStatus, CloseHandle.
 * Success:
 *   - empty port with timeout 0: returns FALSE, lpOverlapped NULL,
 *     GetLastError() == WAIT_TIMEOUT.
 *   - posted (bytes=42, key=0xABCD, OVERLAPPED*) comes back TRUE with the
 *     same three values.
 *   - posted with NULL OVERLAPPED comes back TRUE with lpOverlapped NULL
 *     (this is the wakeup pattern: no I/O, just a key and a byte count).
 *   - after draining, the port is empty again (WAIT_TIMEOUT).
 * Source: curl's multi wakeup posts through WSASetEvent instead, see
 *   lib/multi.c:1697. The PostQueuedCompletionStatus convention is generic.
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

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_NAME "03_post_queued_status_timeouts"

static void fail_exit(const char *why, DWORD gle)
{
  printf("FAIL %s: %s (gle=%lu)\n", TEST_NAME, why, (unsigned long)gle);
  exit(1);
}

int main(void)
{
  HANDLE port;
  OVERLAPPED my_ov, *got_ov = NULL;
  DWORD bytes = 0;
  ULONG_PTR key = 0;
  BOOL ok;

  memset(&my_ov, 0, sizeof my_ov);

  /* Concurrency value 1: one thread at a time may be released. */
  port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
  if(!port)
    fail_exit("CreateIoCompletionPort", GetLastError());

  /* 1. Empty queue, zero timeout. */
  SetLastError(0);
  ok = GetQueuedCompletionStatus(port, &bytes, &key, &got_ov, 0);
  if(ok)
    fail_exit("empty port returned TRUE", 0);
  if(got_ov != NULL)
    fail_exit("empty port returned non-NULL OVERLAPPED", 0);
  if(GetLastError() != WAIT_TIMEOUT)
    fail_exit("empty port: expected WAIT_TIMEOUT", GetLastError());

  /* 2. Post a packet carrying a byte count, key and OVERLAPPED pointer. */
  if(!PostQueuedCompletionStatus(port, 42, 0xABCD, &my_ov))
    fail_exit("PostQueuedCompletionStatus(ov)", GetLastError());

  bytes = 0;
  key = 0;
  got_ov = NULL;
  ok = GetQueuedCompletionStatus(port, &bytes, &key, &got_ov, 1000);
  if(!ok)
    fail_exit("posted packet not dequeued as success", GetLastError());
  if(bytes != 42)
    fail_exit("posted packet bytes mismatch", bytes);
  if(key != 0xABCD)
    fail_exit("posted packet key mismatch", (DWORD)key);
  if(got_ov != &my_ov)
    fail_exit("posted packet OVERLAPPED mismatch", 0);

  /* 3. Post with NULL OVERLAPPED: a pure wakeup. Still returns TRUE. */
  if(!PostQueuedCompletionStatus(port, 0, 0x5150, NULL))
    fail_exit("PostQueuedCompletionStatus(NULL ov)", GetLastError());

  bytes = 99;
  key = 0;
  got_ov = &my_ov;
  ok = GetQueuedCompletionStatus(port, &bytes, &key, &got_ov, 1000);
  if(!ok)
    fail_exit("wakeup packet should return TRUE", GetLastError());
  if(got_ov != NULL)
    fail_exit("wakeup packet should have NULL OVERLAPPED", 0);
  if(bytes != 0)
    fail_exit("wakeup packet bytes should be 0", bytes);
  if(key != 0x5150)
    fail_exit("wakeup packet key mismatch", (DWORD)key);

  /* 4. Queue drained: back to timeout. */
  SetLastError(0);
  ok = GetQueuedCompletionStatus(port, &bytes, &key, &got_ov, 0);
  if(ok || GetLastError() != WAIT_TIMEOUT)
    fail_exit("drained port should time out", GetLastError());

  /* 5. A packet posted with a zero-length byte count and a key of zero is
   * still delivered: the port must not drop it. */
  if(!PostQueuedCompletionStatus(port, 0, 0, NULL))
    fail_exit("PostQueuedCompletionStatus(zero)", GetLastError());
  got_ov = &my_ov;
  ok = GetQueuedCompletionStatus(port, &bytes, &key, &got_ov, 1000);
  if(!ok || got_ov != NULL || key != 0)
    fail_exit("zero packet not delivered as TRUE/NULL/0", GetLastError());

  CloseHandle(port);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
