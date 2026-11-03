/*
 * 12_iocp_worker_pool_stress
 *
 * Purpose: concurrency check of a completion port with several worker
 *   threads, the usual IOCP thread pool shape. Main posts many packets, each
 *   with its own OVERLAPPED, key and byte count. Workers dequeue them and
 *   account for each one. Shutdown uses one sentinel packet per worker.
 *   Verifies that every packet is delivered exactly once, to the correct
 *   key, with the correct OVERLAPPED and byte count.
 * APIs: CreateIoCompletionPort (concurrency value), PostQueuedCompletionStatus,
 *   GetQueuedCompletionStatus (INFINITE), CreateThread, WaitForMultipleObjects,
 *   InterlockedIncrement, InterlockedExchangeAdd, CloseHandle.
 * Success:
 *   - all 2000 packets are dequeued (counter reaches 2000 within 10 s);
 *   - each packet index is seen exactly once (no loss, no duplication);
 *   - no bad packets (wrong key, NULL OVERLAPPED outside shutdown,
 *     OVERLAPPED outside the table);
 *   - the sum of byte counts equals 0+1+...+1999;
 *   - the per-key histogram matches the expected counts (idx % 7);
 *   - all worker threads exit after the sentinels.
 * Source: none. Generic IOCP thread pool contract. curl's threaded resolver
 *   and multi event loop do not use IOCP (see lib/multi.c:1409).
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

#define TEST_NAME "12_iocp_worker_pool_stress"
#define NWORK 4
#define NITEMS 2000
#define NKEYS 7
#define SENTINEL_KEY ((ULONG_PTR)0xFFFF)

static HANDLE g_port;
static OVERLAPPED g_ovs[NITEMS];
static LONG g_seen[NITEMS];
static LONG g_hist[NKEYS];
static LONG g_sum_bytes;
static LONG g_done;
static LONG g_bad;

static void fail_exit(const char *why, DWORD gle)
{
  printf("FAIL %s: %s (gle=%lu)\n", TEST_NAME, why, (unsigned long)gle);
  exit(1);
}

static DWORD WINAPI worker(LPVOID arg)
{
  (void)arg;
  for(;;) {
    DWORD bytes = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *ov = NULL;
    BOOL ok = GetQueuedCompletionStatus(g_port, &bytes, &key, &ov, INFINITE);
    ptrdiff_t idx;

    if(!ok && !ov) {
      /* A failed wait with no packet: must not happen with INFINITE. */
      InterlockedIncrement(&g_bad);
      continue;
    }
    if(!ov) {
      if(key == SENTINEL_KEY && bytes == 0)
        return 0; /* shutdown */
      InterlockedIncrement(&g_bad);
      continue;
    }
    idx = ov - g_ovs;
    if(idx < 0 || idx >= NITEMS || !ok) {
      InterlockedIncrement(&g_bad);
      continue;
    }
    if(bytes != (DWORD)idx || key != (ULONG_PTR)(idx % NKEYS)) {
      InterlockedIncrement(&g_bad);
      continue;
    }
    InterlockedIncrement(&g_seen[idx]);
    InterlockedIncrement(&g_hist[key]);
    InterlockedExchangeAdd(&g_sum_bytes, (LONG)bytes);
    InterlockedIncrement(&g_done);
  }
}

int main(void)
{
  HANDLE threads[NWORK];
  LONG expect_hist[NKEYS];
  LONG expect_sum = 0;
  int i, waited = 0;
  DWORD w;

  memset(g_ovs, 0, sizeof g_ovs);
  memset(g_seen, 0, sizeof g_seen);
  memset(g_hist, 0, sizeof g_hist);

  /* Concurrency 2: at most two workers are released at a time. */
  g_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 2);
  if(!g_port)
    fail_exit("CreateIoCompletionPort", GetLastError());

  for(i = 0; i < NWORK; i++) {
    threads[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if(!threads[i])
      fail_exit("CreateThread(worker)", GetLastError());
  }

  for(i = 0; i < NITEMS; i++) {
    if(!PostQueuedCompletionStatus(g_port, (DWORD)i, (ULONG_PTR)(i % NKEYS),
                                   &g_ovs[i]))
      fail_exit("PostQueuedCompletionStatus", GetLastError());
  }

  /* Wait for the workers to drain the queue. */
  while(InterlockedCompareExchange(&g_done, 0, 0) < NITEMS && waited < 10000) {
    Sleep(1);
    waited++;
  }
  if(InterlockedCompareExchange(&g_done, 0, 0) != NITEMS) {
    printf("FAIL %s: only %ld of %d packets processed\n", TEST_NAME,
           (long)g_done, NITEMS);
    return 1;
  }

  /* One sentinel per worker. */
  for(i = 0; i < NWORK; i++) {
    if(!PostQueuedCompletionStatus(g_port, 0, SENTINEL_KEY, NULL))
      fail_exit("PostQueuedCompletionStatus(sentinel)", GetLastError());
  }
  w = WaitForMultipleObjects(NWORK, threads, TRUE, 10000);
  if(w != WAIT_OBJECT_0)
    fail_exit("workers did not exit after sentinels", w);
  for(i = 0; i < NWORK; i++)
    CloseHandle(threads[i]);
  CloseHandle(g_port);

  /* Verify exactly-once delivery. */
  if(g_bad != 0) {
    printf("FAIL %s: %ld malformed packets\n", TEST_NAME, (long)g_bad);
    return 1;
  }
  for(i = 0; i < NITEMS; i++) {
    if(g_seen[i] != 1) {
      printf("FAIL %s: packet %d delivered %ld times\n", TEST_NAME, i,
             (long)g_seen[i]);
      return 1;
    }
  }
  for(i = 0; i < NITEMS; i++)
    expect_sum += i;
  if(g_sum_bytes != expect_sum) {
    printf("FAIL %s: byte sum %ld expected %ld\n", TEST_NAME,
           (long)g_sum_bytes, (long)expect_sum);
    return 1;
  }

  memset(expect_hist, 0, sizeof expect_hist);
  for(i = 0; i < NITEMS; i++)
    expect_hist[i % NKEYS]++;
  for(i = 0; i < NKEYS; i++) {
    if(g_hist[i] != expect_hist[i]) {
      printf("FAIL %s: key %d count %ld expected %ld\n", TEST_NAME, i,
             (long)g_hist[i], (long)expect_hist[i]);
      return 1;
    }
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
