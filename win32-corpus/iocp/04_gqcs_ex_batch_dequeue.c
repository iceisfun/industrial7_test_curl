/*
 * 04_gqcs_ex_batch_dequeue
 *
 * Purpose: dequeue several completion packets in one call with
 *   GetQueuedCompletionStatusEx, which is how a batched IOCP event loop
 *   drains a port. GetQueuedCompletionStatusEx is a Windows 7+ API and is not
 *   in the mingw import libraries used here, so it is resolved at run time
 *   with LoadLibrary/GetProcAddress and the test SKIPs when it is missing.
 * APIs: LoadLibraryW, GetProcAddress, CreateIoCompletionPort,
 *   PostQueuedCompletionStatus, GetQueuedCompletionStatusEx (dynamic),
 *   OVERLAPPED_ENTRY.
 * Success:
 *   - empty port with timeout 0: returns FALSE and GetLastError() == WAIT_TIMEOUT.
 *     (The count output is not specified on failure and is not checked.)
 *   - five posted packets (keys 1..5, bytes 10*key, distinct OVERLAPPED each)
 *     are all returned across one or more calls; total 5, sum of keys 15,
 *     sum of bytes 150, and every lpOverlapped matches the one posted with
 *     that key.
 *   - the batch call reports count >= 1 on every successful return.
 * Source: none. Generic completion port API. curl's Windows path does not
 *   use the completion port directly (see lib/multi.c:1409 for its wait).
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

#define TEST_NAME "04_gqcs_ex_batch_dequeue"
#define NPOST 5
#define NENTRY 8

typedef BOOL (WINAPI *pfn_gqcs_ex)(HANDLE CompletionPort,
                                   LPOVERLAPPED_ENTRY lpCompletionPortEntries,
                                   ULONG ulCount,
                                   PULONG ulNumEntriesRemoved,
                                   DWORD dwMilliseconds,
                                   BOOL fAlertable);

static void fail_exit(const char *why, DWORD gle)
{
  printf("FAIL %s: %s (gle=%lu)\n", TEST_NAME, why, (unsigned long)gle);
  exit(1);
}

int main(void)
{
  HMODULE k32;
  pfn_gqcs_ex gqcs_ex;
  HANDLE port;
  OVERLAPPED ovs[NPOST];
  OVERLAPPED_ENTRY entries[NENTRY];
  ULONG removed = 0;
  ULONG total = 0;
  ULONG sum_keys = 0;
  ULONG64 sum_bytes = 0;
  int calls = 0;
  ULONG i, j;
  BOOL ok;

  k32 = LoadLibraryW(L"kernel32.dll");
  if(!k32) {
    printf("SKIP %s: LoadLibraryW(kernel32.dll) failed (gle=%lu)\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 77;
  }
  gqcs_ex = (pfn_gqcs_ex)(void *)GetProcAddress(k32, "GetQueuedCompletionStatusEx");
  if(!gqcs_ex) {
    printf("SKIP %s: GetQueuedCompletionStatusEx not exported\n", TEST_NAME);
    return 77;
  }

  memset(ovs, 0, sizeof ovs);
  port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
  if(!port)
    fail_exit("CreateIoCompletionPort", GetLastError());

  /* Empty port: timeout 0 must fail with WAIT_TIMEOUT and report 0 entries. */
  removed = 77;
  SetLastError(0);
  ok = gqcs_ex(port, entries, NENTRY, &removed, 0, FALSE);
  if(ok)
    fail_exit("empty port: GetQueuedCompletionStatusEx returned TRUE", 0);
  if(GetLastError() != WAIT_TIMEOUT)
    fail_exit("empty port: expected WAIT_TIMEOUT", GetLastError());
  /* ulNumEntriesRemoved is not specified on failure, so it is not checked. */

  /* Post five packets, key k, bytes 10*k, OVERLAPPED = &ovs[k-1]. */
  for(i = 1; i <= NPOST; i++) {
    if(!PostQueuedCompletionStatus(port, (DWORD)(10 * i), i, &ovs[i - 1]))
      fail_exit("PostQueuedCompletionStatus", GetLastError());
  }

  /* Drain. Packets may arrive in one batch or several; we keep calling until
   * all five are seen, with a bounded number of calls. */
  while(total < NPOST && calls < 5) {
    calls++;
    removed = 0;
    ok = gqcs_ex(port, entries, NENTRY, &removed, 2000, FALSE);
    if(!ok)
      fail_exit("GetQueuedCompletionStatusEx batch", GetLastError());
    if(removed < 1)
      fail_exit("successful batch returned zero entries", removed);

    for(j = 0; j < removed; j++) {
      ULONG_PTR key = entries[j].lpCompletionKey;
      OVERLAPPED *ov = entries[j].lpOverlapped;
      ULONG idx;

      if(key < 1 || key > NPOST) {
        printf("FAIL %s: unexpected completion key %lu\n", TEST_NAME,
               (unsigned long)key);
        return 1;
      }
      idx = (ULONG)(key - 1);
      if(ov != &ovs[idx]) {
        printf("FAIL %s: key %lu came with wrong OVERLAPPED\n", TEST_NAME,
               (unsigned long)key);
        return 1;
      }
      if(entries[j].dwNumberOfBytesTransferred != 10 * key) {
        printf("FAIL %s: key %lu bytes=%lu expected %lu\n", TEST_NAME,
               (unsigned long)key,
               (unsigned long)entries[j].dwNumberOfBytesTransferred,
               (unsigned long)(10 * key));
        return 1;
      }
      sum_keys += (ULONG)key;
      sum_bytes += entries[j].dwNumberOfBytesTransferred;
    }
    total += removed;
  }

  if(total != NPOST) {
    printf("FAIL %s: dequeued %lu packets, expected %d\n", TEST_NAME,
           (unsigned long)total, NPOST);
    return 1;
  }
  if(sum_keys != 15) {
    printf("FAIL %s: sum of keys %lu expected 15\n", TEST_NAME,
           (unsigned long)sum_keys);
    return 1;
  }
  if(sum_bytes != 150) {
    printf("FAIL %s: sum of bytes %llu expected 150\n", TEST_NAME,
           (unsigned long long)sum_bytes);
    return 1;
  }

  /* Port is now empty again. */
  SetLastError(0);
  ok = gqcs_ex(port, entries, NENTRY, &removed, 0, FALSE);
  if(ok || GetLastError() != WAIT_TIMEOUT)
    fail_exit("drained port should time out", GetLastError());

  CloseHandle(port);
  FreeLibrary(k32);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
