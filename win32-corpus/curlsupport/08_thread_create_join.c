/*
 * Test: 08_thread_create_join
 * Purpose: Mirror curl's Windows thread wrappers: create a worker, join it,
 *   and close the handle, including a join that must time out while the
 *   worker is still blocked.
 * APIs: CreateThread, WaitForSingleObjectEx, WaitForSingleObject,
 *   GetExitCodeThread, CreateEventW, SetEvent, CloseHandle, InterlockedIncrement
 * Source: lib/curl_threads.c:32-62. Curl_thread_create() calls
 *   CreateThread(NULL, 0, func, arg, 0, NULL) and maps a NULL handle to
 *   errno (EACCES or EINVAL); Curl_thread_join() waits with
 *   WaitForSingleObjectEx(*hnd, INFINITE, FALSE) == WAIT_OBJECT_0 and then
 *   Curl_thread_destroy() closes the handle.
 * Success: 4 threads each increment a shared counter 1000 times, all joins
 *   return WAIT_OBJECT_0, each exit code equals its thread id + 100, the
 *   counter equals 4000, and a 0 ms wait on a blocked thread returns
 *   WAIT_TIMEOUT before the event is set.
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
#include <stdint.h>

#define TEST_NAME "08_thread_create_join"
#define NTHREADS 4
#define ITERS 1000

static LONG g_counter = 0;
static HANDLE g_gate = NULL;

static DWORD WINAPI counting_worker(LPVOID arg)
{
  int id = (int)(intptr_t)arg;
  int i;
  for(i = 0; i < ITERS; i++)
    InterlockedIncrement(&g_counter);
  return (DWORD)(id + 100);
}

static DWORD WINAPI blocked_worker(LPVOID arg)
{
  (void)arg;
  /* Alertable=FALSE, same flags as Curl_thread_join() waits */
  WaitForSingleObjectEx(g_gate, INFINITE, FALSE);
  return 7;
}

int main(void)
{
  HANDLE th[NTHREADS];
  HANDLE blocked;
  int i;
  DWORD code = 0;
  DWORD wr;

  for(i = 0; i < NTHREADS; i++) {
    th[i] = CreateThread(NULL, 0, counting_worker,
                         (LPVOID)(intptr_t)i, 0, NULL);
    if(!th[i]) {
      printf("FAIL %s: CreateThread #%d failed, GetLastError=%lu\n",
             TEST_NAME, i, (unsigned long)GetLastError());
      return 1;
    }
  }

  for(i = 0; i < NTHREADS; i++) {
    /* Curl_thread_join: WaitForSingleObjectEx(h, INFINITE, FALSE) */
    wr = WaitForSingleObjectEx(th[i], INFINITE, FALSE);
    if(wr != WAIT_OBJECT_0) {
      printf("FAIL %s: join #%d returned %lu, GetLastError=%lu\n",
             TEST_NAME, i, (unsigned long)wr, (unsigned long)GetLastError());
      return 1;
    }
    if(!GetExitCodeThread(th[i], &code) || code != (DWORD)(i + 100)) {
      printf("FAIL %s: thread #%d exit code %lu, expected %d\n",
             TEST_NAME, i, (unsigned long)code, i + 100);
      return 1;
    }
    /* Curl_thread_destroy */
    if(!CloseHandle(th[i])) {
      printf("FAIL %s: CloseHandle #%d failed, GetLastError=%lu\n",
             TEST_NAME, i, (unsigned long)GetLastError());
      return 1;
    }
  }

  if(g_counter != NTHREADS * ITERS) {
    printf("FAIL %s: counter=%ld, expected %d\n", TEST_NAME,
           (long)g_counter, NTHREADS * ITERS);
    return 1;
  }

  /* Failure path: a join on a blocked thread must time out, not succeed */
  g_gate = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!g_gate) {
    printf("FAIL %s: CreateEventW failed, GetLastError=%lu\n", TEST_NAME,
           (unsigned long)GetLastError());
    return 1;
  }
  blocked = CreateThread(NULL, 0, blocked_worker, NULL, 0, NULL);
  if(!blocked) {
    printf("FAIL %s: CreateThread(blocked) failed, GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    CloseHandle(g_gate);
    return 1;
  }
  wr = WaitForSingleObjectEx(blocked, 0, FALSE);
  if(wr != WAIT_TIMEOUT) {
    printf("FAIL %s: zero-timeout join on blocked thread returned %lu, "
           "expected WAIT_TIMEOUT\n", TEST_NAME, (unsigned long)wr);
    SetEvent(g_gate);
    WaitForSingleObject(blocked, INFINITE);
    CloseHandle(blocked);
    CloseHandle(g_gate);
    return 1;
  }

  SetEvent(g_gate);
  wr = WaitForSingleObjectEx(blocked, INFINITE, FALSE);
  if(wr != WAIT_OBJECT_0 || !GetExitCodeThread(blocked, &code) || code != 7) {
    printf("FAIL %s: released thread join returned %lu code %lu\n",
           TEST_NAME, (unsigned long)wr, (unsigned long)code);
    CloseHandle(blocked);
    CloseHandle(g_gate);
    return 1;
  }
  CloseHandle(blocked);
  CloseHandle(g_gate);

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
