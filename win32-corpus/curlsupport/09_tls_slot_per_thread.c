/*
 * Test: 09_tls_slot_per_thread
 * Purpose: Check that per-thread data stored in a TLS slot is isolated
 *   between threads, which is the property curl's thread-private state
 *   relies on when a handle is used from several threads.
 * APIs: TlsAlloc, TlsSetValue, TlsGetValue, TlsFree, CreateThread,
 *   WaitForSingleObject, GetLastError, SetLastError, InterlockedIncrement,
 *   CloseHandle
 * Source: lib/curl_threads.c:32 (thread creation used by the threaded
 *   resolver and the worker helpers). The TLS slot semantics checked here
 *   are the Win32 contract that such per-thread state depends on.
 * Success: a new thread sees NULL in a fresh slot with GetLastError() == 0;
 *   each of 4 threads stores a distinct pointer, sleeps so that the threads
 *   overlap, and reads back only its own value; the main thread's value is
 *   unchanged afterwards; TlsFree returns TRUE.
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

#define TEST_NAME "09_tls_slot_per_thread"
#define NTHREADS 4
#define MAIN_VALUE ((void *)(uintptr_t)0xABCD)

static DWORD g_slot = TLS_OUT_OF_INDEXES;
static LONG g_errors = 0;

static DWORD WINAPI tls_worker(LPVOID arg)
{
  uintptr_t id = (uintptr_t)arg;
  void *mine = (void *)(uintptr_t)(0x1000 + id);
  void *initial;

  SetLastError(0);
  initial = TlsGetValue(g_slot);
  if(initial != NULL || GetLastError() != ERROR_SUCCESS)
    InterlockedIncrement(&g_errors);

  if(!TlsSetValue(g_slot, mine))
    InterlockedIncrement(&g_errors);

  Sleep(30); /* let the other threads store their values meanwhile */

  if(TlsGetValue(g_slot) != mine)
    InterlockedIncrement(&g_errors);

  return 0;
}

int main(void)
{
  HANDLE th[NTHREADS];
  DWORD wr;
  int i;

  g_slot = TlsAlloc();
  if(g_slot == TLS_OUT_OF_INDEXES) {
    printf("FAIL %s: TlsAlloc failed, GetLastError=%lu\n", TEST_NAME,
           (unsigned long)GetLastError());
    return 1;
  }

  if(!TlsSetValue(g_slot, MAIN_VALUE)) {
    printf("FAIL %s: TlsSetValue(main) failed, GetLastError=%lu\n", TEST_NAME,
           (unsigned long)GetLastError());
    TlsFree(g_slot);
    return 1;
  }

  for(i = 0; i < NTHREADS; i++) {
    th[i] = CreateThread(NULL, 0, tls_worker, (LPVOID)(uintptr_t)i, 0, NULL);
    if(!th[i]) {
      printf("FAIL %s: CreateThread #%d failed, GetLastError=%lu\n", TEST_NAME,
             i, (unsigned long)GetLastError());
      TlsFree(g_slot);
      return 1;
    }
  }

  for(i = 0; i < NTHREADS; i++) {
    wr = WaitForSingleObject(th[i], INFINITE);
    CloseHandle(th[i]);
    if(wr != WAIT_OBJECT_0) {
      printf("FAIL %s: join #%d returned %lu\n", TEST_NAME, i,
             (unsigned long)wr);
      TlsFree(g_slot);
      return 1;
    }
  }

  if(g_errors != 0) {
    printf("FAIL %s: %ld thread-local isolation errors\n", TEST_NAME,
           (long)g_errors);
    TlsFree(g_slot);
    return 1;
  }

  if(TlsGetValue(g_slot) != MAIN_VALUE) {
    printf("FAIL %s: main thread value was overwritten by workers\n", TEST_NAME);
    TlsFree(g_slot);
    return 1;
  }

  if(!TlsFree(g_slot)) {
    printf("FAIL %s: TlsFree failed, GetLastError=%lu\n", TEST_NAME,
           (unsigned long)GetLastError());
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
