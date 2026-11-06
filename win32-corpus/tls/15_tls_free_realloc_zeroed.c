/*
 * Test: 15_tls_free_realloc_zeroed
 * Area: tls
 * Purpose: A freed TLS/FLS index may be handed out again. The new owner must
 *   see NULL in every thread, not the previous owner's value (curl frees its
 *   index in curl_global_cleanup and may re-init in the same process).
 * APIs: TlsAlloc, TlsSetValue, TlsGetValue, TlsFree, FlsAlloc, FlsSetValue,
 *   FlsGetValue, FlsFree, CreateThread.
 * Success means: after TlsFree(i) a value stored by both the main thread and
 *   an already-running helper thread under i is gone for both threads when i
 *   is allocated again (Win10 22H2 reuses the same index immediately; the
 *   test records but does not require reuse, and checks every index handed out
 *   in a 300-round alloc/set/free cycle reads NULL on a fresh allocation).
 * Exit: 0 PASS, 1 FAIL.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define EXPECT(cond, ...) do { if(!(cond)) { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); fflush(stdout); return 1; } } while(0)
#define INFO(...) do { printf("INFO "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while(0)

#define TEST_NAME "15_tls_free_realloc_zeroed"

static HANDLE g_go, g_done, g_set;
static volatile DWORD g_idx;
static volatile int g_ok = 1;
static volatile void *g_seen;

static DWORD WINAPI helper(LPVOID p)
{
  (void)p;
  WaitForSingleObject(g_go, INFINITE);
  TlsSetValue(g_idx, (void *)(uintptr_t)0xAAAA);
  SetEvent(g_set);                    /* value stored */
  WaitForSingleObject(g_go, INFINITE); /* wait for free+realloc */
  g_seen = TlsGetValue(g_idx);
  SetEvent(g_done);
  return 0;
}

int main(void)
{
  DWORD i, j;
  HANDLE th;
  int reused = 0, n;

  g_go = CreateEventW(NULL, FALSE, FALSE, NULL);
  g_set = CreateEventW(NULL, FALSE, FALSE, NULL);
  g_done = CreateEventW(NULL, FALSE, FALSE, NULL);
  th = CreateThread(NULL, 0, helper, NULL, 0, NULL);
  EXPECT(th != NULL, "CreateThread");
  i = TlsAlloc();
  EXPECT(i != TLS_OUT_OF_INDEXES, "TlsAlloc");
  g_idx = i;
  TlsSetValue(i, (void *)(uintptr_t)0xBBBB);
  SetEvent(g_go);
  EXPECT(WaitForSingleObject(g_set, 10000) == WAIT_OBJECT_0, "helper store");
  EXPECT(TlsFree(i), "TlsFree");
  j = TlsAlloc();
  EXPECT(j != TLS_OUT_OF_INDEXES, "TlsAlloc again");
  reused = (j == i);
  INFO("realloc index %lu -> %lu reused=%d", i, j, reused);
  g_idx = j;
  EXPECT(TlsGetValue(j) == NULL, "main thread sees stale value %p in realloc'd slot", TlsGetValue(j));
  SetEvent(g_go);
  EXPECT(WaitForSingleObject(g_done, 10000) == WAIT_OBJECT_0, "helper read");
  EXPECT(g_seen == NULL, "helper thread sees stale value %p in realloc'd slot", (void *)g_seen);
  WaitForSingleObject(th, 10000); CloseHandle(th);
  TlsFree(j);

  for(n = 0; n < 300; n++) {
    DWORD k = TlsAlloc();
    EXPECT(k != TLS_OUT_OF_INDEXES, "round %d TlsAlloc", n);
    EXPECT(TlsGetValue(k) == NULL, "round %d: fresh slot %lu not NULL", n, k);
    TlsSetValue(k, (void *)(uintptr_t)(0x100 + n));
    EXPECT(TlsFree(k), "round %d TlsFree", n);
  }
  for(n = 0; n < 300; n++) {
    DWORD k = FlsAlloc(NULL);
    EXPECT(k != FLS_OUT_OF_INDEXES, "round %d FlsAlloc", n);
    EXPECT(FlsGetValue(k) == NULL, "round %d: fresh FLS slot %lu not NULL", n, k);
    FlsSetValue(k, (void *)(uintptr_t)(0x100 + n));
    EXPECT(FlsFree(k), "round %d FlsFree", n);
  }
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
