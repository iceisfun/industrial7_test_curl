/*
 * Test: 16_tls_expansion_slots
 * Area: tls
 * Purpose: TLS indices >= TLS_MINIMUM_AVAILABLE (64) live in the TEB
 *   expansion array, which is allocated lazily per thread. Verify that
 *   indices above 64 work in a thread created BEFORE the index was allocated
 *   (curl allocates its index lazily in curl_global_init, while application
 *   threads already exist) and that per-thread isolation holds there.
 * APIs: TlsAlloc, TlsSetValue, TlsGetValue, TlsFree, CreateThread.
 * Success means: allocate 100 indices (all distinct, all < 1088); at least one
 *   is >= 64 (the first 64 are taken by the startup, or the count exceeds 64);
 *   a helper thread started before the allocations can, after they exist, set
 *   and read back every index, and the main thread still sees its own values.
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

#define TEST_NAME "16_tls_expansion_slots"
#define N 100

static HANDLE g_go, g_done;
static DWORD g_idx[N];
static volatile int g_bad = -1;

static DWORD WINAPI helper(LPVOID p)
{
  int i;
  (void)p;
  WaitForSingleObject(g_go, INFINITE);
  for(i = 0; i < N; i++) {
    if(TlsGetValue(g_idx[i]) != NULL) { g_bad = i; break; }
    if(!TlsSetValue(g_idx[i], (void *)(uintptr_t)(0x9000 + i))) { g_bad = 1000 + i; break; }
  }
  for(i = 0; g_bad < 0 && i < N; i++)
    if(TlsGetValue(g_idx[i]) != (void *)(uintptr_t)(0x9000 + i)) { g_bad = 2000 + i; break; }
  SetEvent(g_done);
  return 0;
}

int main(void)
{
  HANDLE th;
  int i, maxi = 0, big = 0;

  g_go = CreateEventW(NULL, FALSE, FALSE, NULL);
  g_done = CreateEventW(NULL, FALSE, FALSE, NULL);
  th = CreateThread(NULL, 0, helper, NULL, 0, NULL);
  EXPECT(th != NULL, "CreateThread");
  for(i = 0; i < N; i++) {
    int j;
    g_idx[i] = TlsAlloc();
    EXPECT(g_idx[i] != TLS_OUT_OF_INDEXES, "TlsAlloc #%d", i);
    EXPECT(g_idx[i] < 1088, "index %lu >= 1088", g_idx[i]);
    for(j = 0; j < i; j++) EXPECT(g_idx[j] != g_idx[i], "duplicate index %lu", g_idx[i]);
    if((int)g_idx[i] > maxi) maxi = (int)g_idx[i];
    if(g_idx[i] >= 64) big++;
    EXPECT(TlsSetValue(g_idx[i], (void *)(uintptr_t)(0x1000 + i)), "main TlsSetValue #%d idx %lu", i, g_idx[i]);
  }
  INFO("max index %d, %d indices >= 64", maxi, big);
  EXPECT(big > 0, "no index >= 64 among 100 allocations");
  SetEvent(g_go);
  EXPECT(WaitForSingleObject(g_done, 10000) == WAIT_OBJECT_0, "helper timed out");
  EXPECT(g_bad < 0, "helper failure code %d", g_bad);
  for(i = 0; i < N; i++)
    EXPECT(TlsGetValue(g_idx[i]) == (void *)(uintptr_t)(0x1000 + i), "main lost value for index %lu", g_idx[i]);
  WaitForSingleObject(th, 10000); CloseHandle(th);
  for(i = 0; i < N; i++) TlsFree(g_idx[i]);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
