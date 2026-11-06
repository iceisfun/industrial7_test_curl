/*
 * Test: 17_many_threads_tls_isolation
 * Area: tls
 * Purpose: curl's threaded resolver and curl_multi create many short threads
 *   that each use a TLS/FLS slot. Verify isolation and destructor accounting
 *   under churn: 200 threads in waves of 16, each sets a unique value in one
 *   TLS slot and one FLS slot (with a destructor), reads it back after a
 *   yield, and exits.
 * APIs: CreateThread, TlsAlloc/Set/Get, FlsAlloc (callback)/Set/Get,
 *   InterlockedIncrement, WaitForMultipleObjects.
 * Success means: no thread ever reads another thread's value; the FLS
 *   callback runs exactly once per thread that set a non-NULL value (200
 *   calls, with the unique values summing to the expected total) before the
 *   thread handle is signalled.
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

#define TEST_NAME "17_many_threads_tls_isolation"
#define NT 200
#define WAVE 16

static DWORD g_tls, g_fls;
static volatile LONG g_dtor_calls;
static volatile LONG64 g_dtor_sum;
static volatile LONG g_bad;

static VOID WINAPI dtor(PVOID v)
{
  if(v) {
    InterlockedIncrement(&g_dtor_calls);
    InterlockedExchangeAdd64(&g_dtor_sum, (LONG64)(uintptr_t)v);
  }
}

static DWORD WINAPI worker(LPVOID p)
{
  uintptr_t id = (uintptr_t)p;
  int k;
  TlsSetValue(g_tls, (void *)(id * 3 + 1));
  FlsSetValue(g_fls, (void *)id);
  for(k = 0; k < 50; k++) {
    SwitchToThread();
    if(TlsGetValue(g_tls) != (void *)(id * 3 + 1)) InterlockedIncrement(&g_bad);
    if(FlsGetValue(g_fls) != (void *)id) InterlockedIncrement(&g_bad);
  }
  return 0;
}

int main(void)
{
  int done = 0, i;
  LONG64 expect = 0;

  g_tls = TlsAlloc();
  g_fls = FlsAlloc(dtor);
  EXPECT(g_tls != TLS_OUT_OF_INDEXES && g_fls != FLS_OUT_OF_INDEXES, "alloc");
  while(done < NT) {
    HANDLE h[WAVE];
    int n = 0;
    for(i = 0; i < WAVE && done + i < NT; i++) {
      uintptr_t id = (uintptr_t)(done + i + 1);
      h[n] = CreateThread(NULL, 0, worker, (void *)id, 0, NULL);
      EXPECT(h[n] != NULL, "CreateThread %d err=%lu", done + i, GetLastError());
      expect += (LONG64)id;
      n++;
    }
    EXPECT(WaitForMultipleObjects((DWORD)n, h, TRUE, 30000) == WAIT_OBJECT_0, "wave timeout");
    for(i = 0; i < n; i++) CloseHandle(h[i]);
    done += n;
  }
  EXPECT(g_bad == 0, "%ld cross-thread TLS/FLS reads", (long)g_bad);
  INFO("dtor calls=%ld sum=%lld expect sum=%lld", (long)g_dtor_calls, (long long)g_dtor_sum, (long long)expect);
  EXPECT(g_dtor_calls == NT, "FLS callback ran %ld times, want %d", (long)g_dtor_calls, NT);
  EXPECT(g_dtor_sum == expect, "FLS callback value sum %lld want %lld", (long long)g_dtor_sum, (long long)expect);
  TlsFree(g_tls); FlsFree(g_fls);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
