/*
 * Test: 18_qpc_cross_thread_monotonic
 * Purpose: curl's curlx_now() uses QueryPerformanceCounter and its multi
 *          handle compares timestamps taken on different threads (resolver
 *          threads, the main thread). The counter must be monotonic across
 *          threads and cores, and must agree with the system clock over time.
 * APIs: QueryPerformanceCounter/Frequency, GetSystemTimePreciseAsFileTime,
 *       GetTickCount64, CreateThread, SetThreadAffinityMask, InterlockedCompareExchange64.
 * Success: 8 threads pinned to different logical CPUs read QPC against a shared
 *          "latest seen" value 200000 times each; no thread ever reads a value lower than one
 *          published earlier (checked by a release/acquire handshake);
 *          QPC and GetSystemTimePreciseAsFileTime advance at the same rate within 0.5 percent
 *          over 500 ms (pinned: observed spread logged); QPC and GetTickCount64 agree within
 *          60 ms (the tick counter lags under load: 26 ms seen); the frequency is 10 MHz (Win10 uses the 10 MHz reference when HyperV/TSC).
 * Source: lib/timeval.c (curlx_now on Windows).
 */
#define TEST_NAME "18_qpc_cross_thread_monotonic"
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
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

#define INFO(...) do { printf("INFO "); printf(__VA_ARGS__); printf("\n"); } while (0)
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); g_fail = 1; goto out; } while (0)
static __attribute__((unused)) int g_fail;

static volatile LONG64 g_latest;
static volatile LONG g_bad, g_go;
#define READS 200000
#define NT 8

static DWORD WINAPI worker(LPVOID p) {
  DWORD_PTR cpu = (DWORD_PTR)p;
  LARGE_INTEGER c;
  int i;
  DWORD_PTR mask = (DWORD_PTR)1 << (cpu % 32);
  SetThreadAffinityMask(GetCurrentThread(), mask);
  while (!g_go) Sleep(0);
  for (i = 0; i < READS; i++) {
    LONG64 seen = InterlockedCompareExchange64(&g_latest, 0, 0);
    QueryPerformanceCounter(&c);
    if (c.QuadPart < seen) InterlockedIncrement(&g_bad);
    for (;;) {
      LONG64 cur = InterlockedCompareExchange64(&g_latest, 0, 0);
      if (c.QuadPart <= cur) break;
      if (InterlockedCompareExchange64(&g_latest, c.QuadPart, cur) == cur) break;
    }
  }
  return 0;
}

static double qpc_ms(void) {
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
  return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
}
static double sys_ms(void) {
  FILETIME ft; ULARGE_INTEGER u;
  GetSystemTimePreciseAsFileTime(&ft);
  u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
  return (double)u.QuadPart / 10000.0;
}

int main(void) {
  HANDLE th[NT];
  int i, round;
  LARGE_INTEGER f;
  SYSTEM_INFO si;
  double worst = 0.0;

  GetSystemInfo(&si);
  QueryPerformanceFrequency(&f);
  INFO("QPF=%lld cpus=%lu", (long long)f.QuadPart, (unsigned long)si.dwNumberOfProcessors);
  for (round = 0; round < 5; round++) {
    g_latest = 0; g_bad = 0; g_go = 0;
    for (i = 0; i < NT; i++) th[i] = CreateThread(NULL, 0, worker, (LPVOID)(DWORD_PTR)i, 0, NULL);
    Sleep(50);
    g_go = 1;
    WaitForMultipleObjects(NT, th, TRUE, 30000);
    for (i = 0; i < NT; i++) CloseHandle(th[i]);
    if (g_bad) FAILF("round %d: %ld backwards reads", round, (long)g_bad);
  }
  INFO("5 rounds x 8 threads x %d reads: no backwards QPC read", READS);

  for (round = 0; round < 4; round++) {
    double q0 = qpc_ms(), s0 = sys_ms(), q1, s1, dq, ds, rel;
    ULONGLONG t0 = GetTickCount64(), t1;
    Sleep(500);
    q1 = qpc_ms(); s1 = sys_ms(); t1 = GetTickCount64();
    dq = q1 - q0; ds = s1 - s0;
    rel = (dq - ds) / dq * 100.0;
    if (rel < 0) rel = -rel;
    if (rel > worst) worst = rel;
    INFO("round %d: qpc %.3f ms sys %.3f ms tick %llu ms rel diff %.4f%%", round, dq, ds, (unsigned long long)(t1 - t0), rel);
    if (rel > 0.5) FAILF("QPC and system time diverge by %.3f%% over 500 ms", rel);
    if ((double)(t1 - t0) < dq - 60.0 || (double)(t1 - t0) > dq + 60.0) FAILF("GetTickCount64 delta %llu vs QPC %.1f", (unsigned long long)(t1 - t0), dq);
  }
  INFO("worst QPC vs system clock difference %.4f%%", worst);
  if (f.QuadPart != 10000000LL) FAILF("QPF %lld", (long long)f.QuadPart);
  printf("PASS %s\n", TEST_NAME);
out:
  return g_fail;
}
