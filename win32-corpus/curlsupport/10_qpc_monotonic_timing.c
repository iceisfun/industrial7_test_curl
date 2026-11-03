/*
 * Test: 10_qpc_monotonic_timing
 * Purpose: Mirror curl's Windows monotonic clock (curlx_now_init / curlx_pnow)
 *   and check it against Sleep() and GetTickCount64().
 * APIs: QueryPerformanceFrequency, QueryPerformanceCounter, Sleep,
 *   GetTickCount64
 * Source: lib/curlx/timeval.c:32-46. curlx_now_init() caches the QPC
 *   frequency; curlx_pnow() splits the counter into tv_sec and tv_usec with
 *   tv_sec = count / freq and tv_usec = (count % freq) * 1000000 / freq.
 *   lib/curlx/timeval.c:41 asserts the frequency is non-zero (DEBUGASSERT).
 * Success: frequency is positive; the derived tv_usec is always within
 *   0..999999; 2000 consecutive readings never go backwards; Sleep(50)
 *   measures >= 45000 us by the derived clock and agrees with
 *   GetTickCount64 within 500 ms.
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

#define TEST_NAME "10_qpc_monotonic_timing"

struct test_pnow {
  long long tv_sec;
  long tv_usec;
};

static LARGE_INTEGER s_freq;

/* Same arithmetic as curlx_pnow() in lib/curlx/timeval.c:40-45 */
static void test_pnow(struct test_pnow *pnow)
{
  LARGE_INTEGER count;
  QueryPerformanceCounter(&count);
  pnow->tv_sec = count.QuadPart / s_freq.QuadPart;
  pnow->tv_usec = (long)((count.QuadPart % s_freq.QuadPart) * 1000000 /
                         s_freq.QuadPart);
}

static long long to_usec(const struct test_pnow *t)
{
  return t->tv_sec * 1000000LL + t->tv_usec;
}

int main(void)
{
  struct test_pnow t0, t1, prev;
  ULONGLONG tick0, tick1;
  long long elapsed_us, tick_ms, diff_ms;
  int i;

  if(!QueryPerformanceFrequency(&s_freq) || s_freq.QuadPart <= 0) {
    printf("FAIL %s: QueryPerformanceFrequency failed, GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }

  test_pnow(&prev);
  for(i = 0; i < 2000; i++) {
    struct test_pnow now;
    test_pnow(&now);
    if(now.tv_usec < 0 || now.tv_usec > 999999) {
      printf("FAIL %s: tv_usec=%ld out of range\n", TEST_NAME, now.tv_usec);
      return 1;
    }
    if(to_usec(&now) < to_usec(&prev)) {
      printf("FAIL %s: monotonic clock went backwards at sample %d\n",
             TEST_NAME, i);
      return 1;
    }
    prev = now;
  }

  test_pnow(&t0);
  tick0 = GetTickCount64();
  Sleep(50);
  test_pnow(&t1);
  tick1 = GetTickCount64();

  elapsed_us = to_usec(&t1) - to_usec(&t0);
  if(elapsed_us < 45000 || elapsed_us > 5000000LL) {
    printf("FAIL %s: Sleep(50) measured %lld us by QPC\n", TEST_NAME,
           elapsed_us);
    return 1;
  }

  tick_ms = (long long)(tick1 - tick0);
  diff_ms = (elapsed_us / 1000) - tick_ms;
  if(diff_ms < -500 || diff_ms > 500) {
    printf("FAIL %s: QPC %lld ms vs GetTickCount64 %lld ms disagree\n",
           TEST_NAME, elapsed_us / 1000, tick_ms);
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
