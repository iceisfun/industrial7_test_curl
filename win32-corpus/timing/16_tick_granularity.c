/*
 * Test: 16_tick_granularity
 * Purpose: The clock sources curl mixes (QueryPerformanceCounter for
 *   curlx_now, GetTickCount64, timeGetTime, GetSystemTimeAsFileTime) have very
 *   different granularity; code that compares them must not assume
 *   millisecond steps. Also the system timer resolution via NtQueryTimerResolution.
 * APIs: GetTickCount64, GetTickCount, GetSystemTimeAsFileTime,
 *   GetSystemTimePreciseAsFileTime, QueryPerformanceFrequency,
 *   NtQueryTimerResolution (ntdll), timeBeginPeriod / timeEndPeriod
 * Success (probed on Windows 10 22H2): QueryPerformanceFrequency is 10 MHz;
 *   GetTickCount64 observed over 300 ms takes only a few distinct values
 *   (17-21 values; measured 19) whose steps are all 15 or 16 ms (one
 *   15.625 ms tick); GetTickCount equals the low 32 bits
 *   of GetTickCount64 within 20 ms; the coarse system time moves in the same
 *   steps while GetSystemTimePreciseAsFileTime changes between successive
 *   reads (finer than 1 ms); NtQueryTimerResolution reports current ==
 *   156250 (100 ns units, coarse system time step measured 156412) by default and 10000 while timeBeginPeriod(1) is
 *   held, returning to the default afterwards.
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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if(!(cond)) {                                                          \
      printf("FAIL %s: ", TEST_NAME);                                      \
      printf(__VA_ARGS__);                                                 \
      printf(" [line %d, GetLastError=%lu]\n", __LINE__,                   \
             (unsigned long)GetLastError());                               \
      rc = 1;                                                              \
      goto out;                                                            \
    }                                                                      \
  } while(0)

__attribute__((unused)) static double qpc_ms(void)
{
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
}

__attribute__((unused)) static int is_wine(void)
{
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  return nt && GetProcAddress(nt, "wine_get_version") != NULL;
}

#define TEST_NAME "16_tick_granularity"

typedef LONG (NTAPI *nqtr_fn)(PULONG, PULONG, PULONG);
typedef VOID (WINAPI *precise_fn)(LPFILETIME);

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  int rc = 0, steps = 0, i;
  LARGE_INTEGER f;
  ULONGLONG last, now, minstep = ~0ULL, maxstep = 0, end;
  ULONG minr = 0, maxr = 0, cur = 0, cur1 = 0, cur2 = 0;
  nqtr_fn nq = (nqtr_fn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryTimerResolution");
  precise_fn pre = (precise_fn)(void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetSystemTimePreciseAsFileTime");
  FILETIME a, b;
  ULONGLONG ua, ub, cstep = 0, pdiff = 0;
  int distinct_precise = 0;

  QueryPerformanceFrequency(&f);
  printf("INFO QPC frequency %lld\n", f.QuadPart);
  CHECK(f.QuadPart == 10000000LL, "QPC frequency %lld, expected 10000000", f.QuadPart);

  if(nq) {
    CHECK(nq(&minr, &maxr, &cur) == 0, "NtQueryTimerResolution");
    printf("INFO resolution min %lu max %lu cur %lu\n", (unsigned long)minr, (unsigned long)maxr, (unsigned long)cur);
  }

  /* observe GetTickCount64 steps for 300 ms */
  last = GetTickCount64();
  while(last == (now = GetTickCount64())) ;
  last = now;
  end = last + 300;
  while((now = GetTickCount64()) < end) {
    ULONGLONG step;
    if(now != last) {
      step = now - last;
      if(step < minstep) minstep = step;
      if(step > maxstep) maxstep = step;
      steps++;
      last = now;
    }
  }
  printf("INFO GetTickCount64 steps=%d min=%llu max=%llu\n", steps, minstep, maxstep);
  CHECK(steps >= 17 && steps <= 21, "%d distinct tick values in 300 ms", steps);
  CHECK(minstep >= 15 && maxstep <= 16, "tick steps %llu..%llu ms, expected 15..16", minstep, maxstep);
  {
    ULONGLONG t64 = GetTickCount64();
    DWORD t32 = GetTickCount();
    long diff = (long)((DWORD)t64 - t32);
    CHECK(diff >= -20 && diff <= 20, "GetTickCount vs 64: %ld ms", diff);
  }

  /* precise time is finer than the coarse system time */
  if(pre) {
    pre(&a);
    for(i = 0; i < 1000; i++) {
      pre(&b);
      ua = ((ULONGLONG)a.dwHighDateTime << 32) | a.dwLowDateTime;
      ub = ((ULONGLONG)b.dwHighDateTime << 32) | b.dwLowDateTime;
      if(ub != ua)
        distinct_precise++;
      if(ub - ua > pdiff && ub > ua)
        pdiff = ub - ua;
      a = b;
    }
    printf("INFO precise: %d changes in 1000 reads, max step %llu x100ns\n", distinct_precise, pdiff);
    CHECK(distinct_precise > 50, "precise time changed only %d times", distinct_precise);
    GetSystemTimeAsFileTime(&a);
    do { GetSystemTimeAsFileTime(&b); } while(!memcmp(&a, &b, sizeof(a)));
    ua = ((ULONGLONG)a.dwHighDateTime << 32) | a.dwLowDateTime;
    ub = ((ULONGLONG)b.dwHighDateTime << 32) | b.dwLowDateTime;
    cstep = ub - ua;
    printf("INFO coarse system time step %llu x100ns\n", cstep);
    CHECK(cstep >= 150000 && cstep <= 160000, "coarse step %llu x100ns, expected one tick", cstep);
  }

  if(nq) {
    CHECK(cur == 156250, "default timer resolution %lu, expected 156250", (unsigned long)cur);
    CHECK(timeBeginPeriod(1) == TIMERR_NOERROR, "timeBeginPeriod");
    nq(&minr, &maxr, &cur1);
    timeEndPeriod(1);
    Sleep(50);
    nq(&minr, &maxr, &cur2);
    printf("INFO resolution with period 1: %lu, after end: %lu\n", (unsigned long)cur1, (unsigned long)cur2);
    CHECK(cur1 == 10000, "resolution under timeBeginPeriod(1) is %lu", (unsigned long)cur1);
    CHECK(cur2 == 156250, "resolution after timeEndPeriod is %lu", (unsigned long)cur2);
  }

  printf("PASS %s\n", TEST_NAME);
out:
  return rc;
}
