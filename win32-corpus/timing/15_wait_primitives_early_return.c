/*
 * Test: 15_wait_primitives_early_return
 * Purpose: curl's timeout bookkeeping assumes a wait never returns before its
 *   timeout (lib/curlx/wait.c Sleep, lib/select.c select/WSAPoll). Measure
 *   how early each primitive can return with the default 15.6 ms clock tick:
 *   Sleep, SleepEx, WaitForSingleObject, select, WSAPoll, WSAWaitForMultipleEvents.
 * APIs: Sleep, SleepEx, WaitForSingleObject, select, WSAPoll,
 *   WSAWaitForMultipleEvents, QueryPerformanceCounter
 * Finding (probed on Windows 10 22H2, 6 fresh VMs + 4 probe runs, 30 series, 40 repetitions):
 *   with the default 15.625 ms clock tick, a wait of N ms is quantised to
 *   tick boundaries and returns after somewhere between floor(N/15.625) and
 *   floor(N/15.625)+1 ticks: a 1, 5 or 10 ms wait returns after 0.3-28.5 ms
 *   (WSAPoll(10 ms) was seen returning after 0.25 ms), a 20 ms wait after
 *   15.8-46.9 ms, a 50 ms wait after 48.4-78.2 ms (30 series, 6 fresh VMs). So Sleep, SleepEx,
 *   WaitForSingleObject, select, WSAPoll and WSAWaitForMultipleEvents can
 *   all return up to a tick EARLY (Sleep is the least early). Code, including
 *   curl's timeout bookkeeping, has to re-check the clock instead of
 *   trusting a single wait.
 * Success: no primitive returns before floor(N/15.625)*15.625 - 1.5 ms or
 *   later than that floor + one tick + 20 ms. The measured minimum and
 *   maximum per primitive are printed as INFO lines.
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

#define TEST_NAME "15_wait_primitives_early_return"

enum { SLEEP_, SLEEPEX_, WFSO_, SELECT_, POLL_, WSAWAIT_, NPRIM };
static const char *names[NPRIM] = { "Sleep", "SleepEx", "WaitForSingleObject",
                                    "select", "WSAPoll", "WSAWaitForMultipleEvents" };

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  WSADATA wsa;
  int rc = 0, p, i, t;
  static const int tmo[5] = { 1, 5, 10, 20, 50 };
  HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  WSAEVENT wev = WSA_INVALID_EVENT;
  SOCKET s;
  fd_set rd;
  struct timeval tv;
  WSAPOLLFD pfd;

  if(WSAStartup(MAKEWORD(2, 2), &wsa))
    return 1;
  s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  wev = WSACreateEvent();
  WSAEventSelect(s, wev, FD_READ);

  for(t = 0; t < 5; t++) {
    for(p = 0; p < NPRIM; p++) {
      double mn = 1e9, mx = 0, d, t0, lo;
      for(i = 0; i < 40; i++) {
        t0 = qpc_ms();
        switch(p) {
        case SLEEP_: Sleep(tmo[t]); break;
        case SLEEPEX_: SleepEx(tmo[t], FALSE); break;
        case WFSO_: WaitForSingleObject(ev, tmo[t]); break;
        case SELECT_:
          FD_ZERO(&rd); FD_SET(s, &rd);
          tv.tv_sec = 0; tv.tv_usec = tmo[t] * 1000;
          select(0, &rd, NULL, NULL, &tv);
          break;
        case POLL_:
          pfd.fd = s; pfd.events = POLLRDNORM; pfd.revents = 0;
          WSAPoll(&pfd, 1, tmo[t]);
          break;
        default: WSAWaitForMultipleEvents(1, &wev, FALSE, tmo[t], FALSE); break;
        }
        d = qpc_ms() - t0;
        if(d < mn) mn = d;
        if(d > mx) mx = d;
      }
      printf("INFO %-26s timeout %2d ms: min %.2f max %.2f\n", names[p], tmo[t], mn, mx);
      lo = (int)(tmo[t] / 15.625) * 15.625;
      CHECK(mn >= lo - 1.5, "%s(%d) returned after only %.2f ms (floor %.2f)", names[p], tmo[t], mn, lo);
      CHECK(mx <= lo + 15.625 + 20.0, "%s(%d) took %.2f ms", names[p], tmo[t], mx);
    }
  }
  printf("PASS %s\n", TEST_NAME);
out:
  WSACleanup();
  return rc;
}
