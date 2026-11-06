/*
 * Test: timing_waitable_timer_periodic_createex
 * Purpose: A periodic auto-reset waitable timer fires repeatedly at its
 *          period and stops after CancelWaitableTimer. CreateWaitableTimerExW
 *          (Windows 10 1803+) is resolved with GetProcAddress and the test
 *          SKIPs when it is not exported; the high-resolution flag is tried
 *          first (it must be accepted on Windows; the plain form is the
 *          fallback only under wine).
 * APIs: GetProcAddress, CreateWaitableTimerExW (dynamic), SetWaitableTimer,
 *       WaitForSingleObject, CancelWaitableTimer, QueryPerformanceCounter,
 *       CloseHandle
 * Success: five consecutive waits each return WAIT_OBJECT_0 within 2 s, the
 *          five ticks span 45..80 ms (period 10 ms; measured 51 ms with the
 *          high-resolution timer, which Windows 10 22H2 accepts); after
 *          CancelWaitableTimer and draining any in-flight signal, a 50 ms
 *          pause followed by a zero-timeout wait returns WAIT_TIMEOUT.
 * Source: curl does not use waitable timers (grep finds none in lib/); this
 *         covers the periodic timer primitive, not a curl code path.
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

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

typedef HANDLE (WINAPI *pfn_create_timer_ex_t)(LPSECURITY_ATTRIBUTES, LPCWSTR,
                                               DWORD, DWORD);

int main(void)
{
  HMODULE k32;
  pfn_create_timer_ex_t create_ex;
  HANDLE timer;
  LARGE_INTEGER f, due, a, b;
  DWORD err;
  int ticks = 0, drained = 0;
  double ms;

  k32 = LoadLibraryW(L"kernel32.dll");
  if(!k32) {
    printf("FAIL timing_waitable_timer_periodic_createex: LoadLibraryW(kernel32) error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  create_ex = (pfn_create_timer_ex_t)(void *)GetProcAddress(k32, "CreateWaitableTimerExW");
  if(!create_ex) {
    printf("SKIP timing_waitable_timer_periodic_createex: CreateWaitableTimerExW not exported\n");
    FreeLibrary(k32);
    return 77;
  }

  if(!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) {
    printf("FAIL timing_waitable_timer_periodic_createex: QueryPerformanceFrequency error %lu\n",
           (unsigned long)GetLastError());
    FreeLibrary(k32);
    return 1;
  }

  timer = create_ex(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
  if(!timer) {
    err = GetLastError();
    if(err == ERROR_CALL_NOT_IMPLEMENTED) {
      printf("SKIP timing_waitable_timer_periodic_createex: CreateWaitableTimerExW not implemented\n");
      FreeLibrary(k32);
      return 77;
    }
    printf("INFO CREATE_WAITABLE_TIMER_HIGH_RESOLUTION failed, error %lu\n", (unsigned long)err);
    if(!GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version")) {
      printf("FAIL timing_waitable_timer_periodic_createex: the high-resolution flag is rejected on Windows 10 (error %lu)\n", (unsigned long)err);
      FreeLibrary(k32);
      return 1;
    }
    timer = create_ex(NULL, NULL, 0, TIMER_ALL_ACCESS);
    if(!timer) {
      printf("FAIL timing_waitable_timer_periodic_createex: CreateWaitableTimerExW error %lu\n",
             (unsigned long)GetLastError());
      FreeLibrary(k32);
      return 1;
    }
  }

  printf("INFO high resolution timer created\n");
  /* Auto-reset periodic timer, first due in 10 ms, period 10 ms. */
  due.QuadPart = -100000LL;
  if(!SetWaitableTimer(timer, &due, 10, NULL, NULL, FALSE)) {
    printf("FAIL timing_waitable_timer_periodic_createex: SetWaitableTimer(periodic) error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(timer);
    FreeLibrary(k32);
    return 1;
  }

  if(!QueryPerformanceCounter(&a)) {
    printf("FAIL timing_waitable_timer_periodic_createex: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(timer);
    FreeLibrary(k32);
    return 1;
  }
  for(ticks = 0; ticks < 5; ticks++) {
    if(WaitForSingleObject(timer, 2000) != WAIT_OBJECT_0) {
      printf("FAIL timing_waitable_timer_periodic_createex: tick %d did not arrive (error %lu)\n",
             ticks, (unsigned long)GetLastError());
      CloseHandle(timer);
      FreeLibrary(k32);
      return 1;
    }
  }
  if(!QueryPerformanceCounter(&b)) {
    printf("FAIL timing_waitable_timer_periodic_createex: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(timer);
    FreeLibrary(k32);
    return 1;
  }
  ms = ((double)(b.QuadPart - a.QuadPart) * 1000.0) / (double)f.QuadPart;
  printf("INFO five 10 ms ticks spanned %.2f ms\n", ms);
  if(ms < 45.0 || ms > 80.0) {
    printf("FAIL timing_waitable_timer_periodic_createex: five 10 ms ticks spanned %.1f ms, expected 45..80\n", ms);
    CloseHandle(timer);
    FreeLibrary(k32);
    return 1;
  }

  if(!CancelWaitableTimer(timer)) {
    printf("FAIL timing_waitable_timer_periodic_createex: CancelWaitableTimer error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(timer);
    FreeLibrary(k32);
    return 1;
  }

  /* Drain any tick that was already in flight before the cancel. */
  while(WaitForSingleObject(timer, 0) == WAIT_OBJECT_0 && drained < 100)
    drained++;

  Sleep(50);
  if(WaitForSingleObject(timer, 0) != WAIT_TIMEOUT) {
    printf("FAIL timing_waitable_timer_periodic_createex: timer kept firing after cancel\n");
    CloseHandle(timer);
    FreeLibrary(k32);
    return 1;
  }

  CloseHandle(timer);
  FreeLibrary(k32);
  printf("PASS timing_waitable_timer_periodic_createex\n");
  return 0;
}
