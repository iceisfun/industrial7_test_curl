/*
 * Test: timing_waitforsingleobject_timeout
 * Purpose: WaitForSingleObject and WaitForSingleObjectEx honour their
 *          timeouts exactly: zero timeout polls without blocking, a
 *          finite timeout on an unsignaled event returns WAIT_TIMEOUT after
 *          roughly the requested time, and auto-reset events are consumed.
 * APIs: CreateEventW, SetEvent, ResetEvent, WaitForSingleObject,
 *       WaitForSingleObjectEx, QueryPerformanceCounter, CloseHandle
 * Success: Wait(ev, 0) on an unsignaled event returns WAIT_TIMEOUT in under
 *          100 ms; Wait(ev, 50) returns WAIT_TIMEOUT after at least 40 ms
 *          and under 5 s; after SetEvent on a manual-reset event, Wait(ev,
 *          1000) and WaitForSingleObjectEx(ev, INFINITE, FALSE) return
 *          WAIT_OBJECT_0; an auto-reset event is cleared by the first wait,
 *          so the second wait with timeout 0 returns WAIT_TIMEOUT.
 * Source: curl lib/curl_threads.c:57 (WaitForSingleObjectEx(*hnd, INFINITE,
 *         FALSE) == WAIT_OBJECT_0 is the Windows thread-join primitive;
 *         the timeout forms are what curl's event-based waits rely on).
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

static double ms_between(LARGE_INTEGER a, LARGE_INTEGER b, LONGLONG freq)
{
  return ((double)(b.QuadPart - a.QuadPart) * 1000.0) / (double)freq;
}

int main(void)
{
  HANDLE manual, autoev;
  LARGE_INTEGER f, a, b;
  DWORD r;
  double ms;

  if(!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) {
    printf("FAIL timing_waitforsingleobject_timeout: QueryPerformanceFrequency error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }

  manual = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!manual) {
    printf("FAIL timing_waitforsingleobject_timeout: CreateEventW(manual) error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }

  /* Zero timeout must poll and return immediately. */
  if(!QueryPerformanceCounter(&a)) {
    printf("FAIL timing_waitforsingleobject_timeout: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  r = WaitForSingleObject(manual, 0);
  if(!QueryPerformanceCounter(&b)) {
    printf("FAIL timing_waitforsingleobject_timeout: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  ms = ms_between(a, b, f.QuadPart);
  if(r != WAIT_TIMEOUT) {
    printf("FAIL timing_waitforsingleobject_timeout: Wait(0) on unsignaled event returned %lu (error %lu)\n",
           (unsigned long)r, (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  if(ms > 100.0) {
    printf("FAIL timing_waitforsingleobject_timeout: Wait(0) blocked for %.1f ms\n", ms);
    CloseHandle(manual);
    return 1;
  }

  /* Finite timeout must block for about that long, then time out. */
  if(!QueryPerformanceCounter(&a)) {
    printf("FAIL timing_waitforsingleobject_timeout: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  r = WaitForSingleObject(manual, 50);
  if(!QueryPerformanceCounter(&b)) {
    printf("FAIL timing_waitforsingleobject_timeout: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  ms = ms_between(a, b, f.QuadPart);
  if(r != WAIT_TIMEOUT) {
    printf("FAIL timing_waitforsingleobject_timeout: Wait(50) returned %lu (error %lu)\n",
           (unsigned long)r, (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  if(ms < 40.0 || ms > 5000.0) {
    printf("FAIL timing_waitforsingleobject_timeout: Wait(50) timed out after %.1f ms\n", ms);
    CloseHandle(manual);
    return 1;
  }

  /* Manual-reset event signaled: wait succeeds and stays signaled. */
  if(!SetEvent(manual)) {
    printf("FAIL timing_waitforsingleobject_timeout: SetEvent error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  r = WaitForSingleObject(manual, 1000);
  if(r != WAIT_OBJECT_0) {
    printf("FAIL timing_waitforsingleobject_timeout: Wait(1000) after SetEvent returned %lu\n",
           (unsigned long)r);
    CloseHandle(manual);
    return 1;
  }
  r = WaitForSingleObjectEx(manual, INFINITE, FALSE);
  if(r != WAIT_OBJECT_0) {
    printf("FAIL timing_waitforsingleobject_timeout: WaitForSingleObjectEx(INFINITE) returned %lu\n",
           (unsigned long)r);
    CloseHandle(manual);
    return 1;
  }
  if(!ResetEvent(manual)) {
    printf("FAIL timing_waitforsingleobject_timeout: ResetEvent error %lu\n",
           (unsigned long)GetLastError());
    CloseHandle(manual);
    return 1;
  }
  r = WaitForSingleObject(manual, 0);
  if(r != WAIT_TIMEOUT) {
    printf("FAIL timing_waitforsingleobject_timeout: manual event still signaled after ResetEvent (%lu)\n",
           (unsigned long)r);
    CloseHandle(manual);
    return 1;
  }
  CloseHandle(manual);

  /* Auto-reset event: the first successful wait consumes the signal. */
  autoev = CreateEventW(NULL, FALSE, TRUE, NULL);
  if(!autoev) {
    printf("FAIL timing_waitforsingleobject_timeout: CreateEventW(auto) error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  r = WaitForSingleObject(autoev, 0);
  if(r != WAIT_OBJECT_0) {
    printf("FAIL timing_waitforsingleobject_timeout: first wait on initially signaled auto event returned %lu\n",
           (unsigned long)r);
    CloseHandle(autoev);
    return 1;
  }
  r = WaitForSingleObject(autoev, 0);
  if(r != WAIT_TIMEOUT) {
    printf("FAIL timing_waitforsingleobject_timeout: auto event was not consumed (second wait returned %lu)\n",
           (unsigned long)r);
    CloseHandle(autoev);
    return 1;
  }
  CloseHandle(autoev);

  printf("PASS timing_waitforsingleobject_timeout\n");
  return 0;
}
