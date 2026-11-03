/*
 * Test: timing_qpc_monotonic_split
 * Purpose: QueryPerformanceCounter never goes backwards, and the
 *          seconds/microseconds split that curl performs on it is exact
 *          enough to be monotonic in microseconds too.
 * APIs: QueryPerformanceFrequency, QueryPerformanceCounter
 * Success: 200000 consecutive reads are non-decreasing; for each read the
 *          sec/usec split satisfies 0 <= usec <= 999999, reconstructs the
 *          raw count to within one microsecond worth of ticks, and the
 *          combined sec*1e6+usec value never decreases.
 * Source: curl lib/curlx/timeval.c:38-48 (curlx_pnow) performs exactly
 *         this split: tv_sec = count/freq, tv_usec = (count%freq)*1e6/freq.
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

int main(void)
{
  LARGE_INTEGER f, start, prev, count;
  long long freq, prev_total_us = -1, total_us, sec, rem, usec, back, slack;
  int i;

  if(!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) {
    printf("FAIL timing_qpc_monotonic_split: QueryPerformanceFrequency error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  freq = f.QuadPart;
  slack = freq / 1000000 + 2;

  if(!QueryPerformanceCounter(&start)) {
    printf("FAIL timing_qpc_monotonic_split: QueryPerformanceCounter error %lu\n",
           (unsigned long)GetLastError());
    return 1;
  }
  prev = start;

  for(i = 0; i < 200000; i++) {
    if(!QueryPerformanceCounter(&count)) {
      printf("FAIL timing_qpc_monotonic_split: QPC error %lu at read %d\n",
             (unsigned long)GetLastError(), i);
      return 1;
    }
    if(count.QuadPart < prev.QuadPart) {
      printf("FAIL timing_qpc_monotonic_split: counter went backwards at read %d (%lld < %lld)\n",
             i, (long long)count.QuadPart, (long long)prev.QuadPart);
      return 1;
    }

    /* curl's split, lib/curlx/timeval.c:43-44 */
    sec = count.QuadPart / freq;
    rem = count.QuadPart % freq;
    usec = (rem * 1000000LL) / freq;
    if(usec < 0 || usec > 999999) {
      printf("FAIL timing_qpc_monotonic_split: usec %lld out of range at read %d\n",
             usec, i);
      return 1;
    }

    /* Reconstruction must land within one microsecond of ticks. */
    back = sec * freq + (usec * freq) / 1000000LL;
    if(count.QuadPart - back < 0 || count.QuadPart - back > slack) {
      printf("FAIL timing_qpc_monotonic_split: split does not reconstruct count at read %d (diff %lld, slack %lld)\n",
             i, (long long)(count.QuadPart - back), slack);
      return 1;
    }

    total_us = sec * 1000000LL + usec;
    if(total_us < prev_total_us) {
      printf("FAIL timing_qpc_monotonic_split: microsecond value decreased at read %d (%lld < %lld)\n",
             i, total_us, prev_total_us);
      return 1;
    }
    prev_total_us = total_us;
    prev = count;
  }

  if(prev.QuadPart <= start.QuadPart) {
    printf("FAIL timing_qpc_monotonic_split: counter did not advance across 200000 reads\n");
    return 1;
  }

  printf("PASS timing_qpc_monotonic_split\n");
  return 0;
}
