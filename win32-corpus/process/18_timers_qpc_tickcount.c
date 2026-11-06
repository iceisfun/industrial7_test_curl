/*
 * Test: 18_timers_qpc_tickcount
 *
 * Purpose: the clocks curl's timeval/curlx_now code uses on Windows
 *   (QueryPerformanceCounter, GetTickCount64, GetSystemTimePreciseAsFileTime)
 *   and their resolution. Probed on Win10 22H2 (build 19045).
 *
 * Success:
 *   - QueryPerformanceFrequency is 10 000 000 Hz (Win10 fixed rate), and a
 *     Sleep(50) spans 49.5 .. 250 ms of QPC time.
 *   - GetTickCount64 (and GetTickCount) advance in steps of 10..20 ms (the
 *     default 15.625 ms system timer tick: 5 consecutive steps measured here;
 *     probe: 15 or 16 ms every time) and agree with each other within 1 s.
 *   - a Sleep(1) lasts at least 1 ms and, with the default timer resolution,
 *     100 of them take between 1.0 s and 2.5 s (probed 1.56 s).
 *   - QPC is monotonic over 100000 reads.
 *   - GetSystemTimePreciseAsFileTime is within 50 ms of GetSystemTimeAsFileTime.
 *   - NtQueryTimerResolution reports a current resolution of 156250 (100 ns
 *     units) unless another process raised it; the test only requires that
 *     it is 5000 .. 160000.
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
#include <string.h>
#include <wchar.h>

#define NAME "timers_qpc_tickcount"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

typedef LONG (NTAPI *qtr_fn)(PULONG, PULONG, PULONG);

int main(void)
{
    LARGE_INTEGER fq, a, b, prev;
    ULONGLONG t, s0, s1;
    DWORD i, t0, t1;
    double ms;
    FILETIME fa, fb;
    long long d;
    qtr_fn q;
    ULONG mn, mx, cur;
    int coarse = 1;

    if (!QueryPerformanceFrequency(&fq) || fq.QuadPart != 10000000LL)
        FAILF("QPF = %lld, expected 10000000", (long long)fq.QuadPart);
    {
        qtr_fn q0 = (qtr_fn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryTimerResolution");
        ULONG a0, b0, c0 = 156250;
        if (q0 && q0(&a0, &b0, &c0) == 0)
            coarse = (c0 >= 150000);
        printf("INFO start timer resolution %lu, tick-bound checks %s\n", (unsigned long)c0, coarse ? "on" : "off (another process raised the resolution)");
    }
    QueryPerformanceCounter(&a);
    Sleep(50);
    QueryPerformanceCounter(&b);
    ms = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)fq.QuadPart;
    if (ms < 49.5 || ms > 250.0)
        FAILF("Sleep(50) took %.2f ms of QPC time", ms);

    for (i = 0; i < 5; i++) {
        s0 = GetTickCount64();
        while ((s1 = GetTickCount64()) == s0) ;
        s0 = s1;
        while ((s1 = GetTickCount64()) == s0) ;
        if (coarse && (s1 - s0 < 10 || s1 - s0 > 20))
            FAILF("GetTickCount64 step %llu ms, expected 10..20", (unsigned long long)(s1 - s0));
    }
    t = GetTickCount64();
    {
        ULONGLONG t32 = GetTickCount();
        ULONGLONG diff = t > t32 ? t - t32 : t32 - t;
        if (diff > 1000 && diff < 0xFFFFF000ULL)
            FAILF("GetTickCount (%llu) and GetTickCount64 (%llu) disagree", (unsigned long long)t32, (unsigned long long)t);
    }

    t0 = GetTickCount();
    for (i = 0; i < 100; i++) Sleep(1);
    t1 = GetTickCount();
    if (coarse && (t1 - t0 < 1000 || t1 - t0 > 2500))
        FAILF("100 x Sleep(1) took %lu ms, expected 1000..2500 (15.6 ms tick)", (unsigned long)(t1 - t0));

    QueryPerformanceCounter(&prev);
    for (i = 0; i < 100000; i++) {
        QueryPerformanceCounter(&b);
        if (b.QuadPart < prev.QuadPart)
            FAILF("QPC went backwards at read %lu", (unsigned long)i);
        prev = b;
    }

    GetSystemTimePreciseAsFileTime(&fa);
    GetSystemTimeAsFileTime(&fb);
    d = (long long)((((ULONGLONG)fa.dwHighDateTime << 32) | fa.dwLowDateTime) -
                    (((ULONGLONG)fb.dwHighDateTime << 32) | fb.dwLowDateTime));
    if (d < -500000 || d > 500000)
        FAILF("precise vs coarse system time differ by %lld (100 ns)", d);

    q = (qtr_fn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryTimerResolution");
    if (q) {
        if (q(&mn, &mx, &cur) != 0)
            FAILF("NtQueryTimerResolution failed");
        if (cur < 5000 || cur > 160000)
            FAILF("timer resolution %lu (100 ns) out of range", (unsigned long)cur);
    }

    printf("PASS " NAME "\n");
    return 0;
}
