/*
 * Test: 01_loadlibrary_kernel32_a_w
 *
 * Purpose: LoadLibraryA and LoadLibraryW on an already-loaded system module
 *   (kernel32.dll) return the same HMODULE as GetModuleHandleW, and the
 *   returned handle resolves real exports. Case-insensitive name matching is
 *   exercised with an upper-case wide name.
 *
 * APIs: LoadLibraryA, LoadLibraryW, GetModuleHandleW, GetProcAddress, FreeLibrary
 *
 * Success: both loads return a non-NULL handle equal to GetModuleHandleW(L"kernel32.dll");
 *   GetProcAddress(h, "GetTickCount64") is non-NULL and returns a non-zero tick count;
 *   FreeLibrary returns TRUE for each successful LoadLibrary; the module stays
 *   resolvable afterwards (kernel32 is pinned).
 *
 * Source reference: lib/curlx/version_win32.c:58 uses the same GetModuleHandle +
 *   GetProcAddress pattern (there applied to ntdll, here to kernel32).
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
#include <stdint.h>

#define NAME "loadlibrary_kernel32_a_w"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

int main(void)
{
    HMODULE ha, hw, hm;
    FARPROC p;
    ULONGLONG (WINAPI *get_tick64)(void);

    ha = LoadLibraryA("kernel32.dll");
    if (!ha)
        FAILF("LoadLibraryA(kernel32.dll) err=%lu", (unsigned long)GetLastError());

    hw = LoadLibraryW(L"KERNEL32.DLL");
    if (!hw)
        FAILF("LoadLibraryW(KERNEL32.DLL) err=%lu", (unsigned long)GetLastError());

    hm = GetModuleHandleW(L"kernel32.dll");
    if (!hm)
        FAILF("GetModuleHandleW(kernel32.dll) err=%lu", (unsigned long)GetLastError());

    if (ha != hw || hw != hm)
        FAILF("handles differ: A=%p W=%p GetModuleHandle=%p", (void *)ha, (void *)hw, (void *)hm);

    p = GetProcAddress(ha, "GetTickCount64");
    if (!p)
        FAILF("GetProcAddress(GetTickCount64) err=%lu", (unsigned long)GetLastError());

    get_tick64 = (ULONGLONG (WINAPI *)(void))p;
    if (get_tick64() == 0)
        FAILF("GetTickCount64 returned 0");

    if (!FreeLibrary(ha))
        FAILF("FreeLibrary(A handle) err=%lu", (unsigned long)GetLastError());
    if (!FreeLibrary(hw))
        FAILF("FreeLibrary(W handle) err=%lu", (unsigned long)GetLastError());

    /* kernel32 must still be resolvable after the balancing FreeLibrary calls. */
    if (GetModuleHandleW(L"kernel32.dll") != hm)
        FAILF("kernel32 handle changed after FreeLibrary");
    if (!GetProcAddress(hm, "CreateThread"))
        FAILF("GetProcAddress(CreateThread) after FreeLibrary err=%lu", (unsigned long)GetLastError());

    printf("PASS " NAME "\n");
    return 0;
}
