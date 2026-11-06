/*
 * Test: 05_getprocaddress_missing_null
 *
 * Purpose: GetProcAddress returns NULL with ERROR_PROC_NOT_FOUND for a missing
 *   export; for an out-of-range ordinal it returns NULL with
 *   ERROR_INVALID_ORDINAL (182) (probed on Win10 22H2 build 19045). LoadLibrary of a missing module
 *   returns NULL with ERROR_MOD_NOT_FOUND. Also covers the optional-feature
 *   fallback pattern: a probe for a newer export fails, and the caller falls
 *   back to an older export that exists.
 *
 * APIs: GetModuleHandleW, GetProcAddress, LoadLibraryW, SetLastError, GetLastError
 *
 * Success:
 *   - GetProcAddress(kernel32, "TcNoSuchFunctionXyz05") == NULL and
 *     GetLastError() == 127 (ERROR_PROC_NOT_FOUND).
 *   - GetProcAddress(kernel32, MAKEINTRESOURCEA(65000)) == NULL, error 182
 *     (ERROR_INVALID_ORDINAL).
 *   - LoadLibraryW(L"tc_no_such_module_05.dll") == NULL, error 126.
 *   - Fallback probe: GetProcAddress(kernel32, "GetSystemTimePreciseAsFileTime")
 *     is tried first; if it resolves it is called, otherwise GetSystemTimeAsFileTime
 *     (always present) is used. Either path must return a non-zero FILETIME.
 *     The test does not require the newer export to be absent; it only
 *     requires whichever export was resolved to work.
 *
 * Source reference: none direct; the NULL-check-and-fallback shape mirrors how
 *   curl treats an absent ntdll export (lib/curlx/version_win32.c:58).
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

#define NAME "getprocaddress_missing_null"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

typedef void (WINAPI *precise_fn)(LPFILETIME);
typedef void (WINAPI *plain_fn)(LPFILETIME);

int main(void)
{
    HMODULE k32;
    FARPROC p;
    FILETIME ft;
    ULONGLONG ticks;

    k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32)
        FAILF("GetModuleHandleW(kernel32.dll) err=%lu", (unsigned long)GetLastError());

    SetLastError(0);
    p = GetProcAddress(k32, "TcNoSuchFunctionXyz05");
    if (p != NULL)
        FAILF("nonexistent export resolved to %p", (void *)p);
    if (GetLastError() != ERROR_PROC_NOT_FOUND)
        FAILF("nonexistent export: expected ERROR_PROC_NOT_FOUND(127) got %lu",
              (unsigned long)GetLastError());

    SetLastError(0);
    p = GetProcAddress(k32, MAKEINTRESOURCEA(65000));
    if (p != NULL)
        FAILF("out-of-range ordinal resolved to %p", (void *)p);
    if (GetLastError() != ERROR_INVALID_ORDINAL)
        FAILF("out-of-range ordinal: expected ERROR_INVALID_ORDINAL(182) got %lu", (unsigned long)GetLastError());

    SetLastError(0);
    if (LoadLibraryW(L"tc_no_such_module_05.dll") != NULL)
        FAILF("LoadLibraryW of nonexistent DLL succeeded");
    if (GetLastError() != ERROR_MOD_NOT_FOUND)
        FAILF("nonexistent DLL: expected ERROR_MOD_NOT_FOUND(126) got %lu",
              (unsigned long)GetLastError());

    /* Optional-feature fallback: probe newer export, fall back to older one. */
    p = GetProcAddress(k32, "GetSystemTimePreciseAsFileTime");
    if (p) {
        ((precise_fn)(void *)p)(&ft);
    } else {
        p = GetProcAddress(k32, "GetSystemTimeAsFileTime");
        if (!p)
            FAILF("fallback GetSystemTimeAsFileTime err=%lu", (unsigned long)GetLastError());
        ((plain_fn)(void *)p)(&ft);
    }
    ticks = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    if (ticks == 0)
        FAILF("fallback time query returned a zero FILETIME");

    printf("PASS " NAME "\n");
    return 0;
}
