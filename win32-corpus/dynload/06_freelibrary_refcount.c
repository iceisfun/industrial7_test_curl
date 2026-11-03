/*
 * Test: 06_freelibrary_refcount
 *
 * Purpose: Reference counting through LoadLibrary/FreeLibrary. Two loads of
 *   the same DLL return the same handle; one FreeLibrary must not invalidate
 *   the module while another reference is held; the function pointer obtained
 *   earlier must still be callable. FreeLibrary(NULL) must fail with
 *   ERROR_INVALID_HANDLE. LOAD_LIBRARY_AS_DATAFILE returns a non-executable
 *   handle with the low bit set, and FreeLibrary releases it.
 *
 * APIs: LoadLibraryExW (LOAD_LIBRARY_SEARCH_SYSTEM32), LoadLibraryW,
 *   GetProcAddress, FreeLibrary, GetModuleHandleW
 *
 * Success:
 *   - h1 == h2 != NULL for two loads of version.dll.
 *   - After FreeLibrary(h1) (TRUE), GetProcAddress(h2, "GetFileVersionInfoSizeW")
 *     is still non-NULL and the function still runs (missing file -> 0).
 *   - FreeLibrary(h2) returns TRUE.
 *   - FreeLibrary(NULL) returns FALSE with ERROR_INVALID_HANDLE (6).
 *   - LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_AS_DATAFILE) != NULL with
 *     ((uintptr_t)h & 1) == 1; FreeLibrary on it returns TRUE.
 *
 * Source reference: none direct; this covers the load/resolve/free lifecycle
 *   that any loader-based curl optional feature would follow.
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

#define NAME "freelibrary_refcount"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

typedef DWORD (WINAPI *get_ver_size_fn)(LPCWSTR, LPDWORD);

int main(void)
{
    HMODULE h1, h2, hdata;
    FARPROC p;
    get_ver_size_fn size_fn;
    DWORD r;

    h1 = LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!h1)
        FAILF("first load err=%lu", (unsigned long)GetLastError());

    h2 = LoadLibraryW(L"version.dll");
    if (!h2)
        FAILF("second load err=%lu", (unsigned long)GetLastError());
    if (h1 != h2)
        FAILF("two loads of same DLL gave different handles %p and %p", (void *)h1, (void *)h2);

    p = GetProcAddress(h1, "GetFileVersionInfoSizeW");
    if (!p)
        FAILF("GetProcAddress before free err=%lu", (unsigned long)GetLastError());
    size_fn = (get_ver_size_fn)(void *)p;

    if (!FreeLibrary(h1))
        FAILF("FreeLibrary(first ref) err=%lu", (unsigned long)GetLastError());

    /* One reference is still held, so the module and the pointer must still work. */
    if (GetModuleHandleW(L"version.dll") != h2)
        FAILF("module disappeared after releasing one of two references");
    SetLastError(0);
    r = size_fn(L"tc_no_such_file_06.dll", NULL);
    if (r != 0 || GetLastError() == 0)
        FAILF("pointer from earlier GetProcAddress no longer behaves (r=%lu err=%lu)",
              (unsigned long)r, (unsigned long)GetLastError());

    if (!FreeLibrary(h2))
        FAILF("FreeLibrary(second ref) err=%lu", (unsigned long)GetLastError());

    /* FreeLibrary(NULL) is an invalid handle. */
    SetLastError(0);
    if (FreeLibrary(NULL))
        FAILF("FreeLibrary(NULL) unexpectedly returned TRUE");
    if (GetLastError() != ERROR_INVALID_HANDLE)
        FAILF("FreeLibrary(NULL): expected ERROR_INVALID_HANDLE(6) got %lu",
              (unsigned long)GetLastError());

    /* Data-file load: not executable, low bit tagged. */
    hdata = LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hdata)
        FAILF("LOAD_LIBRARY_AS_DATAFILE err=%lu", (unsigned long)GetLastError());
    if ((((uintptr_t)hdata) & 1u) != 1u)
        FAILF("datafile handle %p does not have low bit set", (void *)hdata);
    if (!FreeLibrary(hdata))
        FAILF("FreeLibrary(datafile handle) err=%lu", (unsigned long)GetLastError());

    printf("PASS " NAME "\n");
    return 0;
}
