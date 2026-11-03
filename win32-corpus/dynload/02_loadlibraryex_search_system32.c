/*
 * Test: 02_loadlibraryex_search_system32
 *
 * Purpose: LoadLibraryExW with LOAD_LIBRARY_SEARCH_SYSTEM32 loads a DLL by
 *   bare name from the system directory, and the loaded module really lives
 *   there. Exports used afterwards must resolve. This is the hardened loading
 *   mode a loader-based build would use for optional system DLLs (curl itself
 *   does not call LoadLibrary today).
 *
 * APIs: GetSystemDirectoryW, LoadLibraryExW (LOAD_LIBRARY_SEARCH_SYSTEM32),
 *   GetModuleFileNameW, GetProcAddress, FreeLibrary, _wcsnicmp
 *
 * Success: LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)
 *   returns a handle; GetModuleFileNameW gives a path that starts with the
 *   system directory and ends with version.dll; GetFileVersionInfoSizeW and
 *   GetFileVersionInfoW resolve; a second load returns the same handle.
 *
 * Source reference: none direct in curl (curl never calls LoadLibrary); this
 *   mirrors the hardened-load pattern for optional system DLLs (see the
 *   11_optional_features test).
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
#include <wchar.h>

#define NAME "loadlibraryex_search_system32"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

typedef DWORD (WINAPI *get_ver_size_fn)(LPCWSTR, LPDWORD);
typedef BOOL (WINAPI *get_ver_fn)(LPCWSTR, DWORD, DWORD, LPVOID);

int main(void)
{
    wchar_t sysdir[MAX_PATH];
    wchar_t path[MAX_PATH];
    wchar_t probe[MAX_PATH + 32];
    HMODULE h, h2;
    DWORD n, got;
    FARPROC p_size, p_get;
    get_ver_size_fn ver_size;
    get_ver_fn ver_get;

    n = GetSystemDirectoryW(sysdir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        FAILF("GetSystemDirectoryW n=%lu err=%lu", (unsigned long)n, (unsigned long)GetLastError());

    h = LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!h)
        FAILF("LoadLibraryExW(version.dll, SEARCH_SYSTEM32) err=%lu", (unsigned long)GetLastError());

    got = GetModuleFileNameW(h, path, MAX_PATH);
    if (got == 0 || got >= MAX_PATH)
        FAILF("GetModuleFileNameW got=%lu err=%lu", (unsigned long)got, (unsigned long)GetLastError());

    if (_wcsnicmp(path, sysdir, wcslen(sysdir)) != 0)
        FAILF("module path '%ls' is not under system dir '%ls'", path, sysdir);

    if (_wcsicmp(path + wcslen(path) - 11, L"version.dll") != 0)
        FAILF("module path '%ls' does not end in version.dll", path);

    p_size = GetProcAddress(h, "GetFileVersionInfoSizeW");
    p_get = GetProcAddress(h, "GetFileVersionInfoW");
    if (!p_size || !p_get)
        FAILF("GetProcAddress version exports err=%lu", (unsigned long)GetLastError());

    ver_size = (get_ver_size_fn)(void *)p_size;
    ver_get = (get_ver_fn)(void *)p_get;

    /* Ask for the version info of a file that certainly does not exist: must
     * return 0 and set a non-zero error, proving the export really runs. */
    SetLastError(0);
    if (ver_size(L"tc_no_such_file_for_version.dll", NULL) != 0)
        FAILF("GetFileVersionInfoSizeW of missing file returned non-zero");
    if (GetLastError() == 0)
        FAILF("GetFileVersionInfoSizeW of missing file left GetLastError()==0");

    /* Same path through the call pipeline: version of a real file in the system dir. */
    if (swprintf(probe, MAX_PATH + 32, L"%ls\\version.dll", sysdir) < 0)
        FAILF("swprintf failed");
    {
        DWORD handle_dummy = 0;
        DWORD sz = ver_size(probe, &handle_dummy);
        BYTE *buf;
        if (sz == 0)
            FAILF("GetFileVersionInfoSizeW(system version.dll) returned 0 err=%lu",
                  (unsigned long)GetLastError());
        buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sz);
        if (!buf)
            FAILF("HeapAlloc(%lu) failed", (unsigned long)sz);
        if (!ver_get(probe, 0, sz, buf)) {
            HeapFree(GetProcessHeap(), 0, buf);
            FAILF("GetFileVersionInfoW err=%lu", (unsigned long)GetLastError());
        }
        HeapFree(GetProcessHeap(), 0, buf);
    }

    h2 = LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (h2 != h)
        FAILF("second load gave %p, expected %p", (void *)h2, (void *)h);

    if (!FreeLibrary(h2) || !FreeLibrary(h))
        FAILF("FreeLibrary err=%lu", (unsigned long)GetLastError());

    printf("PASS " NAME "\n");
    return 0;
}
