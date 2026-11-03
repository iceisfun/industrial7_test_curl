/*
 * Test: 03_loadlibraryex_default_dirs_missing
 *
 * Purpose: LoadLibraryExW with LOAD_LIBRARY_SEARCH_DEFAULT_DIRS resolves a
 *   system DLL by bare name (ws2_32.dll), and fails cleanly for a DLL that
 *   does not exist anywhere, reporting ERROR_MOD_NOT_FOUND. A missing optional
 *   DLL must be an ordinary error that the caller can branch on, not a crash.
 *
 * APIs: LoadLibraryExW (LOAD_LIBRARY_SEARCH_DEFAULT_DIRS), GetModuleFileNameW,
 *   GetModuleHandleW, FreeLibrary, GetSystemDirectoryW
 *
 * Success:
 *   - LoadLibraryExW(L"ws2_32.dll", NULL, DEFAULT_DIRS) != NULL, and the
 *     module path ends in ws2_32.dll.
 *   - LoadLibraryExW(L"tc_no_such_module_03.dll", ...) == NULL with
 *     GetLastError() == ERROR_MOD_NOT_FOUND (126).
 *   - LoadLibraryExW of an absolute path inside the system directory that does
 *     not exist == NULL with error ERROR_MOD_NOT_FOUND or ERROR_FILE_NOT_FOUND.
 *   - GetModuleHandleW of the missing name returns NULL and does not load it.
 *
 * Source reference: none in curl (curl links ws2_32/bcrypt/secur32 statically
 *   and never calls LoadLibrary). A loader-based build would need the
 *   failing-soft contract checked here; see
 *   11_optional_features_ws2_dnsapi_bcrypt_secur32.c.
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

#define NAME "loadlibraryex_default_dirs_missing"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

int main(void)
{
    HMODULE h;
    wchar_t sysdir[MAX_PATH];
    wchar_t path[MAX_PATH];
    wchar_t abs_missing[MAX_PATH + 64];
    DWORD err, n;

    /* 1. System DLL by bare name under DEFAULT_DIRS. */
    h = LoadLibraryExW(L"ws2_32.dll", NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!h)
        FAILF("LoadLibraryExW(ws2_32.dll, DEFAULT_DIRS) err=%lu", (unsigned long)GetLastError());

    n = GetModuleFileNameW(h, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        FAILF("GetModuleFileNameW n=%lu err=%lu", (unsigned long)n, (unsigned long)GetLastError());
    if (_wcsicmp(path + wcslen(path) - 10, L"ws2_32.dll") != 0)
        FAILF("module path '%ls' does not end in ws2_32.dll", path);

    if (GetModuleHandleW(L"ws2_32.dll") != h)
        FAILF("GetModuleHandleW(ws2_32.dll) differs from LoadLibraryExW handle");

    if (!FreeLibrary(h))
        FAILF("FreeLibrary(ws2_32) err=%lu", (unsigned long)GetLastError());

    /* 2. Bare name that exists nowhere. */
    SetLastError(0);
    h = LoadLibraryExW(L"tc_no_such_module_03.dll", NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (h != NULL) {
        FreeLibrary(h);
        FAILF("LoadLibraryExW of a nonexistent DLL unexpectedly succeeded");
    }
    err = GetLastError();
    if (err != ERROR_MOD_NOT_FOUND)
        FAILF("nonexistent DLL: expected ERROR_MOD_NOT_FOUND(126) got %lu", (unsigned long)err);

    if (GetModuleHandleW(L"tc_no_such_module_03.dll") != NULL)
        FAILF("GetModuleHandleW found the nonexistent module");

    /* 3. Absolute path to a file that does not exist. */
    n = GetSystemDirectoryW(sysdir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        FAILF("GetSystemDirectoryW err=%lu", (unsigned long)GetLastError());
    if (swprintf(abs_missing, MAX_PATH + 64, L"%ls\\tc_no_such_module_03.dll", sysdir) < 0)
        FAILF("swprintf failed");

    SetLastError(0);
    h = LoadLibraryExW(abs_missing, NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (h != NULL) {
        FreeLibrary(h);
        FAILF("absolute missing path unexpectedly loaded");
    }
    err = GetLastError();
    if (err != ERROR_MOD_NOT_FOUND && err != ERROR_FILE_NOT_FOUND)
        FAILF("absolute missing path: unexpected error %lu", (unsigned long)err);

    printf("PASS " NAME "\n");
    return 0;
}
