/*
 * Test: 15_loadlibrary_search_flag_errors
 *
 * Purpose: the LoadLibraryEx behaviours curl's Curl_load_library() depends on
 *   when it loads system DLLs (secur32, ws2_32, advapi32 ...): the search
 *   flag combinations that resolve a system DLL, the absolute-path form built
 *   from GetSystemDirectory + LOAD_WITH_ALTERED_SEARCH_PATH, and the exact
 *   error codes for the failure forms. All values probed on Win10 22H2
 *   (build 19045), std and adm identical.
 *
 * Success:
 *   - ws2_32.dll loads, and yields the same HMODULE, with each of
 *     LOAD_LIBRARY_SEARCH_DEFAULT_DIRS (absolute system path),
 *     SEARCH_SYSTEM32|SEARCH_USER_DIRS, SEARCH_SYSTEM32|LOAD_WITH_ALTERED_SEARCH_PATH,
 *     and a relative "..\\System32\\ws2_32.dll" with SEARCH_SYSTEM32.
 *   - GetSystemDirectoryA + "\\ws2_32.dll" with LOAD_WITH_ALTERED_SEARCH_PATH
 *     (curl's form) returns the module GetModuleHandleW(ws2_32.dll) reports.
 *   - missing DLL: NULL with ERROR_MOD_NOT_FOUND (126) for a bare name and an
 *     absolute path, with flags 0 and with SEARCH_DEFAULT_DIRS.
 *   - hFile != NULL or an undefined flag bit (0x80000000): NULL with
 *     ERROR_INVALID_PARAMETER (87).
 *   - secur32.dll, sspicli.dll and security.dll all load with SEARCH_SYSTEM32.
 *
 * Source reference: curl lib/curl_sspi.c Curl_load_library; lib/curlx/version_win32.c.
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

#define NAME "loadlibrary_search_flag_errors"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static int expect_fail(const wchar_t *what, const wchar_t *dll, HANDLE hfile, DWORD flags, DWORD want)
{
    HMODULE h;
    SetLastError(0);
    h = LoadLibraryExW(dll, hfile, flags);
    if (h) {
        FreeLibrary(h);
        printf("FAIL " NAME ": %ls unexpectedly loaded\n", what);
        return 1;
    }
    if (GetLastError() != want) {
        printf("FAIL " NAME ": %ls: expected error %lu got %lu\n", what, (unsigned long)want,
               (unsigned long)GetLastError());
        return 1;
    }
    return 0;
}

int main(void)
{
    HMODULE ref, h;
    char sysdirA[MAX_PATH], pathA[MAX_PATH + 32];
    wchar_t sysdirW[MAX_PATH], pathW[MAX_PATH + 32];
    UINT n;
    unsigned i;
    struct { const wchar_t *what; const wchar_t *name; DWORD flags; } ok_forms[4];
    const char *sysdlls[3] = { "secur32.dll", "sspicli.dll", "security.dll" };

    ref = LoadLibraryExW(L"ws2_32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!ref)
        FAILF("reference load err=%lu", (unsigned long)GetLastError());

    n = GetSystemDirectoryW(sysdirW, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        FAILF("GetSystemDirectoryW");
    swprintf(pathW, MAX_PATH + 32, L"%ls\\ws2_32.dll", sysdirW);

    ok_forms[0].what = L"absolute + DEFAULT_DIRS";  ok_forms[0].name = pathW;
    ok_forms[0].flags = LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;
    ok_forms[1].what = L"SYSTEM32|USER_DIRS";       ok_forms[1].name = L"ws2_32.dll";
    ok_forms[1].flags = LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS;
    ok_forms[2].what = L"SYSTEM32|ALTERED";         ok_forms[2].name = L"ws2_32.dll";
    ok_forms[2].flags = LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_WITH_ALTERED_SEARCH_PATH;
    ok_forms[3].what = L"relative ..\\System32";    ok_forms[3].name = L"..\\System32\\ws2_32.dll";
    ok_forms[3].flags = LOAD_LIBRARY_SEARCH_SYSTEM32;
    for (i = 0; i < 4; i++) {
        SetLastError(0);
        h = LoadLibraryExW(ok_forms[i].name, NULL, ok_forms[i].flags);
        if (!h)
            FAILF("%ls: load failed err=%lu", ok_forms[i].what, (unsigned long)GetLastError());
        if (h != ref)
            FAILF("%ls: handle %p differs from reference %p", ok_forms[i].what, (void *)h, (void *)ref);
        FreeLibrary(h);
    }

    /* curl's own form: GetSystemDirectoryA + "\\" + name, ALTERED_SEARCH_PATH. */
    n = GetSystemDirectoryA(sysdirA, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        FAILF("GetSystemDirectoryA");
    snprintf(pathA, sizeof pathA, "%s\\ws2_32.dll", sysdirA);
    h = LoadLibraryExA(pathA, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!h)
        FAILF("curl form load of '%s' err=%lu", pathA, (unsigned long)GetLastError());
    if (h != GetModuleHandleW(L"ws2_32.dll"))
        FAILF("curl form handle differs from GetModuleHandleW");
    FreeLibrary(h);

    for (i = 0; i < 3; i++) {
        h = LoadLibraryExA(sysdlls[i], NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!h)
            FAILF("%s err=%lu", sysdlls[i], (unsigned long)GetLastError());
        FreeLibrary(h);
    }

    if (expect_fail(L"missing bare flags=0", L"tc_no_such_15.dll", NULL, 0, ERROR_MOD_NOT_FOUND))
        return 1;
    if (expect_fail(L"missing bare DEFAULT_DIRS", L"tc_no_such_15.dll", NULL,
                    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, ERROR_MOD_NOT_FOUND))
        return 1;
    if (expect_fail(L"missing absolute flags=0", L"C:\\tc_no_such_15.dll", NULL, 0, ERROR_MOD_NOT_FOUND))
        return 1;
    if (expect_fail(L"missing absolute DEFAULT_DIRS", L"C:\\tc_no_such_15.dll", NULL,
                    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, ERROR_MOD_NOT_FOUND))
        return 1;
    if (expect_fail(L"hFile != NULL", L"ws2_32.dll", (HANDLE)1, 0, ERROR_INVALID_PARAMETER))
        return 1;
    if (expect_fail(L"undefined flag bit", L"ws2_32.dll", NULL, 0x80000000UL, ERROR_INVALID_PARAMETER))
        return 1;

    FreeLibrary(ref);
    printf("PASS " NAME "\n");
    return 0;
}
