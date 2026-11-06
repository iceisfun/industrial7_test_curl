/*
 * Test: 16_getmodulehandleex_flags
 *
 * Purpose: GetModuleHandleExW semantics used by loader code (find the module
 *   that contains an address, pin a module, probe without touching the
 *   refcount). Probed on Win10 22H2 (build 19045).
 *
 * Success:
 *   - FROM_ADDRESS|UNCHANGED_REFCOUNT with the address of GetTickCount64
 *     returns TRUE and the kernel32 handle (GetModuleHandleW(kernel32.dll)).
 *   - FROM_ADDRESS with address 8 returns FALSE, ERROR_MOD_NOT_FOUND (126).
 *   - a missing module name returns FALSE, handle NULL, error 126.
 *   - without UNCHANGED_REFCOUNT the refcount goes up: a module loaded once
 *     (version.dll), fetched with GetModuleHandleExW(0) and then freed once
 *     is still loaded; two FreeLibrary calls unload it (GetModuleHandleW
 *     then fails with 126).
 *   - GET_MODULE_HANDLE_EX_FLAG_PIN on a freshly loaded version.dll makes
 *     FreeLibrary calls no-ops: the module is still loaded afterwards.
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

#define NAME "getmodulehandleex_flags"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

int main(void)
{
    HMODULE m = NULL, k32, v, v2;
    BOOL r;

    k32 = GetModuleHandleW(L"kernel32.dll");
    r = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)(void *)&GetTickCount64, &m);
    if (!r || m != k32)
        FAILF("FROM_ADDRESS GetTickCount64 r=%d m=%p kernel32=%p", r, (void *)m, (void *)k32);

    m = (HMODULE)1;
    SetLastError(0);
    r = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)(ULONG_PTR)8, &m);
    if (r || GetLastError() != ERROR_MOD_NOT_FOUND)
        FAILF("FROM_ADDRESS 8: r=%d err=%lu, expected FALSE/126", r, (unsigned long)GetLastError());

    m = (HMODULE)1;
    SetLastError(0);
    r = GetModuleHandleExW(0, L"tc_no_such_16.dll", &m);
    if (r || m != NULL || GetLastError() != ERROR_MOD_NOT_FOUND)
        FAILF("missing module: r=%d m=%p err=%lu, expected FALSE/NULL/126", r, (void *)m,
              (unsigned long)GetLastError());

    /* refcount: load(1) + GetModuleHandleEx(2) ; free, still loaded ; free, gone */
    if (GetModuleHandleW(L"version.dll"))
        FAILF("version.dll already loaded; test precondition");
    v = LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!v)
        FAILF("load version.dll err=%lu", (unsigned long)GetLastError());
    if (!GetModuleHandleExW(0, L"version.dll", &v2) || v2 != v)
        FAILF("GetModuleHandleExW(0) failed");
    if (!FreeLibrary(v) || !GetModuleHandleW(L"version.dll"))
        FAILF("module gone after one FreeLibrary although GetModuleHandleExW added a reference");
    if (!FreeLibrary(v))
        FAILF("second FreeLibrary err=%lu", (unsigned long)GetLastError());
    SetLastError(0);
    if (GetModuleHandleW(L"version.dll") || GetLastError() != ERROR_MOD_NOT_FOUND)
        FAILF("version.dll still loaded after both references were released");

    /* PIN */
    v = LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!v || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN, L"version.dll", &v2) || v2 != v)
        FAILF("PIN failed err=%lu", (unsigned long)GetLastError());
    FreeLibrary(v);
    FreeLibrary(v);
    if (!GetModuleHandleW(L"version.dll"))
        FAILF("pinned module was unloaded");

    printf("PASS " NAME "\n");
    return 0;
}
