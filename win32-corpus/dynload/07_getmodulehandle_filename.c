/*
 * Test: 07_getmodulehandle_filename
 *
 * Purpose: GetModuleHandleW(NULL) returns the executable's own module, which
 *   GetModuleFileNameW reports as an existing .exe. A too-small buffer is
 *   truncated, NUL-terminated and reports ERROR_INSUFFICIENT_BUFFER. A missing
 *   module name returns NULL with ERROR_MOD_NOT_FOUND. ntdll exports used by
 *   curl's Windows version probe are present.
 *
 * APIs: GetModuleHandleW, GetModuleHandleA, GetModuleFileNameW, GetFileAttributesW,
 *   GetProcAddress (ntdll), LoadLibraryW
 *
 * Success:
 *   - GetModuleHandleW(NULL) == GetModuleHandleA(NULL) != NULL.
 *   - GetModuleFileNameW(NULL) returns n > 0, the path ends in .exe, and
 *     GetFileAttributesW on that path is not INVALID_FILE_ATTRIBUTES.
 *   - GetModuleFileNameW(exe handle, ...) returns the same string as (NULL).
 *   - GetModuleFileNameW(NULL, buf, 4) returns 4, sets ERROR_INSUFFICIENT_BUFFER
 *     (122), and buf[3] == 0.
 *   - GetModuleHandleW(L"tc_no_such_module_07.dll") == NULL with error 126.
 *   - ntdll.dll (via LoadLibraryW) exports RtlVerifyVersionInfo, the symbol
 *     lib/curlx/version_win32.c:58 resolves on the GetModuleHandle path.
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

#define NAME "getmodulehandle_filename"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

int main(void)
{
    HMODULE self_w, self_a, ntdll;
    wchar_t full[MAX_PATH];
    wchar_t again[MAX_PATH];
    wchar_t small[4];
    DWORD n, n2;
    size_t len;

    self_w = GetModuleHandleW(NULL);
    self_a = GetModuleHandleA(NULL);
    if (!self_w || self_w != self_a)
        FAILF("GetModuleHandle(NULL) W=%p A=%p err=%lu", (void *)self_w, (void *)self_a,
              (unsigned long)GetLastError());

    n = GetModuleFileNameW(NULL, full, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        FAILF("GetModuleFileNameW(NULL) n=%lu err=%lu", (unsigned long)n, (unsigned long)GetLastError());
    len = wcslen(full);
    if (len < 4 || _wcsicmp(full + len - 4, L".exe") != 0)
        FAILF("exe path '%ls' does not end in .exe", full);
    if (GetFileAttributesW(full) == INVALID_FILE_ATTRIBUTES)
        FAILF("exe path '%ls' does not exist (err=%lu)", full, (unsigned long)GetLastError());

    n2 = GetModuleFileNameW(self_w, again, MAX_PATH);
    if (n2 != n || wcscmp(full, again) != 0)
        FAILF("GetModuleFileNameW(handle) '%ls' differs from NULL form '%ls'", again, full);

    /* Truncation contract. The buffer is sentinel-filled so the NUL check
     * reads what the call wrote, not stack garbage. */
    {
        size_t i;
        for (i = 0; i < 4; i++)
            small[i] = (wchar_t)0xFFFF;
        SetLastError(0);
        n = GetModuleFileNameW(NULL, small, 4);
        if (n != 4)
            FAILF("truncated GetModuleFileNameW returned %lu, expected 4", (unsigned long)n);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            FAILF("truncated GetModuleFileNameW: expected ERROR_INSUFFICIENT_BUFFER(122) got %lu",
                  (unsigned long)GetLastError());
        /* Windows NUL-terminates the truncated result (verified on Win10 22H2;
         * wine leaves it unterminated, a known wine gap). */
        if (small[3] != L'\0')
            FAILF("truncated buffer not NUL-terminated");
        if (small[0] == 0xFFFF || wcslen(small) != 3)
            FAILF("truncated buffer content wrong (len %lu)", (unsigned long)wcslen(small));
    }

    /* Missing module by name. */
    SetLastError(0);
    if (GetModuleHandleW(L"tc_no_such_module_07.dll") != NULL)
        FAILF("GetModuleHandleW found a nonexistent module");
    if (GetLastError() != ERROR_MOD_NOT_FOUND)
        FAILF("nonexistent GetModuleHandleW: expected ERROR_MOD_NOT_FOUND(126) got %lu",
              (unsigned long)GetLastError());

    /* ntdll export used by curl's Windows version detection. */
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        FAILF("GetModuleHandleW(ntdll.dll) err=%lu", (unsigned long)GetLastError());
    if (!GetProcAddress(ntdll, "RtlVerifyVersionInfo"))
        FAILF("ntdll!RtlVerifyVersionInfo not exported err=%lu", (unsigned long)GetLastError());

    printf("PASS " NAME "\n");
    return 0;
}
