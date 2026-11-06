/*
 * Test: 15_getenvironmentvariable_contract
 *
 * Purpose: the GetEnvironmentVariable contract curl's curlx_getenv() relies on
 *   (size query, truncation, missing vs empty). Probed on Win10 22H2.
 *
 * Success (variable TC_PROBE_ENV_15, set to "abc" via SetEnvironmentVariableW):
 *   - size query (NULL, 0) returns 4 (length + NUL).
 *   - buffer of 3 returns 4 (required size), buffer untouched semantics not
 *     checked; buffer of 4 returns 3 and holds "abc".
 *   - lookup is case-insensitive (set lower-case name, read upper-case).
 *   - empty value: returns 0 with GetLastError() == 0 (found, empty); size
 *     query returns 1.
 *   - missing variable: returns 0 with ERROR_ENVVAR_NOT_FOUND (203).
 *   - a name containing '=' is rejected by SetEnvironmentVariableW with
 *     ERROR_INVALID_PARAMETER (87).
 *   - USERPROFILE (set by the logon) is present and its size query is > 3.
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

#define NAME "getenvironmentvariable_contract"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

int main(void)
{
    wchar_t b[64];
    DWORD n;

    SetEnvironmentVariableW(L"TC_PROBE_ENV_15", NULL);
    SetLastError(0);
    n = GetEnvironmentVariableW(L"TC_PROBE_ENV_15", b, 64);
    if (n != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND)
        FAILF("missing: n=%lu err=%lu, expected 0/203", (unsigned long)n, (unsigned long)GetLastError());

    if (!SetEnvironmentVariableW(L"TC_PROBE_ENV_15", L"abc"))
        FAILF("SetEnvironmentVariableW err=%lu", (unsigned long)GetLastError());
    n = GetEnvironmentVariableW(L"TC_PROBE_ENV_15", NULL, 0);
    if (n != 4)
        FAILF("size query returned %lu, expected 4", (unsigned long)n);
    n = GetEnvironmentVariableW(L"TC_PROBE_ENV_15", b, 3);
    if (n != 4)
        FAILF("3-char buffer returned %lu, expected required size 4", (unsigned long)n);
    memset(b, 0, sizeof b);
    n = GetEnvironmentVariableW(L"TC_PROBE_ENV_15", b, 4);
    if (n != 3 || wcscmp(b, L"abc") != 0)
        FAILF("exact buffer: n=%lu value '%ls'", (unsigned long)n, b);

    SetEnvironmentVariableW(L"tc_probe_env_15", L"lower");
    n = GetEnvironmentVariableW(L"TC_PROBE_ENV_15", b, 64);
    if (n != 5 || wcscmp(b, L"lower") != 0)
        FAILF("case-insensitive lookup: n=%lu value '%ls'", (unsigned long)n, b);

    SetEnvironmentVariableW(L"TC_PROBE_ENV_15", L"");
    SetLastError(0);
    n = GetEnvironmentVariableW(L"TC_PROBE_ENV_15", b, 64);
    if (n != 0 || GetLastError() != 0)
        FAILF("empty value: n=%lu err=%lu, expected 0/0", (unsigned long)n, (unsigned long)GetLastError());
    n = GetEnvironmentVariableW(L"TC_PROBE_ENV_15", NULL, 0);
    if (n != 1)
        FAILF("empty value size query returned %lu, expected 1", (unsigned long)n);

    SetLastError(0);
    if (SetEnvironmentVariableW(L"A=B", L"x") || GetLastError() != ERROR_INVALID_PARAMETER)
        FAILF("name with '=': err=%lu, expected failure with 87", (unsigned long)GetLastError());

    SetEnvironmentVariableW(L"TC_PROBE_ENV_15", NULL);
    n = GetEnvironmentVariableA("USERPROFILE", NULL, 0);
    if (n <= 3)
        FAILF("USERPROFILE size query returned %lu", (unsigned long)n);

    printf("PASS " NAME "\n");
    return 0;
}
