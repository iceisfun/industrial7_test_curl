/*
 * Test: 16_multibyte_widechar_contract
 *
 * Purpose: MultiByteToWideChar / WideCharToMultiByte behaviour curl's Windows
 *   unicode path (curlx_convert_UTF8_to_wchar, curlx_convert_wchar_to_UTF8)
 *   depends on: size query, strictness flags, invalid-input handling.
 *   Probed on Win10 22H2 (ACP 1252, OEM 437).
 *
 * Success:
 *   - CP_UTF8 "h\xc3\xa9llo" with cch -1: size query 6, conversion 6.
 *   - a 3-wchar buffer for "hello" returns 0 with ERROR_INSUFFICIENT_BUFFER (122).
 *   - cch 5 gives 5 and does not NUL-terminate; cch 0 gives 0 with error 87.
 *   - invalid byte 0xFF: flags 0 gives 4 with U+FFFD as the third wchar;
 *     MB_ERR_INVALID_CHARS gives 0 with ERROR_NO_UNICODE_TRANSLATION (1113).
 *   - encoded surrogate (ED A0 80) and overlong (C0 80): 0 flags -> U+FFFD
 *     replacement (3 chars incl NUL for the surrogate); MB_ERR_INVALID_CHARS
 *     -> 0 with 1113.
 *   - U+1F600 (F0 9F 98 80) -> D83D DE00, 3 chars with NUL.
 *   - WideCharToMultiByte CP_UTF8 of a lone surrogate: WC_ERR_INVALID_CHARS
 *     -> 0 with 1113; flags 0 -> EF BF BD ("U+FFFD"), 5 bytes with NUL.
 *   - CP 1252 conversion of U+4E2D substitutes '?' and sets usedDefault.
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

#define NAME "multibyte_widechar_contract"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

int main(void)
{
    wchar_t w[16];
    char c[16];
    BOOL used = FALSE;
    int n;

    n = MultiByteToWideChar(CP_UTF8, 0, "h\xc3\xa9llo", -1, NULL, 0);
    if (n != 6) FAILF("size query %d, expected 6", n);
    n = MultiByteToWideChar(CP_UTF8, 0, "h\xc3\xa9llo", -1, w, 16);
    if (n != 6 || w[1] != 0xE9 || w[5] != 0) FAILF("conversion n=%d", n);

    SetLastError(0);
    n = MultiByteToWideChar(CP_UTF8, 0, "hello", -1, w, 3);
    if (n != 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        FAILF("small buffer n=%d err=%lu, expected 0/122", n, (unsigned long)GetLastError());

    w[5] = 0x1234;
    n = MultiByteToWideChar(CP_UTF8, 0, "hello", 5, w, 16);
    if (n != 5 || w[5] != 0x1234) FAILF("cch=5 n=%d w5=%x", n, w[5]);
    SetLastError(0);
    n = MultiByteToWideChar(CP_UTF8, 0, "", 0, w, 16);
    if (n != 0 || GetLastError() != ERROR_INVALID_PARAMETER)
        FAILF("cch=0 n=%d err=%lu, expected 0/87", n, (unsigned long)GetLastError());

    SetLastError(0);
    n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, "ab\xff", -1, w, 16);
    if (n != 0 || GetLastError() != ERROR_NO_UNICODE_TRANSLATION)
        FAILF("0xFF strict n=%d err=%lu, expected 0/1113", n, (unsigned long)GetLastError());
    n = MultiByteToWideChar(CP_UTF8, 0, "ab\xff", -1, w, 16);
    if (n != 4 || w[2] != 0xFFFD) FAILF("0xFF lenient n=%d w2=%x", n, w[2]);

    n = MultiByteToWideChar(CP_UTF8, 0, "\xed\xa0\x80", -1, w, 16);
    if (n != 3 || w[0] != 0xFFFD) FAILF("surrogate lenient n=%d w0=%x", n, w[0]);
    SetLastError(0);
    n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, "\xed\xa0\x80", -1, w, 16);
    if (n != 0 || GetLastError() != ERROR_NO_UNICODE_TRANSLATION)
        FAILF("surrogate strict n=%d err=%lu", n, (unsigned long)GetLastError());
    SetLastError(0);
    n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, "\xc0\x80", -1, w, 16);
    if (n != 0 || GetLastError() != ERROR_NO_UNICODE_TRANSLATION)
        FAILF("overlong strict n=%d err=%lu", n, (unsigned long)GetLastError());

    n = MultiByteToWideChar(CP_UTF8, 0, "\xf0\x9f\x98\x80", -1, w, 16);
    if (n != 3 || w[0] != 0xD83D || w[1] != 0xDE00) FAILF("astral n=%d %x %x", n, w[0], w[1]);

    SetLastError(0);
    n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, L"a\xd800", -1, c, 16, NULL, NULL);
    if (n != 0 || GetLastError() != ERROR_NO_UNICODE_TRANSLATION)
        FAILF("lone surrogate strict n=%d err=%lu", n, (unsigned long)GetLastError());
    n = WideCharToMultiByte(CP_UTF8, 0, L"a\xd800", -1, c, 16, NULL, NULL);
    if (n != 5 || (unsigned char)c[1] != 0xEF || (unsigned char)c[2] != 0xBF || (unsigned char)c[3] != 0xBD)
        FAILF("lone surrogate lenient n=%d", n);

    n = WideCharToMultiByte(1252, 0, L"a\x4e2d", -1, c, 16, NULL, &used);
    if (n != 3 || !used || c[1] != '?') FAILF("cp1252 n=%d used=%d c1=%02x", n, used, (unsigned char)c[1]);

    printf("PASS " NAME "\n");
    return 0;
}
