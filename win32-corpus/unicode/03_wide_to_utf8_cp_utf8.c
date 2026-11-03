/*
 * Test: 03_wide_to_utf8_cp_utf8
 *
 * Purpose: exercise WideCharToMultiByte(CP_UTF8) as curl uses it to turn
 *          UTF-16 strings (GetEnvironmentVariableW, FindFirstFileW names,
 *          GetFullPathNameW results) back into UTF-8: a size query with
 *          cbMultiByte = 0 and a conversion with cchWideChar = -1 so the
 *          terminator is included in the output. Also covers lone surrogates
 *          with and without WC_ERR_INVALID_CHARS, and a too-small buffer.
 *
 * APIs:    WideCharToMultiByte, SetLastError, GetLastError
 *
 * Success: - L"hé€" (-1) has size 7 (h=1, e-acute=2, euro=3,
 *            terminator=1) and converts to 68 C3 A9 E2 82 AC 00
 *          - L"😀" (-1) converts to F0 9F 98 80 00, size 5
 *          - a lone high surrogate with WC_ERR_INVALID_CHARS fails with
 *            ERROR_NO_UNICODE_TRANSLATION (1113) and returns 0
 *          - the same lone surrogate without the flag becomes EF BF BD
 *            (U+FFFD) and the conversion succeeds
 *          - a too-small output buffer returns 0 with
 *            ERROR_INSUFFICIENT_BUFFER (122)
 *          - explicit length (cchWideChar = 1) does not add a terminator
 *
 * Source:  lib/curlx/multibyte.c:56-76 (curlx_convert_wchar_to_UTF8) uses
 *          size-query-then-convert with cchWideChar = -1 and flags 0.
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

#define NAME "wide_to_utf8_cp_utf8"

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if(!(cond)) {                                                          \
      printf("FAIL %s: ", NAME);                                           \
      printf(__VA_ARGS__);                                                 \
      printf(" [line %d, GetLastError=%lu]\n", __LINE__,                   \
             (unsigned long)GetLastError());                               \
      rc = 1;                                                              \
      goto out;                                                            \
    }                                                                      \
  } while(0)

static int bytes_equal(const char *got, int got_len,
                       const unsigned char *want, int want_len)
{
  return got_len == want_len && memcmp(got, want, (size_t)want_len) == 0;
}

int main(void)
{
  int rc = 0;
  char out8[32];
  int need, n;
  static const wchar_t w_mix[] = L"hé€";
  static const wchar_t w_emoji[] = L"😀";
  static const wchar_t w_lone[] = L"x\xD83Dy";
  static const unsigned char want_mix[] = {
    0x68, 0xC3, 0xA9, 0xE2, 0x82, 0xAC, 0x00
  };
  static const unsigned char want_emoji[] = { 0xF0, 0x9F, 0x98, 0x80, 0x00 };
  static const unsigned char want_repl[] = {
    0x78, 0xEF, 0xBF, 0xBD, 0x79, 0x00
  };

  /* 1. size query including terminator */
  need = WideCharToMultiByte(CP_UTF8, 0, w_mix, -1, NULL, 0, NULL, NULL);
  CHECK(need == 7, "mix size returned %d, expected 7", need);

  /* 2. conversion into exact buffer */
  memset(out8, 0x55, sizeof(out8));
  n = WideCharToMultiByte(CP_UTF8, 0, w_mix, -1, out8, need, NULL, NULL);
  CHECK(n == 7, "mix conversion returned %d, expected 7", n);
  CHECK(bytes_equal(out8, n, want_mix, sizeof(want_mix)),
        "mix bytes differ from UTF-8 of U+0068 U+00E9 U+20AC");

  /* 3. surrogate pair becomes one 4-byte sequence */
  need = WideCharToMultiByte(CP_UTF8, 0, w_emoji, -1, NULL, 0, NULL, NULL);
  CHECK(need == 5, "emoji size returned %d, expected 5", need);
  n = WideCharToMultiByte(CP_UTF8, 0, w_emoji, -1, out8, need, NULL, NULL);
  CHECK(n == 5, "emoji conversion returned %d, expected 5", n);
  CHECK(bytes_equal(out8, n, want_emoji, sizeof(want_emoji)),
        "emoji bytes differ from F0 9F 98 80 00");

  /* 4. lone high surrogate, strict mode must fail */
  SetLastError(0);
  n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w_lone, -1,
                          NULL, 0, NULL, NULL);
  CHECK(n == 0, "strict lone surrogate size returned %d, expected 0", n);
  CHECK(GetLastError() == ERROR_NO_UNICODE_TRANSLATION,
        "strict lone surrogate error %lu, expected 1113",
        (unsigned long)GetLastError());

  /* 5. lone high surrogate, lenient mode substitutes U+FFFD */
  need = WideCharToMultiByte(CP_UTF8, 0, w_lone, -1, NULL, 0, NULL, NULL);
  CHECK(need == 6, "lenient lone surrogate size returned %d, expected 6",
        need);
  n = WideCharToMultiByte(CP_UTF8, 0, w_lone, -1, out8, need, NULL, NULL);
  CHECK(n == 6, "lenient lone surrogate conversion returned %d", n);
  CHECK(bytes_equal(out8, n, want_repl, sizeof(want_repl)),
        "lenient lone surrogate bytes differ from 78 EF BF BD 79 00");

  /* 6. output buffer one byte short */
  SetLastError(0);
  n = WideCharToMultiByte(CP_UTF8, 0, w_mix, -1, out8, 6, NULL, NULL);
  CHECK(n == 0, "short buffer returned %d, expected 0", n);
  CHECK(GetLastError() == ERROR_INSUFFICIENT_BUFFER,
        "short buffer error %lu, expected 122",
        (unsigned long)GetLastError());

  /* 7. explicit length: one code unit, no terminator appended. Pre-filled
   *    with a sentinel so an appended NUL at out8[1] would be visible. */
  memset(out8, 0x55, sizeof(out8));
  n = WideCharToMultiByte(CP_UTF8, 0, w_mix, 1, out8, sizeof(out8),
                          NULL, NULL);
  CHECK(n == 1, "explicit length returned %d, expected 1", n);
  CHECK(out8[0] == 0x68 && out8[1] == 0x55,
        "explicit length bytes wrong: %02x %02x",
        (unsigned)(unsigned char)out8[0], (unsigned)(unsigned char)out8[1]);

  printf("PASS %s\n", NAME);

out:
  return rc;
}
