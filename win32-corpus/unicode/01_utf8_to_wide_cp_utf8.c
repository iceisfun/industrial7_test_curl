/*
 * Test: 01_utf8_to_wide_cp_utf8
 *
 * Purpose: exercise MultiByteToWideChar(CP_UTF8) the way curl converts
 *          UTF-8 path and URL strings to UTF-16 for the W APIs:
 *          a size query (cchWideChar = 0) followed by a conversion into a
 *          buffer of exactly the reported size, with MB_ERR_INVALID_CHARS.
 *
 * APIs:    MultiByteToWideChar, SetLastError, GetLastError
 *
 * Success: - size query for "h\xc3\xa9" (NUL terminated, -1) returns 3
 *            (2 code units plus the terminator)
 *          - conversion yields L"hé" followed by NUL
 *          - U+20AC (3 UTF-8 bytes) becomes the single unit 0x20AC
 *          - U+1F600 (4 UTF-8 bytes) becomes the surrogate pair D83D DE00
 *          - an explicit byte length (no terminator in input) produces no
 *            terminator in output
 *          - an output buffer that is one unit too small returns 0 with
 *            ERROR_INSUFFICIENT_BUFFER (122)
 *          - the empty string with -1 returns 1 (only the terminator)
 *
 * Source:  lib/curlx/multibyte.c:34-54 (curlx_convert_UTF8_to_wchar) uses
 *          exactly this size-query-then-convert sequence with
 *          MB_ERR_INVALID_CHARS.
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

#define NAME "utf8_to_wide_cp_utf8"

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

int main(void)
{
  int rc = 0;
  const char *u8_e_acute = "h\xc3\xa9";          /* "hé" */
  const char *u8_euro = "\xe2\x82\xac";          /* U+20AC */
  const char *u8_emoji = "\xf0\x9f\x98\x80";     /* U+1F600 */
  wchar_t buf[16];
  int need, n;

  /* 1. size query, NUL terminated input */
  need = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                             u8_e_acute, -1, NULL, 0);
  CHECK(need == 3, "size query returned %d, expected 3", need);

  /* 2. conversion into exactly the sized buffer */
  memset(buf, 0xAA, sizeof(buf));
  n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                          u8_e_acute, -1, buf, need);
  CHECK(n == 3, "conversion returned %d, expected 3", n);
  CHECK(buf[0] == L'h', "buf[0]=0x%04x expected 'h'", (unsigned)buf[0]);
  CHECK(buf[1] == 0x00E9, "buf[1]=0x%04x expected 0x00E9",
        (unsigned)buf[1]);
  CHECK(buf[2] == 0, "buf[2]=0x%04x expected terminator",
        (unsigned)buf[2]);
  CHECK(wcslen(buf) == 2, "wcslen=%u expected 2", (unsigned)wcslen(buf));

  /* 3. BMP code point above ASCII, one unit */
  n = MultiByteToWideChar(CP_UTF8, 0, u8_euro, 3, buf, 16);
  CHECK(n == 1, "euro conversion returned %d, expected 1", n);
  CHECK(buf[0] == 0x20AC, "euro unit=0x%04x expected 0x20AC",
        (unsigned)buf[0]);

  /* 4. supplementary plane code point becomes a surrogate pair */
  n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, u8_emoji, 4,
                          buf, 16);
  CHECK(n == 2, "emoji conversion returned %d, expected 2", n);
  CHECK(buf[0] == 0xD83D && buf[1] == 0xDE00,
        "emoji units=0x%04x 0x%04x expected D83D DE00",
        (unsigned)buf[0], (unsigned)buf[1]);

  /* 5. explicit length without terminator: no NUL is appended. The buffer
   *    is pre-filled with a sentinel so that a written NUL at buf[2] is
   *    distinguishable from an untouched slot. */
  memset(buf, 0xAA, sizeof(buf));
  n = MultiByteToWideChar(CP_UTF8, 0, u8_e_acute, 3, buf, 16);
  CHECK(n == 2, "explicit-length conversion returned %d, expected 2", n);
  CHECK(buf[2] == 0xAAAA, "terminator or data written past units: 0x%04x",
        (unsigned)buf[2]);

  /* 6. size query for explicit length is 2, not 3 */
  need = MultiByteToWideChar(CP_UTF8, 0, u8_e_acute, 3, NULL, 0);
  CHECK(need == 2, "explicit-length size query returned %d, expected 2",
        need);

  /* 7. buffer one unit too small fails with ERROR_INSUFFICIENT_BUFFER */
  SetLastError(0);
  n = MultiByteToWideChar(CP_UTF8, 0, u8_e_acute, -1, buf, 2);
  CHECK(n == 0, "short buffer returned %d, expected 0", n);
  CHECK(GetLastError() == ERROR_INSUFFICIENT_BUFFER,
        "short buffer error %lu, expected 122",
        (unsigned long)GetLastError());

  /* 8. empty string with -1 yields just the terminator */
  n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, "", -1, NULL, 0);
  CHECK(n == 1, "empty string size returned %d, expected 1", n);

  printf("PASS %s\n", NAME);

out:
  return rc;
}
