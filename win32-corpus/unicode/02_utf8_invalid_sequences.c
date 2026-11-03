/*
 * Test: 02_utf8_invalid_sequences
 *
 * Purpose: check how MultiByteToWideChar(CP_UTF8) treats malformed UTF-8,
 *          in both modes curl depends on:
 *          - MB_ERR_INVALID_CHARS set: malformed input must be rejected so
 *            that curl refuses to build a wide path from garbage bytes.
 *          - flags == 0: malformed bytes become U+FFFD and the call succeeds.
 *
 * APIs:    MultiByteToWideChar, SetLastError, GetLastError
 *
 * Success: - lone continuation byte 0x80, invalid lead byte 0xFF, overlong
 *            encoding C0 80 and a truncated 3-byte sequence E2 82 are each
 *            rejected with ERROR_NO_UNICODE_TRANSLATION (1113) when
 *            MB_ERR_INVALID_CHARS is set, and the size query returns 0
 *          - with flags == 0 the byte 0xFF in "a\xff" "b" becomes U+FFFD and
 *            the conversion returns 4 (a, U+FFFD, b, terminator)
 *          - with flags == 0 an isolated continuation byte converts to U+FFFD
 *          - a valid prefix followed by a truncated lead byte ("ok\xc3") still
 *            reports the failure for the whole string under MB_ERR_INVALID_CHARS
 *
 * Source:  lib/curlx/multibyte.c:34-54 (curlx_convert_UTF8_to_wchar) treats
 *          a zero size query as failure and returns NULL; this test pins the
 *          API behaviour that makes that path reachable.
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

#define NAME "utf8_invalid_sequences"

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

struct bad_case {
  const char *label;
  const char *bytes;
  int len;
};

static const struct bad_case strict_bad[] = {
  { "lone continuation", "\x80", 1 },
  { "invalid lead 0xFF", "\xff", 1 },
  { "overlong C0 80", "\xc0\x80", 2 },
  { "truncated E2 82", "\xe2\x82", 2 },
  { "valid then bad", "ok\xc3" , 3 },
};

int main(void)
{
  int rc = 0;
  size_t i;
  wchar_t buf[16];
  int n;

  for(i = 0; i < sizeof(strict_bad) / sizeof(strict_bad[0]); i++) {
    const struct bad_case *c = &strict_bad[i];

    SetLastError(0);
    n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            c->bytes, c->len, NULL, 0);
    CHECK(n == 0, "%s: size query returned %d, expected 0", c->label, n);
    CHECK(GetLastError() == ERROR_NO_UNICODE_TRANSLATION,
          "%s: error %lu, expected 1113", c->label,
          (unsigned long)GetLastError());

    SetLastError(0);
    n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            c->bytes, c->len, buf, 16);
    CHECK(n == 0, "%s: conversion returned %d, expected 0", c->label, n);
    CHECK(GetLastError() == ERROR_NO_UNICODE_TRANSLATION,
          "%s: conversion error %lu, expected 1113", c->label,
          (unsigned long)GetLastError());
  }

  /* lenient mode: 0xFF is replaced with U+FFFD, conversion succeeds */
  n = MultiByteToWideChar(CP_UTF8, 0, "a\xff" "b", -1, NULL, 0);
  CHECK(n == 4, "lenient size query returned %d, expected 4", n);

  /* sentinel fill so the terminator at buf[3] must really be written */
  memset(buf, 0xAA, sizeof(buf));
  n = MultiByteToWideChar(CP_UTF8, 0, "a\xff" "b", -1, buf, 16);
  CHECK(n == 4, "lenient conversion returned %d, expected 4", n);
  CHECK(buf[0] == L'a', "lenient buf[0]=0x%04x", (unsigned)buf[0]);
  CHECK(buf[1] == 0xFFFD, "lenient buf[1]=0x%04x expected FFFD",
        (unsigned)buf[1]);
  CHECK(buf[2] == L'b', "lenient buf[2]=0x%04x expected 'b'",
        (unsigned)buf[2]);
  CHECK(buf[3] == 0, "lenient terminator missing");

  /* lenient mode: lone continuation byte becomes U+FFFD */
  memset(buf, 0, sizeof(buf));
  n = MultiByteToWideChar(CP_UTF8, 0, "\x80", 1, buf, 16);
  CHECK(n == 1, "lenient continuation returned %d, expected 1", n);
  CHECK(buf[0] == 0xFFFD, "lenient continuation unit=0x%04x",
        (unsigned)buf[0]);

  printf("PASS %s\n", NAME);

out:
  return rc;
}
