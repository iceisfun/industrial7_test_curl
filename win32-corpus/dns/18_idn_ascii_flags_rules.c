/*
 * Test 18_idn_ascii_flags_rules
 *
 * Purpose: what IdnToAscii() does with the host names curl hands it. curl
 * (lib/idn.c, win32_idn_to_ascii) calls IdnToAscii(0, wide_host, -1, out, size)
 * with dwFlags 0 for every host that is not plain ASCII; a result of 0 is
 * mapped to CURLE_URL_MALFORMAT. This pins what flags 0 accepts and rejects,
 * the effect of IDN_USE_STD3_ASCII_RULES (0x2) and IDN_ALLOW_UNASSIGNED (0x1),
 * and the buffer/length conventions.
 *
 * APIs: LoadLibraryW(normaliz.dll), GetProcAddress, IdnToAscii, IdnToUnicode,
 *       GetLastError.
 *
 * Success (probed on Windows 10 22H2). With dwFlags 0: "localhost" ->
 * "localhost" (returns 10 = characters including the NUL); the Unicode name
 * "bücher.example" -> "xn--bcher-kva.example" (22); the Japanese name
 * "例え.jp" -> "xn--r8jz45g.jp"; a Cyrillic "аpple.com" ->
 * "xn--pple-43d.com"; "ß.de" -> "ss.de" (IDNA2003 mapping); the
 * ideographic full stop in "a。b" is a label separator ("a.b"); upper
 * case ASCII is not lower-cased; underscores, spaces and leading or trailing
 * hyphens pass through unchanged ("_dmarc.example", "foo bar.example",
 * "-a.example"). A trailing dot is kept ("a.b."). "1.2.3.4" is unchanged.
 * An empty label ("x..y"), the name "." and the empty string fail with 0 and
 * GetLastError()==ERROR_INVALID_NAME (123). IDN_USE_STD3_ASCII_RULES makes
 * underscore, space and leading/trailing hyphen names fail with 123 while
 * the plain names still pass. A 4-character output buffer fails with 0 and
 * ERROR_INSUFFICIENT_BUFFER (122); a NULL output with size 0 returns the
 * required size (10 for "localhost"); an explicit length of 9 (no NUL)
 * converts 9 characters and returns 9. IdnToUnicode("xn--bcher-kva.example")
 * returns 15 and "bücher.example".
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
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define T "18_idn_ascii_flags_rules"

#ifndef IDN_ALLOW_UNASSIGNED
#define IDN_ALLOW_UNASSIGNED 0x01
#endif
#ifndef IDN_USE_STD3_ASCII_RULES
#define IDN_USE_STD3_ASCII_RULES 0x02
#endif

typedef int (WINAPI *PFN_IdnToAscii)(DWORD, LPCWSTR, int, LPWSTR, int);
typedef int (WINAPI *PFN_IdnToUnicode)(DWORD, LPCWSTR, int, LPWSTR, int);

static int status = 0;
#define NOTE_FAIL(...) do { printf("FAIL %s: ", T); printf(__VA_ARGS__); printf("\n"); status = 1; } while(0)

static PFN_IdnToAscii pToAscii;

/* want == NULL: must fail with ERROR_INVALID_NAME */
static void conv(DWORD flags, const wchar_t *in, const wchar_t *want)
{
  wchar_t out[256];
  int n;
  memset(out, 0, sizeof(out));
  SetLastError(0);
  n = pToAscii(flags, in, -1, out, 256);
  if(!want) {
    if(n != 0 || GetLastError() != ERROR_INVALID_NAME)
      NOTE_FAIL("IdnToAscii(0x%lx, \"%ls\") = %d GLE=%lu, expected 0 / 123", (unsigned long)flags, in,
                n, (unsigned long)GetLastError());
    return;
  }
  if(n != (int)wcslen(want) + 1 || wcscmp(out, want) != 0)
    NOTE_FAIL("IdnToAscii(0x%lx, \"%ls\") = %d \"%ls\", expected %d \"%ls\"", (unsigned long)flags, in, n,
              n > 0 ? out : L"", (int)wcslen(want) + 1, want);
}

int main(void)
{
  HMODULE lib = LoadLibraryW(L"normaliz.dll");
  PFN_IdnToUnicode pToUnicode;
  wchar_t out[256];
  int n;

  if(!lib) {
    printf("SKIP %s: normaliz.dll not loadable\n", T);
    return 77;
  }
  pToAscii = (PFN_IdnToAscii)(void *)GetProcAddress(lib, "IdnToAscii");
  pToUnicode = (PFN_IdnToUnicode)(void *)GetProcAddress(lib, "IdnToUnicode");
  if(!pToAscii || !pToUnicode) {
    printf("SKIP %s: IdnToAscii/IdnToUnicode not exported\n", T);
    return 77;
  }

  conv(0, L"localhost", L"localhost");
  conv(0, L"bücher.example", L"xn--bcher-kva.example");
  conv(0, L"例え.jp", L"xn--r8jz45g.jp");
  conv(0, L"аpple.com", L"xn--pple-43d.com");
  conv(0, L"ß.de", L"ss.de");
  conv(0, L"a。" L"b", L"a.b");
  conv(0, L"EXAMPLE.COM", L"EXAMPLE.COM");
  conv(0, L"_dmarc.example", L"_dmarc.example");
  conv(0, L"foo bar.example", L"foo bar.example");
  conv(0, L"-a.example", L"-a.example");
  conv(0, L"a-.example", L"a-.example");
  conv(0, L"a.b.", L"a.b.");
  conv(0, L"1.2.3.4", L"1.2.3.4");
  conv(0, L"xn--bcher-kva.example", L"xn--bcher-kva.example");
  conv(0, L"x..y", NULL);
  conv(0, L".", NULL);
  conv(0, L"", NULL);

  conv(IDN_USE_STD3_ASCII_RULES, L"localhost", L"localhost");
  conv(IDN_USE_STD3_ASCII_RULES, L"bücher.example", L"xn--bcher-kva.example");
  conv(IDN_USE_STD3_ASCII_RULES, L"_dmarc.example", NULL);
  conv(IDN_USE_STD3_ASCII_RULES, L"a_b.example", NULL);
  conv(IDN_USE_STD3_ASCII_RULES, L"foo bar.example", NULL);
  conv(IDN_USE_STD3_ASCII_RULES, L"-a.example", NULL);
  conv(IDN_USE_STD3_ASCII_RULES, L"a-.example", NULL);
  conv(IDN_ALLOW_UNASSIGNED, L"_dmarc.example", L"_dmarc.example");
  conv(IDN_ALLOW_UNASSIGNED, L"bücher.example", L"xn--bcher-kva.example");

  /* buffer and length conventions */
  SetLastError(0);
  n = pToAscii(0, L"localhost", -1, out, 4);
  if(n != 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    NOTE_FAIL("4-character output: %d GLE=%lu, expected 0 / 122", n, (unsigned long)GetLastError());
  n = pToAscii(0, L"localhost", -1, NULL, 0);
  if(n != 10)
    NOTE_FAIL("size query returned %d, expected 10", n);
  memset(out, 0, sizeof(out));
  n = pToAscii(0, L"localhost", 9, out, 256);
  if(n != 9 || wcsncmp(out, L"localhost", 9) != 0)
    NOTE_FAIL("explicit length 9: returned %d", n);

  memset(out, 0, sizeof(out));
  n = pToUnicode(0, L"xn--bcher-kva.example", -1, out, 256);
  if(n != 15 || wcscmp(out, L"bücher.example") != 0)
    NOTE_FAIL("IdnToUnicode returned %d \"%ls\", expected 15 \"b\\u00fccher.example\"", n, out);

  FreeLibrary(lib);
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
