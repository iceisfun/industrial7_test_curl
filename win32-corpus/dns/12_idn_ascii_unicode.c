/*
 * Test 12_idn_ascii_unicode
 *
 * Purpose: IDN (punycode) conversion that curl performs for host names on
 * Windows: IdnToAscii() on a Unicode host, IdnToUnicode() on the punycode
 * form, and rejection of invalid input. IdnToAscii/IdnToUnicode are taken
 * from normaliz.dll, falling back to kernel32.dll, both resolved with
 * LoadLibrary/GetProcAddress. A lowercase fallback via LCMapStringW is
 * checked first, since it needs no IDN support at all.
 *
 * APIs: LoadLibraryW, GetProcAddress, IdnToAscii, IdnToUnicode,
 *       LCMapStringW, GetLastError, FreeLibrary.
 *
 * Success:
 *   LCMapStringW(LOCALE_INVARIANT, LCMAP_LOWERCASE, L"LocalHost") == "localhost".
 *   IdnToAscii(L"localhost", length incl. NUL) returns > 0 and yields "localhost".
 *   IdnToAscii(L"bücher.example") yields "xn--bcher-kva.example".
 *   IdnToUnicode(L"xn--bcher-kva.example") yields L"bücher.example".
 *   IdnToAscii with a 64-character ASCII label (over 63 octets) returns 0.
 *   If neither normaliz.dll nor kernel32.dll exports the IDN functions, the
 *   IDN part FAILs after the LCMapString check.
 *
 * Source: lib/idn.c:167-192 (win32_idn_to_ascii: MultiByteToWideChar with
 *         MB_ERR_INVALID_CHARS, IdnToAscii with the length that includes the
 *         NUL, CURLE_URL_MALFORMAT when chars <= 0), lib/idn.c:194-225
 *         (win32_ascii_to_idn: IdnToUnicode, same error mapping).
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

#define T "12_idn_ascii_unicode"

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [GLE=%lu]\n", (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

#define SKIPF(msg) do { \
    printf("SKIP %s: %s\n", T, msg); status = 77; goto out; } while(0)

typedef int (WINAPI *PFN_IdnToAscii)(DWORD, LPCWSTR, int, LPWSTR, int);
typedef int (WINAPI *PFN_IdnToUnicode)(DWORD, LPCWSTR, int, LPWSTR, int);

int main(void)
{
  HMODULE lib = NULL;
  PFN_IdnToAscii pToAscii = NULL;
  PFN_IdnToUnicode pToUnicode = NULL;
  WCHAR lower[16];
  WCHAR out[256];
  int n;
  wchar_t long_label[80];
  int i;

  /* Fallback lowercase path first: no IDN support required. */
  n = LCMapStringW(LOCALE_INVARIANT, LCMAP_LOWERCASE, L"LocalHost", 9,
                   lower, 16);
  if(n != 9)
    FAILF("LCMapStringW returned %d, expected 9", n);
  lower[9] = 0;
  if(wcscmp(lower, L"localhost") != 0)
    FAILF("LCMapStringW lowercase gave '%ls'", lower);

  /* Resolve IdnToAscii/IdnToUnicode: normaliz.dll first, then kernel32. */
  lib = LoadLibraryW(L"normaliz.dll");
  if(lib) {
    pToAscii = (PFN_IdnToAscii)(void *)GetProcAddress(lib, "IdnToAscii");
    pToUnicode = (PFN_IdnToUnicode)(void *)GetProcAddress(lib, "IdnToUnicode");
  }
  if(!pToAscii || !pToUnicode) {
    if(lib)
      FreeLibrary(lib);
    lib = LoadLibraryW(L"kernel32.dll");
    if(lib) {
      pToAscii = (PFN_IdnToAscii)(void *)GetProcAddress(lib, "IdnToAscii");
      pToUnicode = (PFN_IdnToUnicode)(void *)GetProcAddress(lib, "IdnToUnicode");
    }
  }
  if(!pToAscii || !pToUnicode)
    FAILF("IdnToAscii/IdnToUnicode not exported by normaliz.dll or kernel32.dll");

  /* ASCII host: length includes the NUL, as lib/idn.c passes it. */
  memset(out, 0, sizeof(out));
  n = pToAscii(0, L"localhost", 10, out, 256);
  if(n <= 0)
    FAILF("IdnToAscii(localhost) returned %d", n);
  if(wcscmp(out, L"localhost") != 0)
    FAILF("IdnToAscii(localhost) gave '%ls'", out);

  /* Unicode label to punycode. */
  memset(out, 0, sizeof(out));
  n = pToAscii(0, L"bücher.example", -1, out, 256);
  if(n <= 0)
    FAILF("IdnToAscii(bucher.example) returned %d", n);
  if(wcscmp(out, L"xn--bcher-kva.example") != 0)
    FAILF("IdnToAscii(bucher.example) gave '%ls', expected xn--bcher-kva.example", out);

  /* Punycode back to Unicode. */
  memset(out, 0, sizeof(out));
  n = pToUnicode(0, L"xn--bcher-kva.example", -1, out, 256);
  if(n <= 0)
    FAILF("IdnToUnicode(xn--bcher-kva.example) returned %d", n);
  if(wcscmp(out, L"bücher.example") != 0)
    FAILF("IdnToUnicode gave '%ls'", out);

  /* An ASCII label longer than 63 octets is not a valid DNS label. */
  for(i = 0; i < 64; i++)
    long_label[i] = L'a';
  long_label[64] = L'\0';
  SetLastError(0);
  n = pToAscii(0, long_label, -1, out, 256);
  if(n != 0)
    FAILF("IdnToAscii accepted a 64-character label (returned %d)", n);

  /* Control character is invalid input for IDNA. */
  SetLastError(0);
  n = pToAscii(0, L"a\x0001" L"b.example", -1, out, 256);
  if(n != 0)
    FAILF("IdnToAscii accepted a control character (returned %d)", n);

out:
  if(lib)
    FreeLibrary(lib);
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
