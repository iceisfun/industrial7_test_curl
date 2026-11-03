/*
 * Test: cryptgenrandom_prov_rsa_full
 *
 * Purpose: the CryptoAPI random path. Acquire a verify-only PROV_RSA_FULL
 *   context (no key container is created or touched), draw random bytes with
 *   CryptGenRandom, release the context, then re-acquire and draw again to
 *   prove the release left the provider usable.
 *
 * APIs: CryptAcquireContextW(PROV_RSA_FULL, NULL, NULL, CRYPT_VERIFYCONTEXT),
 *       CryptGenRandom, CryptReleaseContext
 *
 * Success: acquire returns TRUE, CryptGenRandom returns TRUE and fills a
 *   non-zero 32-byte buffer, CryptReleaseContext returns TRUE, and a second
 *   acquire/generate/release cycle also succeeds with different output.
 *
 * Source: lib/md5.c:206 uses CryptAcquireContext(PROV_RSA_FULL,
 *   CRYPT_VERIFYCONTEXT | CRYPT_SILENT), the same provider type this test
 *   acquires for its CryptoAPI hash backend. curl itself does not call
 *   CryptGenRandom in this tree.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>

#define NAME "cryptgenrandom_prov_rsa_full"

static int all_zero(const unsigned char *p, size_t n)
{
  size_t i;
  for(i = 0; i < n; i++)
    if(p[i])
      return 0;
  return 1;
}

static int cycle(unsigned char *out, size_t n, const char *tag)
{
  HCRYPTPROV hProv = 0;

  if(!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT)) {
    printf("FAIL %s: CryptAcquireContextW(%s) GetLastError 0x%08lx\n",
           NAME, tag, (unsigned long)GetLastError());
    return 0;
  }
  if(!hProv) {
    printf("FAIL %s: CryptAcquireContextW(%s) returned a NULL provider\n",
           NAME, tag);
    return 0;
  }
  memset(out, 0, n);
  if(!CryptGenRandom(hProv, (DWORD)n, out)) {
    printf("FAIL %s: CryptGenRandom(%s) GetLastError 0x%08lx\n",
           NAME, tag, (unsigned long)GetLastError());
    CryptReleaseContext(hProv, 0);
    return 0;
  }
  if(all_zero(out, n)) {
    printf("FAIL %s: CryptGenRandom(%s) output is all zero\n", NAME, tag);
    CryptReleaseContext(hProv, 0);
    return 0;
  }
  if(!CryptReleaseContext(hProv, 0)) {
    printf("FAIL %s: CryptReleaseContext(%s) GetLastError 0x%08lx\n",
           NAME, tag, (unsigned long)GetLastError());
    return 0;
  }
  return 1;
}

int main(void)
{
  unsigned char a[32], b[32];

  if(!cycle(a, sizeof(a), "first"))
    return 1;
  if(!cycle(b, sizeof(b), "second"))
    return 1;
  if(memcmp(a, b, sizeof(a)) == 0) {
    printf("FAIL %s: two acquire/generate/release cycles produced identical "
           "32-byte output\n", NAME);
    return 1;
  }

  printf("PASS %s\n", NAME);
  return 0;
}
