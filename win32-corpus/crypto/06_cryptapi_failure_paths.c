/*
 * Test: cryptapi_failure_paths
 *
 * Purpose: failure paths of the CryptoAPI random/provider entry points, which
 *   curl's CryptoAPI backends depend on to report errors rather than hand back
 *   unseeded or uninitialised data.
 *   (a) CryptGenRandom with an invalid (zero) provider handle must fail.
 *   (b) CryptAcquireContextW with a named container that does not exist and
 *       without CRYPT_NEWKEYSET must fail (no container is created, so the
 *       test writes nothing to the registry).
 *   (c) CryptAcquireContextW combining a container name with
 *       CRYPT_VERIFYCONTEXT is invalid and must fail.
 *   (d) the verify-only acquire still succeeds afterwards, so the earlier
 *       failures did not poison the process.
 *
 * APIs: CryptGenRandom, CryptAcquireContextW, CryptReleaseContext
 *
 * Success: (a), (b) and (c) return FALSE, and (d) returns TRUE.
 *
 * Source: lib/md5.c:206-210 and lib/sha256.c:211-215 check the acquire return
 *   value and map failure to an error; this test checks that the failures
 *   actually surface.
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

#define NAME "cryptapi_failure_paths"

int main(void)
{
  unsigned char buf[16];
  HCRYPTPROV hProv = 0;

  memset(buf, 0, sizeof(buf));

  /* (a) Generate with an invalid provider handle. */
  if(CryptGenRandom((HCRYPTPROV)0, (DWORD)sizeof(buf), buf)) {
    printf("FAIL %s: CryptGenRandom succeeded with a zero provider handle\n",
           NAME);
    return 1;
  }

  /* (b) Open a container that was never created, without NEWKEYSET. */
  hProv = 0;
  if(CryptAcquireContextW(&hProv, L"curl_corpus_no_such_container_4f1a",
                          NULL, PROV_RSA_FULL, 0)) {
    CryptReleaseContext(hProv, 0);
    printf("FAIL %s: CryptAcquireContextW opened a container that should not "
           "exist\n", NAME);
    return 1;
  }

  /* (c) A container name together with CRYPT_VERIFYCONTEXT is invalid. */
  hProv = 0;
  if(CryptAcquireContextW(&hProv, L"curl_corpus_no_such_container_4f1a",
                          NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    CryptReleaseContext(hProv, 0);
    printf("FAIL %s: CryptAcquireContextW accepted container name with "
           "CRYPT_VERIFYCONTEXT\n", NAME);
    return 1;
  }

  /* (d) The process can still acquire and use a verify-only context. */
  hProv = 0;
  if(!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT)) {
    printf("FAIL %s: recovery acquire GetLastError 0x%08lx\n",
           NAME, (unsigned long)GetLastError());
    return 1;
  }
  if(!CryptGenRandom(hProv, (DWORD)sizeof(buf), buf)) {
    printf("FAIL %s: recovery CryptGenRandom GetLastError 0x%08lx\n",
           NAME, (unsigned long)GetLastError());
    CryptReleaseContext(hProv, 0);
    return 1;
  }
  if(!CryptReleaseContext(hProv, 0)) {
    printf("FAIL %s: recovery CryptReleaseContext GetLastError 0x%08lx\n",
           NAME, (unsigned long)GetLastError());
    return 1;
  }

  printf("PASS %s\n", NAME);
  return 0;
}
