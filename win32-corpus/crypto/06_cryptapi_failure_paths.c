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
 * Success (exact errors probed on Windows 10 22H2): (a) fails with
 * ERROR_INVALID_PARAMETER (0x57); (b) NTE_BAD_KEYSET (0x80090016); (c)
 * NTE_BAD_FLAGS (0x80090009); an unknown provider name NTE_KEYSET_NOT_DEF
 * (0x80090019); provider type 9999 NTE_BAD_PROV_TYPE (0x80090014); undefined
 * flag bits NTE_BAD_FLAGS; a NULL output handle, CryptReleaseContext(0), a NULL
 * random buffer, use after release and a double release all ERROR_INVALID_PARAMETER;
 * a zero-length CryptGenRandom succeeds; (d) returns TRUE.
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
  SetLastError(0);
  if(CryptGenRandom((HCRYPTPROV)0, (DWORD)sizeof(buf), buf) ||
     GetLastError() != ERROR_INVALID_PARAMETER) {
    printf("FAIL %s: CryptGenRandom with a zero provider handle: expected "
           "failure with ERROR_INVALID_PARAMETER (GLE=0x%08lx)\n", NAME,
           (unsigned long)GetLastError());
    return 1;
  }

  /* (b) Open a container that was never created, without NEWKEYSET. */
  hProv = 0;
  SetLastError(0);
  if(CryptAcquireContextW(&hProv, L"curl_corpus_no_such_container_4f1a",
                          NULL, PROV_RSA_FULL, 0)) {
    CryptReleaseContext(hProv, 0);
    printf("FAIL %s: CryptAcquireContextW opened a container that should not "
           "exist\n", NAME);
    return 1;
  }
  if(GetLastError() != (DWORD)NTE_BAD_KEYSET) {
    printf("FAIL %s: missing container GLE=0x%08lx, expected NTE_BAD_KEYSET "
           "0x80090016\n", NAME, (unsigned long)GetLastError());
    return 1;
  }

  /* (c) A container name together with CRYPT_VERIFYCONTEXT is invalid. */
  hProv = 0;
  SetLastError(0);
  if(CryptAcquireContextW(&hProv, L"curl_corpus_no_such_container_4f1a",
                          NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    CryptReleaseContext(hProv, 0);
    printf("FAIL %s: CryptAcquireContextW accepted container name with "
           "CRYPT_VERIFYCONTEXT\n", NAME);
    return 1;
  }
  if(GetLastError() != (DWORD)NTE_BAD_FLAGS) {
    printf("FAIL %s: container+VERIFYCONTEXT GLE=0x%08lx, expected "
           "NTE_BAD_FLAGS 0x80090009\n", NAME, (unsigned long)GetLastError());
    return 1;
  }

  /* (c2) Unknown provider name, undefined provider type, undefined flag bits,
     NULL output handle. */
  hProv = 0;
  SetLastError(0);
  if(CryptAcquireContextW(&hProv, NULL, L"No Such Provider", PROV_RSA_FULL,
                          CRYPT_VERIFYCONTEXT) ||
     GetLastError() != (DWORD)NTE_KEYSET_NOT_DEF) {
    printf("FAIL %s: unknown provider name GLE=0x%08lx, expected "
           "NTE_KEYSET_NOT_DEF 0x80090019\n", NAME, (unsigned long)GetLastError());
    return 1;
  }
  SetLastError(0);
  if(CryptAcquireContextW(&hProv, NULL, NULL, 9999, CRYPT_VERIFYCONTEXT) ||
     GetLastError() != (DWORD)NTE_BAD_PROV_TYPE) {
    printf("FAIL %s: provider type 9999 GLE=0x%08lx, expected NTE_BAD_PROV_TYPE "
           "0x80090014\n", NAME, (unsigned long)GetLastError());
    return 1;
  }
  SetLastError(0);
  if(CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL,
                          0x00FF0000 | CRYPT_VERIFYCONTEXT) ||
     GetLastError() != (DWORD)NTE_BAD_FLAGS) {
    printf("FAIL %s: undefined flag bits GLE=0x%08lx, expected NTE_BAD_FLAGS\n",
           NAME, (unsigned long)GetLastError());
    return 1;
  }
  SetLastError(0);
  if(CryptAcquireContextW(NULL, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ||
     GetLastError() != ERROR_INVALID_PARAMETER) {
    printf("FAIL %s: NULL phProv GLE=0x%08lx, expected ERROR_INVALID_PARAMETER\n",
           NAME, (unsigned long)GetLastError());
    return 1;
  }
  SetLastError(0);
  if(CryptReleaseContext(0, 0) || GetLastError() != ERROR_INVALID_PARAMETER) {
    printf("FAIL %s: CryptReleaseContext(0) GLE=0x%08lx, expected "
           "ERROR_INVALID_PARAMETER\n", NAME, (unsigned long)GetLastError());
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
  /* zero-length request is fine; NULL buffer is not */
  SetLastError(0);
  if(!CryptGenRandom(hProv, 0, buf)) {
    printf("FAIL %s: zero-length CryptGenRandom failed\n", NAME);
    return 1;
  }
  if(CryptGenRandom(hProv, (DWORD)sizeof(buf), NULL) ||
     GetLastError() != ERROR_INVALID_PARAMETER) {
    printf("FAIL %s: NULL buffer GLE=0x%08lx, expected ERROR_INVALID_PARAMETER\n",
           NAME, (unsigned long)GetLastError());
    return 1;
  }
  if(!CryptReleaseContext(hProv, 0)) {
    printf("FAIL %s: recovery CryptReleaseContext GetLastError 0x%08lx\n",
           NAME, (unsigned long)GetLastError());
    return 1;
  }
  /* use after release and double release fail with ERROR_INVALID_PARAMETER */
  SetLastError(0);
  if(CryptGenRandom(hProv, (DWORD)sizeof(buf), buf) ||
     GetLastError() != ERROR_INVALID_PARAMETER) {
    printf("FAIL %s: CryptGenRandom after release GLE=0x%08lx\n", NAME,
           (unsigned long)GetLastError());
    return 1;
  }
  SetLastError(0);
  if(CryptReleaseContext(hProv, 0) || GetLastError() != ERROR_INVALID_PARAMETER) {
    printf("FAIL %s: second CryptReleaseContext GLE=0x%08lx\n", NAME,
           (unsigned long)GetLastError());
    return 1;
  }

  printf("PASS %s\n", NAME);
  return 0;
}
