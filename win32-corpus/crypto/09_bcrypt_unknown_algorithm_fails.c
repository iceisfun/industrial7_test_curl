/*
 * Test: bcrypt_unknown_algorithm_fails
 *
 * Purpose: failure paths of CNG provider/algorithm selection. A caller that
 *   asks for an algorithm or provider that does not exist must get a
 *   non-success status and no usable handle, so curl's CNG code cannot
 *   silently proceed with a NULL algorithm. A control open of SHA256 from the
 *   default provider is done first to show the failures are specific.
 *
 * APIs: BCryptOpenAlgorithmProvider (unknown algorithm, unknown provider,
 *       and the SHA256 control), BCryptCloseAlgorithmProvider,
 *       BCryptGetProperty with an undersized output buffer
 *
 * Success: the control open returns STATUS_SUCCESS; the unknown algorithm and
 *   unknown provider opens return a non-success status (expected
 *   STATUS_NOT_FOUND 0xC0000225); the undersized BCRYPT_HASH_LENGTH query
 *   returns a non-success status (STATUS_BUFFER_TOO_SMALL 0xC0000023 or
 *   STATUS_INVALID_PARAMETER 0xC000000D).
 *
 * Source: no direct curl call site; this complements the CNG use in test 08.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#define NAME "bcrypt_unknown_algorithm_fails"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#define CURL_STATUS_NOT_FOUND       ((NTSTATUS)0xC0000225L)
#define CURL_STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#define CURL_STATUS_NOT_SUPPORTED   ((NTSTATUS)0xC00000BBL)

int main(void)
{
  BCRYPT_ALG_HANDLE hAlg = NULL;
  NTSTATUS st;
  DWORD hashlen = 0;
  ULONG got = 0;
  unsigned char tiny[1];

  /* Control: a real algorithm opens. */
  st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
  if(st == CURL_STATUS_NOT_FOUND || st == CURL_STATUS_NOT_IMPLEMENTED ||
     st == CURL_STATUS_NOT_SUPPORTED) {
    printf("SKIP %s: SHA256 provider absent (status 0x%08lx)\n", NAME,
           (unsigned long)st);
    return 77;
  }
  if(st != STATUS_SUCCESS || !hAlg) {
    printf("FAIL %s: control open of SHA256 status 0x%08lx\n", NAME,
           (unsigned long)st);
    return 1;
  }

  /* Undersized output buffer for a DWORD property must not succeed. */
  st = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, tiny, sizeof(tiny),
                         &got, 0);
  if(st == STATUS_SUCCESS) {
    printf("FAIL %s: BCRYPT_HASH_LENGTH accepted a 1-byte output buffer\n",
           NAME);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }
  hashlen = 0;
  st = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashlen,
                         sizeof(hashlen), &got, 0);
  if(st != STATUS_SUCCESS || hashlen != 32) {
    printf("FAIL %s: BCRYPT_HASH_LENGTH after failed query is %lu "
           "(status 0x%08lx)\n", NAME, (unsigned long)hashlen,
           (unsigned long)st);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }
  BCryptCloseAlgorithmProvider(hAlg, 0);
  hAlg = NULL;

  /* Unknown algorithm name. */
  st = BCryptOpenAlgorithmProvider(&hAlg, L"CURL-CORPUS-NO-SUCH-ALG", NULL, 0);
  if(st == STATUS_SUCCESS) {
    printf("FAIL %s: unknown algorithm name opened successfully\n", NAME);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }
  /* Windows reports STATUS_NOT_FOUND. Wine reports STATUS_NOT_IMPLEMENTED
     for the same request; both are non-success, which is what matters. */
  if(st != CURL_STATUS_NOT_FOUND && st != CURL_STATUS_NOT_IMPLEMENTED) {
    printf("FAIL %s: unknown algorithm returned 0x%08lx, expected "
           "STATUS_NOT_FOUND (0xC0000225), GetLastError %lu\n", NAME,
           (unsigned long)st, (unsigned long)GetLastError());
    return 1;
  }

  /* Known algorithm, unknown provider. */
  hAlg = NULL;
  st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                   L"Curl Corpus No Such Provider", 0);
  if(st == STATUS_SUCCESS) {
    printf("FAIL %s: unknown provider name opened successfully\n", NAME);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }
  if(st != CURL_STATUS_NOT_FOUND && st != CURL_STATUS_NOT_IMPLEMENTED) {
    printf("FAIL %s: unknown provider returned 0x%08lx, expected "
           "STATUS_NOT_FOUND (0xC0000225)\n", NAME, (unsigned long)st);
    return 1;
  }

  printf("PASS %s\n", NAME);
  return 0;
}
