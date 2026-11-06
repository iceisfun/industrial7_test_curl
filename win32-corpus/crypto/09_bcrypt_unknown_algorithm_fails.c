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
 *   returns STATUS_BUFFER_TOO_SMALL (0xC0000023) with the needed size 4; the
 *   size query succeeds with 4; an unknown property and a lower-case
 *   algorithm id return STATUS_NOT_SUPPORTED (0xC00000BB); undefined flags, a
 *   NULL output handle and a NULL algorithm return STATUS_INVALID_PARAMETER
 *   (0xC000000D); closing NULL returns STATUS_INVALID_HANDLE (0xC0000008).
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
#define CURL_STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)

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
  if(st != (NTSTATUS)0xC0000023L /* STATUS_BUFFER_TOO_SMALL */ || got != 4) {
    printf("FAIL %s: BCRYPT_HASH_LENGTH with a 1-byte buffer: status 0x%08lx "
           "needed %lu, expected 0xC0000023 / 4\n", NAME, (unsigned long)st,
           (unsigned long)got);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }
  st = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, NULL, 0, &got, 0);
  if(st != STATUS_SUCCESS || got != 4) {
    printf("FAIL %s: size query status 0x%08lx got %lu, expected 0 / 4\n",
           NAME, (unsigned long)st, (unsigned long)got);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }
  st = BCryptGetProperty(hAlg, L"NoSuchProperty", tiny, sizeof(tiny), &got, 0);
  if(st != CURL_STATUS_NOT_SUPPORTED) {
    printf("FAIL %s: unknown property status 0x%08lx, expected 0xC00000BB\n",
           NAME, (unsigned long)st);
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
  /* Windows 10 22H2 reports STATUS_NOT_FOUND. */
  if(st != CURL_STATUS_NOT_FOUND) {
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
  if(st != CURL_STATUS_NOT_FOUND) {
    printf("FAIL %s: unknown provider returned 0x%08lx, expected "
           "STATUS_NOT_FOUND (0xC0000225)\n", NAME, (unsigned long)st);
    return 1;
  }

  /* Argument and name errors (Windows 10 22H2). */
  hAlg = NULL;
  st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0x1000);
  if(st != CURL_STATUS_INVALID_PARAMETER) {
    printf("FAIL %s: undefined flags status 0x%08lx, expected 0xC000000D\n", NAME, (unsigned long)st);
    return 1;
  }
  st = BCryptOpenAlgorithmProvider(NULL, BCRYPT_SHA256_ALGORITHM, NULL, 0);
  if(st != CURL_STATUS_INVALID_PARAMETER) {
    printf("FAIL %s: NULL output handle status 0x%08lx, expected 0xC000000D\n", NAME, (unsigned long)st);
    return 1;
  }
  st = BCryptOpenAlgorithmProvider(&hAlg, NULL, NULL, 0);
  if(st != CURL_STATUS_INVALID_PARAMETER) {
    printf("FAIL %s: NULL algorithm status 0x%08lx, expected 0xC000000D\n", NAME, (unsigned long)st);
    return 1;
  }
  st = BCryptOpenAlgorithmProvider(&hAlg, L"sha256", NULL, 0);
  if(st != CURL_STATUS_NOT_SUPPORTED) {
    printf("FAIL %s: lower-case algorithm id status 0x%08lx, expected 0xC00000BB "
           "(identifiers are case sensitive)\n", NAME, (unsigned long)st);
    if(st == STATUS_SUCCESS)
      BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }
  /* Closing a handle twice, or closing NULL. */
  hAlg = NULL;
  st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
  if(st != STATUS_SUCCESS || BCryptCloseAlgorithmProvider(hAlg, 0) != STATUS_SUCCESS) {
    printf("FAIL %s: control open/close failed\n", NAME);
    return 1;
  }
  st = BCryptCloseAlgorithmProvider(NULL, 0);
  if(st != (NTSTATUS)0xC0000008L) {
    printf("FAIL %s: close of NULL status 0x%08lx, expected 0xC0000008\n", NAME, (unsigned long)st);
    return 1;
  }

  printf("PASS %s\n", NAME);
  return 0;
}
