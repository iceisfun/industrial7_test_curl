/*
 * Test: bcrypt_genrandom_provider_rng
 *
 * Purpose: exercise the explicit-provider path for randomness: open the
 *   "RNG" algorithm from the Microsoft Primitive Provider, generate bytes
 *   with BCryptGenRandom on that handle, then close the provider. This is
 *   the path a program takes when it does not want the system-preferred
 *   shortcut and wants a handle it can reuse.
 *
 * APIs: BCryptOpenAlgorithmProvider(BCRYPT_RNG_ALGORITHM,
 *         MS_PRIMITIVE_PROVIDER), BCryptGenRandom(hAlg, ..., 0),
 *       BCryptCloseAlgorithmProvider
 *
 * Success: open returns STATUS_SUCCESS, two 64-byte outputs are non-zero
 *   and differ, close returns STATUS_SUCCESS and the handle is non-NULL.
 *
 * Source: no direct curl call site. This is the handle-based counterpart of
 *   lib/curlx/winapi.c:118, which uses BCRYPT_USE_SYSTEM_PREFERRED_RNG.
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

#define NAME "bcrypt_genrandom_provider_rng"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#define CURL_STATUS_NOT_FOUND       ((NTSTATUS)0xC0000225L)
#define CURL_STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#define CURL_STATUS_NOT_SUPPORTED   ((NTSTATUS)0xC00000BBL)

static int all_zero(const unsigned char *p, size_t n)
{
  size_t i;
  for(i = 0; i < n; i++)
    if(p[i])
      return 0;
  return 1;
}

int main(void)
{
  BCRYPT_ALG_HANDLE hAlg = NULL;
  unsigned char a[64], b[64];
  NTSTATUS st;

  st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM,
                                   MS_PRIMITIVE_PROVIDER, 0);
  if(st == CURL_STATUS_NOT_FOUND || st == CURL_STATUS_NOT_IMPLEMENTED ||
     st == CURL_STATUS_NOT_SUPPORTED) {
    printf("SKIP %s: RNG algorithm provider absent (status 0x%08lx)\n",
           NAME, (unsigned long)st);
    return 77;
  }
  if(st != STATUS_SUCCESS || !hAlg) {
    printf("FAIL %s: BCryptOpenAlgorithmProvider status 0x%08lx, "
           "GetLastError %lu\n", NAME, (unsigned long)st,
           (unsigned long)GetLastError());
    return 1;
  }

  memset(a, 0, sizeof(a));
  memset(b, 0, sizeof(b));

  st = BCryptGenRandom(hAlg, a, (ULONG)sizeof(a), 0);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: BCryptGenRandom(hAlg) status 0x%08lx, GetLastError %lu\n",
           NAME, (unsigned long)st, (unsigned long)GetLastError());
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }
  if(all_zero(a, sizeof(a))) {
    printf("FAIL %s: first 64-byte output is all zero\n", NAME);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }

  st = BCryptGenRandom(hAlg, b, (ULONG)sizeof(b), 0);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: second BCryptGenRandom(hAlg) status 0x%08lx\n",
           NAME, (unsigned long)st);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }
  if(memcmp(a, b, sizeof(a)) == 0) {
    printf("FAIL %s: two 64-byte outputs from the same handle are identical\n",
           NAME);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }

  st = BCryptCloseAlgorithmProvider(hAlg, 0);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: BCryptCloseAlgorithmProvider status 0x%08lx\n",
           NAME, (unsigned long)st);
    return 1;
  }

  printf("PASS %s\n", NAME);
  return 0;
}
