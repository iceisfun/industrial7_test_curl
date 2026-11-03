/*
 * Test: 11_bcrypt_random
 * Purpose: Mirror curl's Windows entropy source used for random seeds
 *   (Curl_rand in lib/rand.c:51 calls curlx_win32_random) via BCryptGenRandom
 *   with the system RNG.
 * APIs: BCryptGenRandom, memset, memcmp
 * Source: lib/curlx/winapi.c:114-123. curlx_win32_random() zeroes the
 *   buffer and calls BCryptGenRandom(NULL, entropy, length,
 *   BCRYPT_USE_SYSTEM_PREFERRED_RNG); any result other than STATUS_SUCCESS
 *   becomes CURLE_FAILED_INIT.
 * Success: the call returns STATUS_SUCCESS (0) for 32 and 1024 byte buffers;
 *   the output is not all zero; two successive 32 byte draws differ; and a
 *   call with no algorithm handle and without the system-preferred flag is
 *   rejected with a non-success NTSTATUS.
 * Linking: BCryptGenRandom is exported by bcrypt.lib (the -lbcrypt import
 *   library), so it is linked directly rather than resolved with
 *   LoadLibrary. The test has no SKIP path; a missing export is a link error.
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
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "11_bcrypt_random"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

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
  unsigned char a[32], b[32], big[1024];
  NTSTATUS st;

  /* curl zeroes the buffer first, then fills it */
  memset(a, 0, sizeof(a));
  st = BCryptGenRandom(NULL, a, (ULONG)sizeof(a),
                       BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: BCryptGenRandom(32) returned 0x%08lx\n", TEST_NAME,
           (unsigned long)st);
    return 1;
  }
  if(all_zero(a, sizeof(a))) {
    printf("FAIL %s: 32 byte output is all zero\n", TEST_NAME);
    return 1;
  }

  memset(b, 0, sizeof(b));
  st = BCryptGenRandom(NULL, b, (ULONG)sizeof(b),
                       BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: second BCryptGenRandom(32) returned 0x%08lx\n", TEST_NAME,
           (unsigned long)st);
    return 1;
  }
  if(memcmp(a, b, sizeof(a)) == 0) {
    printf("FAIL %s: two 32 byte draws are identical\n", TEST_NAME);
    return 1;
  }

  memset(big, 0, sizeof(big));
  st = BCryptGenRandom(NULL, big, (ULONG)sizeof(big),
                       BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if(st != STATUS_SUCCESS || all_zero(big, sizeof(big))) {
    printf("FAIL %s: 1024 byte draw status=0x%08lx or all zero\n", TEST_NAME,
           (unsigned long)st);
    return 1;
  }

  /* Failure path: without an algorithm handle and without the
     system-preferred flag the call must not report success */
  st = BCryptGenRandom(NULL, a, (ULONG)sizeof(a), 0);
  if(st == STATUS_SUCCESS) {
    printf("FAIL %s: BCryptGenRandom with no algorithm and no flag succeeded\n",
           TEST_NAME);
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
