/*
 * Test: bcrypt_genrandom_system_rng
 *
 * Purpose: exercise BCryptGenRandom with a NULL algorithm handle and
 *   BCRYPT_USE_SYSTEM_PREFERRED_RNG, the exact call curl makes to seed
 *   its random data (curlx_win32_random).
 *
 * APIs: BCryptGenRandom(NULL, buf, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
 *
 * Success: the call returns STATUS_SUCCESS, the 32-byte output is not all
 *   zero, and two consecutive outputs differ.
 *
 * Source: lib/curlx/winapi.c:118-122 (curlx_win32_random)
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

#define NAME "bcrypt_genrandom_system_rng"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
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
  unsigned char a[32], b[32];
  NTSTATUS st;

  memset(a, 0, sizeof(a));
  memset(b, 0, sizeof(b));

  st = BCryptGenRandom(NULL, a, (ULONG)sizeof(a),
                       BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if(st == CURL_STATUS_NOT_IMPLEMENTED || st == CURL_STATUS_NOT_SUPPORTED) {
    printf("SKIP %s: BCryptGenRandom not supported (status 0x%08lx)\n",
           NAME, (unsigned long)st);
    return 77;
  }
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: BCryptGenRandom status 0x%08lx, GetLastError %lu\n",
           NAME, (unsigned long)st, (unsigned long)GetLastError());
    return 1;
  }
  if(all_zero(a, sizeof(a))) {
    printf("FAIL %s: first 32-byte output is all zero\n", NAME);
    return 1;
  }

  st = BCryptGenRandom(NULL, b, (ULONG)sizeof(b),
                       BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: second BCryptGenRandom status 0x%08lx, GetLastError %lu\n",
           NAME, (unsigned long)st, (unsigned long)GetLastError());
    return 1;
  }
  if(all_zero(b, sizeof(b))) {
    printf("FAIL %s: second 32-byte output is all zero\n", NAME);
    return 1;
  }
  if(memcmp(a, b, sizeof(a)) == 0) {
    printf("FAIL %s: two independent 32-byte outputs are identical\n", NAME);
    return 1;
  }

  printf("PASS %s\n", NAME);
  return 0;
}
