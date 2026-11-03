/*
 * Test: bcrypt_genrandom_null_handle_flags
 *
 * Purpose: failure path for BCryptGenRandom. A NULL algorithm handle is only
 *   valid together with BCRYPT_USE_SYSTEM_PREFERRED_RNG. Without that flag the
 *   call must fail rather than silently producing unseeded output. curl's
 *   wrapper turns any non-STATUS_SUCCESS into CURLE_FAILED_INIT, so a
 *   successful return here would hide a broken RNG.
 *
 * APIs: BCryptGenRandom(NULL, buf, n, 0) and
 *       BCryptGenRandom(NULL, buf, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) as the
 *       control case.
 *
 * Success: the flagless NULL-handle call returns a non-success NTSTATUS
 *   (documented STATUS_INVALID_HANDLE 0xC0000008 or STATUS_INVALID_PARAMETER
 *   0xC000000D), and the control call with the flag returns STATUS_SUCCESS.
 *
 * Source: lib/curlx/winapi.c:118-122 (curl only ever passes the flag, so this
 *   test pins the behaviour that makes that choice necessary).
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

#define NAME "bcrypt_genrandom_null_handle_flags"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#define CURL_STATUS_INVALID_HANDLE   ((NTSTATUS)0xC0000008L)
#define CURL_STATUS_INVALID_PARAM    ((NTSTATUS)0xC000000DL)
#define CURL_STATUS_NOT_IMPLEMENTED  ((NTSTATUS)0xC0000002L)
#define CURL_STATUS_NOT_SUPPORTED    ((NTSTATUS)0xC00000BBL)

int main(void)
{
  unsigned char buf[32];
  NTSTATUS st;

  memset(buf, 0xA5, sizeof(buf));

  /* Control: the flag makes a NULL handle valid. */
  st = BCryptGenRandom(NULL, buf, (ULONG)sizeof(buf),
                       BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if(st == CURL_STATUS_NOT_IMPLEMENTED || st == CURL_STATUS_NOT_SUPPORTED) {
    printf("SKIP %s: BCryptGenRandom not supported (status 0x%08lx)\n",
           NAME, (unsigned long)st);
    return 77;
  }
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: control call with USE_SYSTEM_PREFERRED_RNG status "
           "0x%08lx, GetLastError %lu\n", NAME, (unsigned long)st,
           (unsigned long)GetLastError());
    return 1;
  }

  /* Failure path: NULL handle without the flag. */
  memset(buf, 0xA5, sizeof(buf));
  st = BCryptGenRandom(NULL, buf, (ULONG)sizeof(buf), 0);
  if(st == STATUS_SUCCESS) {
    printf("FAIL %s: NULL handle without USE_SYSTEM_PREFERRED_RNG returned "
           "STATUS_SUCCESS\n", NAME);
    return 1;
  }
  if(st != CURL_STATUS_INVALID_HANDLE && st != CURL_STATUS_INVALID_PARAM) {
    printf("FAIL %s: unexpected status 0x%08lx for NULL handle without flag, "
           "GetLastError %lu\n", NAME, (unsigned long)st,
           (unsigned long)GetLastError());
    return 1;
  }

  printf("PASS %s\n", NAME);
  return 0;
}
