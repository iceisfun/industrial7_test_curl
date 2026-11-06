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
 *   (STATUS_INVALID_HANDLE 0xC0000008), and the control call with the flag returns STATUS_SUCCESS.
 *
 * Source: lib/curlx/winapi.c:118-122 (curl only ever passes the flag, so this
 *   test pins the behaviour that makes that choice necessary).
 *
 * Probed on Windows 10 22H2: flagless NULL handle -> STATUS_INVALID_HANDLE
 * (0xC0000008); NULL buffer -> STATUS_INVALID_PARAMETER (0xC000000D); length 0
 * -> success; unknown flag bit 0x80 with the system flag -> 0xC000000D; flag
 * 0x100 alone -> 0xC0000008; with the system flag, BCRYPT_RNG_USE_ENTROPY_IN_BUFFER
 * is accepted.
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
  /* Windows 10 22H2: STATUS_INVALID_HANDLE (0xC0000008), every time. */
  if(st != CURL_STATUS_INVALID_HANDLE) {
    printf("FAIL %s: status 0x%08lx for NULL handle without flag, expected "
           "0xC0000008\n", NAME, (unsigned long)st);
    return 1;
  }

  /* Other argument errors (probed on Windows 10 22H2). */
  st = BCryptGenRandom(NULL, NULL, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if(st != CURL_STATUS_INVALID_PARAM) {
    printf("FAIL %s: NULL buffer status 0x%08lx, expected 0xC000000D\n", NAME, (unsigned long)st);
    return 1;
  }
  st = BCryptGenRandom(NULL, buf, 0, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: zero-length request status 0x%08lx, expected success\n", NAME, (unsigned long)st);
    return 1;
  }
  st = BCryptGenRandom(NULL, buf, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG | 0x80);
  if(st != CURL_STATUS_INVALID_PARAM) {
    printf("FAIL %s: unknown flag 0x80 status 0x%08lx, expected 0xC000000D\n", NAME, (unsigned long)st);
    return 1;
  }
  st = BCryptGenRandom(NULL, buf, 32, 0x100);
  if(st != CURL_STATUS_INVALID_HANDLE) {
    printf("FAIL %s: flag 0x100 without the system flag status 0x%08lx, expected 0xC0000008\n",
           NAME, (unsigned long)st);
    return 1;
  }
  /* BCRYPT_RNG_USE_ENTROPY_IN_BUFFER is accepted together with the system flag. */
  st = BCryptGenRandom(NULL, buf, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG | BCRYPT_RNG_USE_ENTROPY_IN_BUFFER);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: ENTROPY_IN_BUFFER status 0x%08lx, expected success\n", NAME, (unsigned long)st);
    return 1;
  }

  printf("PASS %s\n", NAME);
  return 0;
}
