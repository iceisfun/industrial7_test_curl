/*
 * Test: 08_env_wide_get_set_crt
 *
 * Purpose: round-trip a non-ASCII environment variable through the wide
 *          Win32 environment API (SetEnvironmentVariableW and
 *          GetEnvironmentVariableW, including the size-query and the
 *          too-small-buffer rules) and through the CRT (_wputenv_s and
 *          _wgetenv), which is what curl's getenv helpers and the CRT
 *          see. Also checks deletion semantics.
 *
 * APIs:    SetEnvironmentVariableW, GetEnvironmentVariableW, _wputenv_s,
 *          _wgetenv, GetLastError, SetLastError
 *
 * Success: - SetEnvironmentVariableW(L"CURLCORPUS_U08_ÜNI", L"välue
 *            ✓") succeeds
 *          - GetEnvironmentVariableW(name, NULL, 0) returns 8 (7 characters
 *            plus terminator)
 *          - GetEnvironmentVariableW(name, buf, 64) returns 7 and buf equals
 *            the value
 *          - GetEnvironmentVariableW(name, buf, 3) returns 8 (required
 *            size) and does not report success
 *          - an unknown name returns 0 with ERROR_ENVVAR_NOT_FOUND (203)
 *          - SetEnvironmentVariableW(name, NULL) deletes; the next get
 *            returns 0 with 203
 *          - _wputenv_s(L"CURLCORPUS_U08_CRT", value) returns 0, _wgetenv
 *            returns the value, and GetEnvironmentVariableW sees it too
 *          - _wputenv_s(name, L"") removes it: _wgetenv returns NULL
 *
 * Source:  lib/getenv.c:53 (curl_getenv) reads variables through
 *          GetEnvironmentVariableA with the same size-query contract. curl
 *          does not call the W form directly; this test covers the wide
 *          variant of that contract, which the UNICODE build relies on.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>

#define NAME "env_wide_get_set_crt"

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if(!(cond)) {                                                          \
      printf("FAIL %s: ", NAME);                                           \
      printf(__VA_ARGS__);                                                 \
      printf(" [line %d, GetLastError=%lu]\n", __LINE__,                   \
             (unsigned long)GetLastError());                               \
      rc = 1;                                                              \
      goto out;                                                            \
    }                                                                      \
  } while(0)

#define VAR_W L"CURLCORPUS_U08_ÜNI"
#define VAL_W L"välue ✓"
#define CRT_VAR L"CURLCORPUS_U08_CRT"

int main(void)
{
  int rc = 0;
  wchar_t buf[64];
  DWORD n;
  wchar_t *p;
  int set_done = 0;
  int crt_set = 0;

  /* 1. set */
  CHECK(SetEnvironmentVariableW(VAR_W, VAL_W), "SetEnvironmentVariableW");
  set_done = 1;

  /* 2. size query */
  n = GetEnvironmentVariableW(VAR_W, NULL, 0);
  CHECK(n == 8, "size query returned %lu, expected 8", (unsigned long)n);

  /* 3. full read */
  memset(buf, 0, sizeof(buf));
  n = GetEnvironmentVariableW(VAR_W, buf, 64);
  CHECK(n == 7, "full read returned %lu, expected 7", (unsigned long)n);
  CHECK(wcscmp(buf, VAL_W) == 0, "value mismatch: '%ls'", buf);

  /* 4. too small buffer: required size comes back, no success */
  SetLastError(0);
  n = GetEnvironmentVariableW(VAR_W, buf, 3);
  CHECK(n == 8, "small buffer returned %lu, expected 8", (unsigned long)n);

  /* 5. unknown name */
  SetLastError(0);
  n = GetEnvironmentVariableW(L"CURLCORPUS_U08_NOPE", buf, 64);
  CHECK(n == 0, "unknown name returned %lu, expected 0", (unsigned long)n);
  CHECK(GetLastError() == ERROR_ENVVAR_NOT_FOUND,
        "unknown name error %lu, expected 203",
        (unsigned long)GetLastError());

  /* 6. delete with NULL value */
  CHECK(SetEnvironmentVariableW(VAR_W, NULL), "delete via NULL failed");
  set_done = 0;
  SetLastError(0);
  n = GetEnvironmentVariableW(VAR_W, buf, 64);
  CHECK(n == 0, "after delete returned %lu, expected 0", (unsigned long)n);
  CHECK(GetLastError() == ERROR_ENVVAR_NOT_FOUND,
        "after delete error %lu, expected 203",
        (unsigned long)GetLastError());

  /* 7. CRT put/get: _wputenv_s writes the process environment too */
  CHECK(_wputenv_s(CRT_VAR, VAL_W) == 0, "_wputenv_s failed");
  crt_set = 1;
  p = _wgetenv(CRT_VAR);
  CHECK(p != NULL, "_wgetenv returned NULL after _wputenv_s");
  CHECK(wcscmp(p, VAL_W) == 0, "_wgetenv value '%ls'", p);
  memset(buf, 0, sizeof(buf));
  n = GetEnvironmentVariableW(CRT_VAR, buf, 64);
  CHECK(n == 7, "GetEnvironmentVariableW after _wputenv_s returned %lu",
        (unsigned long)n);
  CHECK(wcscmp(buf, VAL_W) == 0, "Win32 view of CRT var '%ls'", buf);

  /* 8. _wgetenv of a missing name */
  CHECK(_wgetenv(L"CURLCORPUS_U08_MISSING") == NULL,
        "_wgetenv of missing name was not NULL");

  /* 9. _wputenv_s with an empty value removes the variable */
  CHECK(_wputenv_s(CRT_VAR, L"") == 0, "_wputenv_s(empty) failed");
  crt_set = 0;
  CHECK(_wgetenv(CRT_VAR) == NULL, "_wgetenv still set after removal");

  printf("PASS %s\n", NAME);

out:
  if(set_done)
    SetEnvironmentVariableW(VAR_W, NULL);
  if(crt_set)
    _wputenv_s(CRT_VAR, L"");
  return rc;
}
