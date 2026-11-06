/*
 * Test: reg_hklm_readonly
 *
 * Purpose: Read HKLM values with RegOpenKeyExW and RegQueryValueExW using
 *   KEY_READ only, the way a read-only configuration probe does. Covers the
 *   size-query protocol for REG_SZ values, a DWORD read, and the failure
 *   paths for a missing key and a missing value. Nothing is written.
 *
 * APIs: RegOpenKeyExW, RegQueryValueExW, RegCloseKey (advapi32).
 *
 * Success means: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion opens with
 *   KEY_READ; the REG_SZ value CurrentBuildNumber has type REG_SZ and a
 *   non-empty all-digit string, and the size-query call (NULL data) reports
 *   a size equal to the byte length from the sized read; a DWORD read of
 *   CurrentMajorVersionNumber, if present, returns REG_DWORD; a missing key
 *   returns ERROR_FILE_NOT_FOUND (2); a missing value under the open key
 *   returns ERROR_FILE_NOT_FOUND. A missing API is a FAIL (Win10 22H2 has it).
 *
 * Source reference: curl's tree does not read HKLM. Its OS gating uses
 *   lib/curlx/version_win32.c:84 (curlx_verify_windows_version) instead of
 *   registry probes, so this test covers the registry surface on its own.
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
#define TEST_NAME "reg_hklm_readonly"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#define BASE_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

int main(void)
{
  HKEY key = NULL;
  LONG rc;
  DWORD type = 0, size = 0;
  wchar_t *data;
  DWORD i;

  rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, BASE_KEY, 0, KEY_READ, &key);
  if(rc == ERROR_FILE_NOT_FOUND) {
    printf("FAIL %s: %ls key absent on this host\n", TEST_NAME, BASE_KEY);
    return 1;
  }
  if(rc != ERROR_SUCCESS) {
    printf("FAIL %s: RegOpenKeyExW(HKLM\\%ls) rc=%ld\n", TEST_NAME, BASE_KEY, (long)rc);
    return 1;
  }

  /* Size query for CurrentBuildNumber (REG_SZ). */
  rc = RegQueryValueExW(key, L"CurrentBuildNumber", NULL, &type, NULL, &size);
  if(rc != ERROR_SUCCESS) {
    RegCloseKey(key);
    printf("FAIL %s: CurrentBuildNumber not readable (rc=%ld)\n", TEST_NAME, (long)rc);
    return 1;
  }
  if(type != REG_SZ) {
    RegCloseKey(key);
    printf("FAIL %s: CurrentBuildNumber type=%lu (want REG_SZ=1)\n",
           TEST_NAME, (unsigned long)type);
    return 1;
  }
  if(size < sizeof(wchar_t) || (size % sizeof(wchar_t)) != 0) {
    RegCloseKey(key);
    printf("FAIL %s: size query returned %lu bytes\n", TEST_NAME, (unsigned long)size);
    return 1;
  }

  data = (wchar_t *)malloc(size);
  if(!data) {
    RegCloseKey(key);
    printf("FAIL %s: malloc failed\n", TEST_NAME);
    return 1;
  }
  {
    DWORD sized = size, type2 = 0;
    rc = RegQueryValueExW(key, L"CurrentBuildNumber", NULL, &type2,
                          (LPBYTE)data, &sized);
    if(rc != ERROR_SUCCESS || type2 != REG_SZ || sized != size) {
      free(data);
      RegCloseKey(key);
      printf("FAIL %s: sized read rc=%ld type=%lu size=%lu (expected size %lu)\n",
             TEST_NAME, (long)rc, (unsigned long)type2, (unsigned long)sized,
             (unsigned long)size);
      return 1;
    }
  }
  {
    DWORD max_chars = size / (DWORD)sizeof(wchar_t);
    int terminated = 0;
    for(i = 0; i < max_chars; i++) {
      if(data[i] == L'\0') {
        terminated = 1;
        break;
      }
    }
    if(!terminated || i == 0) {
      free(data);
      RegCloseKey(key);
      printf("FAIL %s: CurrentBuildNumber is empty or not NUL-terminated\n", TEST_NAME);
      return 1;
    }
  }
  for(i = 0; data[i] != L'\0'; i++) {
    if(data[i] < L'0' || data[i] > L'9') {
      printf("FAIL %s: CurrentBuildNumber \"%ls\" is not all digits\n", TEST_NAME, data);
      free(data);
      RegCloseKey(key);
      return 1;
    }
  }
  free(data);

  /* DWORD read, optional value on older builds. */
  {
    DWORD dword_val = 0, dsize = sizeof(dword_val), dtype = 0;
    rc = RegQueryValueExW(key, L"CurrentMajorVersionNumber", NULL, &dtype,
                          (LPBYTE)&dword_val, &dsize);
    if(rc == ERROR_SUCCESS && dtype != REG_DWORD) {
      RegCloseKey(key);
      printf("FAIL %s: CurrentMajorVersionNumber type=%lu (want REG_DWORD=4)\n",
             TEST_NAME, (unsigned long)dtype);
      return 1;
    }
  }

  /* Missing value under an open key. */
  rc = RegQueryValueExW(key, L"CurlTestNoSuchValue_7f3a", NULL, NULL, NULL, NULL);
  if(rc != ERROR_FILE_NOT_FOUND) {
    RegCloseKey(key);
    printf("FAIL %s: missing value rc=%ld (want ERROR_FILE_NOT_FOUND=2)\n",
           TEST_NAME, (long)rc);
    return 1;
  }
  RegCloseKey(key);
  key = NULL;

  /* Missing key. */
  rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\CurlTestNoSuchKey_7f3a",
                     0, KEY_READ, &key);
  if(rc != ERROR_FILE_NOT_FOUND) {
    if(rc == ERROR_SUCCESS)
      RegCloseKey(key);
    printf("FAIL %s: missing key rc=%ld (want ERROR_FILE_NOT_FOUND=2)\n",
           TEST_NAME, (long)rc);
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
