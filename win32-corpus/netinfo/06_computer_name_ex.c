/*
 * Test: computer_name_ex
 *
 * Purpose: Read the local host name through GetComputerNameExW for the
 *   NetBIOS and DNS name classes using the size-query protocol, and check
 *   the result against the legacy GetComputerNameW. Also covers the failure
 *   path for an invalid COMPUTER_NAME_FORMAT value.
 *
 * APIs: GetComputerNameExW, GetComputerNameW (kernel32).
 *
 * Success means: ComputerNameNetBIOS with a NULL buffer returns FALSE with
 *   ERROR_MORE_DATA and a required size that includes the terminating NUL;
 *   a sized call returns TRUE with the size equal to wcslen(buffer); the
 *   NetBIOS name equals GetComputerNameW case-insensitively (truncated to
 *   MAX_COMPUTERNAME_LENGTH=15); ComputerNameDnsHostname returns a non-empty
 *   name of at most 63 characters; ComputerNameMax (invalid format 99)
 *   returns FALSE with ERROR_INVALID_PARAMETER.
 *
 * Source reference: none. curl's tree has no GetComputerNameExW call site;
 *   included to cover the local host-name query surface for the corpus.
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
#define TEST_NAME "computer_name_ex"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static wchar_t lower_w(wchar_t c)
{
  return (c >= L'A' && c <= L'Z') ? (wchar_t)(c - L'A' + L'a') : c;
}

static BOOL same_name_ci(const wchar_t *a, const wchar_t *b, size_t n)
{
  size_t i;
  for(i = 0; i < n; i++) {
    if(lower_w(a[i]) != lower_w(b[i]))
      return FALSE;
    if(a[i] == L'\0' || b[i] == L'\0')
      return a[i] == b[i];
  }
  return TRUE;
}

/* Reads one COMPUTER_NAME_FORMAT class. Returns 0 on success. */
static int read_name(COMPUTER_NAME_FORMAT fmt, wchar_t **out, DWORD *len_out,
                     DWORD *err_out)
{
  DWORD size = 0;
  wchar_t *buf;
  BOOL ok;

  ok = GetComputerNameExW(fmt, NULL, &size);
  if(ok) {
    *err_out = 0;
    return 2; /* unexpected success with no buffer */
  }
  if(GetLastError() != ERROR_MORE_DATA) {
    *err_out = GetLastError();
    return 1;
  }
  if(size < 2) {
    *err_out = 0;
    return 3;
  }
  buf = (wchar_t *)malloc(size * sizeof(wchar_t));
  if(!buf) {
    *err_out = ERROR_NOT_ENOUGH_MEMORY;
    return 1;
  }
  {
    DWORD required = size;
    ok = GetComputerNameExW(fmt, buf, &size);
    if(!ok) {
      *err_out = GetLastError();
      free(buf);
      return 1;
    }
    if(size != (DWORD)wcslen(buf) || size + 1 > required) {
      *err_out = 0;
      free(buf);
      return 4;
    }
  }
  *out = buf;
  *len_out = size;
  *err_out = 0;
  return 0;
}

int main(void)
{
  wchar_t *netbios = NULL, *dns = NULL;
  DWORD nb_len = 0, dns_len = 0, err = 0, legacy_size = MAX_COMPUTERNAME_LENGTH + 1;
  wchar_t legacy[MAX_COMPUTERNAME_LENGTH + 1];
  int rc;

  rc = read_name(ComputerNameNetBIOS, &netbios, &nb_len, &err);
  if(rc == 1) {
    printf("FAIL %s: ComputerNameNetBIOS size query/read GetLastError=%lu\n",
           TEST_NAME, (unsigned long)err);
    return 1;
  }
  if(rc != 0) {
    printf("FAIL %s: ComputerNameNetBIOS protocol violation (code=%d)\n", TEST_NAME, rc);
    return 1;
  }
  if(nb_len == 0) {
    free(netbios);
    printf("FAIL %s: NetBIOS computer name is empty\n", TEST_NAME);
    return 1;
  }

  if(!GetComputerNameW(legacy, &legacy_size)) {
    free(netbios);
    printf("FAIL %s: GetComputerNameW GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }
  if(legacy_size == 0 || wcslen(legacy) == 0) {
    free(netbios);
    printf("FAIL %s: GetComputerNameW returned an empty name\n", TEST_NAME);
    return 1;
  }
  if(!same_name_ci(netbios, legacy, MAX_COMPUTERNAME_LENGTH)) {
    printf("FAIL %s: NetBIOS name differs from GetComputerNameW\n", TEST_NAME);
    free(netbios);
    return 1;
  }
  free(netbios);

  rc = read_name(ComputerNameDnsHostname, &dns, &dns_len, &err);
  if(rc != 0) {
    printf("FAIL %s: ComputerNameDnsHostname read failed (code=%d GetLastError=%lu)\n",
           TEST_NAME, rc, (unsigned long)err);
    return 1;
  }
  if(dns_len == 0 || dns_len > 63) {
    free(dns);
    printf("FAIL %s: DNS host name length %lu outside 1..63\n",
           TEST_NAME, (unsigned long)dns_len);
    return 1;
  }
  free(dns);

  SetLastError(0);
  if(GetComputerNameExW((COMPUTER_NAME_FORMAT)99, legacy, &legacy_size)) {
    printf("FAIL %s: invalid COMPUTER_NAME_FORMAT 99 unexpectedly succeeded\n", TEST_NAME);
    return 1;
  }
  if(GetLastError() != ERROR_INVALID_PARAMETER) {
    printf("FAIL %s: invalid format error=%lu (want ERROR_INVALID_PARAMETER=87)\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
