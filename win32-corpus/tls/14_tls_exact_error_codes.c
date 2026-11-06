/*
 * Test: 14_tls_exact_error_codes
 * Area: tls
 * Purpose: Pin the exact last-error values of the TLS/FLS API on Win10 22H2.
 *   curl's threaded code (Curl_thread_create, easy handles, OpenSSL/Schannel
 *   per-thread state) uses TlsGetValue and relies on its SetLastError(0)
 *   side effect on success, so an unset slot must not be mistaken for an error.
 * APIs: TlsAlloc, TlsGetValue, TlsSetValue, TlsFree, FlsAlloc, FlsGetValue,
 *   FlsSetValue, FlsFree, SetLastError, GetLastError.
 * Success means (values probed on Win10 22H2): TlsGetValue on a live slot
 *   with no value returns NULL and sets last error to 0 even when it was 1234;
 *   TlsGetValue/TlsSetValue/TlsFree on TLS_OUT_OF_INDEXES fail with
 *   ERROR_INVALID_PARAMETER (87); TlsGetValue of a value after TlsSetValue
 *   leaves last error 0; TlsFree twice: second call fails with 87;
 *   TlsSetValue on an already-freed in-range index is probed (INFO) only;
 *   same for FlsGetValue/FlsSetValue/FlsFree on FLS_OUT_OF_INDEXES (87).
 * Exit: 0 PASS, 1 FAIL.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define EXPECT(cond, ...) do { if(!(cond)) { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); fflush(stdout); return 1; } } while(0)
#define INFO(...) do { printf("INFO "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while(0)

#define TEST_NAME "14_tls_exact_error_codes"

int main(void)
{
  DWORD i, f;
  void *v;
  DWORD e;

  i = TlsAlloc();
  EXPECT(i != TLS_OUT_OF_INDEXES, "TlsAlloc");
  SetLastError(1234);
  v = TlsGetValue(i);
  e = GetLastError();
  INFO("TlsGetValue(unset) v=%p gle=%lu", v, e);
  EXPECT(v == NULL && e == 0, "unset slot: v=%p gle=%lu want NULL,0", v, e);
  EXPECT(TlsSetValue(i, (void *)(uintptr_t)0x1234), "TlsSetValue");
  SetLastError(1234);
  v = TlsGetValue(i);
  e = GetLastError();
  EXPECT(v == (void *)(uintptr_t)0x1234 && e == 0, "set slot: v=%p gle=%lu", v, e);

  SetLastError(0);
  v = TlsGetValue(TLS_OUT_OF_INDEXES); e = GetLastError();
  INFO("TlsGetValue(OOI) gle=%lu", e);
  EXPECT(v == NULL && e == ERROR_INVALID_PARAMETER, "TlsGetValue(OOI) gle=%lu want 87", e);
  SetLastError(0);
  EXPECT(!TlsSetValue(TLS_OUT_OF_INDEXES, NULL), "TlsSetValue(OOI) succeeded");
  e = GetLastError();
  INFO("TlsSetValue(OOI) gle=%lu", e);
  EXPECT(e == ERROR_INVALID_PARAMETER, "TlsSetValue(OOI) gle=%lu want 87", e);
  SetLastError(0);
  EXPECT(!TlsFree(TLS_OUT_OF_INDEXES), "TlsFree(OOI) succeeded");
  e = GetLastError();
  INFO("TlsFree(OOI) gle=%lu", e);
  EXPECT(e == ERROR_INVALID_PARAMETER, "TlsFree(OOI) gle=%lu want 87", e);

  EXPECT(TlsFree(i), "TlsFree");
  SetLastError(0);
  EXPECT(!TlsFree(i), "second TlsFree succeeded");
  e = GetLastError();
  INFO("TlsFree(twice) gle=%lu", e);
  EXPECT(e == ERROR_INVALID_PARAMETER, "second TlsFree gle=%lu want 87", e);
  /* Win10 22H2: TlsSetValue/TlsGetValue on a freed (in-range) index do not fail. */
  SetLastError(1234);
  e = TlsSetValue(i, NULL) ? 1 : 0;
  INFO("TlsSetValue(freed) ok=%lu gle=%lu", e, GetLastError());
  v = TlsGetValue(i);
  INFO("TlsGetValue(freed) v=%p gle=%lu", v, GetLastError());

  SetLastError(0);
  v = FlsGetValue(FLS_OUT_OF_INDEXES); e = GetLastError();
  INFO("FlsGetValue(OOI) gle=%lu", e);
  EXPECT(v == NULL && e == ERROR_INVALID_PARAMETER, "FlsGetValue(OOI) gle=%lu want 87", e);
  SetLastError(0);
  EXPECT(!FlsSetValue(FLS_OUT_OF_INDEXES, NULL), "FlsSetValue(OOI) succeeded");
  e = GetLastError();
  INFO("FlsSetValue(OOI) gle=%lu", e);
  EXPECT(e == ERROR_INVALID_PARAMETER, "FlsSetValue(OOI) gle=%lu want 87", e);
  SetLastError(0);
  EXPECT(!FlsFree(FLS_OUT_OF_INDEXES), "FlsFree(OOI) succeeded");
  e = GetLastError();
  INFO("FlsFree(OOI) gle=%lu", e);
  EXPECT(e == ERROR_INVALID_PARAMETER, "FlsFree(OOI) gle=%lu want 87", e);

  f = FlsAlloc(NULL);
  EXPECT(f != FLS_OUT_OF_INDEXES, "FlsAlloc");
  SetLastError(1234);
  v = FlsGetValue(f); e = GetLastError();
  INFO("FlsGetValue(unset) v=%p gle=%lu", v, e);
  EXPECT(v == NULL && e == 0, "FlsGetValue(unset) gle=%lu want 0", e);
  EXPECT(FlsFree(f), "FlsFree");
  SetLastError(0);
  EXPECT(!FlsFree(f), "second FlsFree succeeded");
  e = GetLastError();
  INFO("FlsFree(twice) gle=%lu", e);
  EXPECT(e == ERROR_INVALID_PARAMETER, "second FlsFree gle=%lu want 87", e);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
