/*
 * Test: 12_loadlibrary_rtlverifyversion
 * Purpose: Resolve an undocumented ntdll export with GetModuleHandle and
 *   GetProcAddress, as curl does for RtlVerifyVersionInfo, call it, and
 *   check the dynamic-load failure modes (missing export, missing DLL).
 *   ws2_32 is also loaded with LoadLibrary to check its exports; this is a
 *   test-only addition, not something curl does.
 * APIs: GetModuleHandleW, LoadLibraryW, GetProcAddress, FreeLibrary,
 *   VerSetConditionMask, RtlVerifyVersionInfo (resolved, not linked),
 *   GetLastError
 * Source: lib/curlx/version_win32.c:55-58 (curlx_verify_windows_init()
 *   does GetProcAddress(GetModuleHandle(TEXT("ntdll")),
 *   "RtlVerifyVersionInfo") and casts the result through
 *   CURLX_FUNCTION_CAST). curl links bcrypt directly (lib/curlx/winapi.c:109
 *   includes bcrypt.h and winapi.c:118 calls BCryptGenRandom), so bcrypt is
 *   not a dynamic-load example.
 * Success: RtlVerifyVersionInfo resolves; a major version of 1 satisfies
 *   VER_GREATER_EQUAL and returns 0; a major version of 999 does not
 *   (non-zero status); GetProcAddress for a missing export returns NULL
 *   with ERROR_PROC_NOT_FOUND (127); LoadLibraryW of a missing DLL returns
 *   NULL with ERROR_MOD_NOT_FOUND (126); ws2_32 loads and exports WSAPoll
 *   and WSAStartup.
 * SKIP: only under wine when ntdll lacks RtlVerifyVersionInfo.
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
#include <string.h>

#define TEST_NAME "12_loadlibrary_rtlverifyversion"

typedef LONG (APIENTRY *curl_test_rtlverify_fn)(OSVERSIONINFOEXW *, ULONG,
                                                ULONGLONG);

int main(void)
{
  HMODULE ntdll;
  HMODULE ws2;
  FARPROC p;
  curl_test_rtlverify_fn verify;
  OSVERSIONINFOEXW info;
  ULONGLONG cond = 0;
  LONG st;

  ntdll = GetModuleHandleW(L"ntdll.dll");
  if(!ntdll) {
    printf("FAIL %s: GetModuleHandleW(ntdll.dll) failed, GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }

  p = GetProcAddress(ntdll, "RtlVerifyVersionInfo");
  if(!p) {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if(nt && GetProcAddress(nt, "wine_get_version")) {
      printf("SKIP %s: wine ntdll does not export RtlVerifyVersionInfo\n", TEST_NAME);
      return 77;
    }
    printf("FAIL %s: ntdll does not export RtlVerifyVersionInfo\n", TEST_NAME);
    return 1;
  }
  /* curl casts through CURLX_FUNCTION_CAST; go through void* here */
  verify = (curl_test_rtlverify_fn)(void *)p;

  memset(&info, 0, sizeof(info));
  info.dwOSVersionInfoSize = sizeof(info);
  info.dwMajorVersion = 1;
  info.dwMinorVersion = 0;
  cond = VerSetConditionMask(cond, VER_MAJORVERSION, VER_GREATER_EQUAL);
  st = verify(&info, VER_MAJORVERSION, cond);
  if(st != 0) {
    printf("FAIL %s: RtlVerifyVersionInfo(major>=1) returned 0x%08lx\n",
           TEST_NAME, (unsigned long)st);
    return 1;
  }

  info.dwMajorVersion = 999;
  st = verify(&info, VER_MAJORVERSION, cond);
  if(st == 0) {
    printf("FAIL %s: RtlVerifyVersionInfo(major>=999) unexpectedly succeeded\n",
           TEST_NAME);
    return 1;
  }

  /* Missing export: NULL and ERROR_PROC_NOT_FOUND */
  SetLastError(0);
  p = GetProcAddress(ntdll, "CurlTestNoSuchExport_xyz");
  if(p != NULL || GetLastError() != ERROR_PROC_NOT_FOUND) {
    printf("FAIL %s: missing export gave p=%p GetLastError=%lu\n", TEST_NAME,
           (void *)p, (unsigned long)GetLastError());
    return 1;
  }

  /* Missing DLL: NULL and ERROR_MOD_NOT_FOUND */
  SetLastError(0);
  ws2 = LoadLibraryW(L"curl_test_no_such_module_xyz.dll");
  if(ws2 != NULL || GetLastError() != ERROR_MOD_NOT_FOUND) {
    printf("FAIL %s: missing DLL gave handle=%p GetLastError=%lu\n", TEST_NAME,
           (void *)ws2, (unsigned long)GetLastError());
    if(ws2)
      FreeLibrary(ws2);
    return 1;
  }

  /* Winsock is loaded the way curl loads optional modules */
  ws2 = LoadLibraryW(L"ws2_32.dll");
  if(!ws2) {
    printf("FAIL %s: ws2_32.dll could not be loaded, GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }
  if(!GetProcAddress(ws2, "WSAStartup") || !GetProcAddress(ws2, "WSAPoll")) {
    printf("FAIL %s: ws2_32 is missing WSAStartup or WSAPoll, "
           "GetLastError=%lu\n", TEST_NAME, (unsigned long)GetLastError());
    FreeLibrary(ws2);
    return 1;
  }
  FreeLibrary(ws2);

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
