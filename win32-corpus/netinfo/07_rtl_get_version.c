/*
 * Test: rtl_get_version
 *
 * Purpose: Read the OS version through ntdll!RtlGetVersion, which is
 *   resolved with GetModuleHandleW/GetProcAddress, rather than the
 *   deprecated and manifest-dependent GetVersionEx. This is the call that
 *   reports the real version independent of the application manifest.
 *
 * APIs: GetModuleHandleW, GetProcAddress, RtlGetVersion (ntdll, undocumented
 *   export, resolved at run time), RTL_OSVERSIONINFOW (local definition).
 *
 * Success means: RtlGetVersion returns STATUS_SUCCESS (0); dwPlatformId is
 *   VER_PLATFORM_WIN32_NT (2); the major version is at least 5; the build
 *   number is nonzero; dwOSVersionInfoSize is unchanged by the call; and the
 *   szCSDVersion buffer is NUL-terminated within its 128 characters (the
 *   buffer is prefilled with a non-zero sentinel before the call, so the
 *   terminator must be written by RtlGetVersion).
 *   A missing API is a FAIL (Win10 22H2 has it).
 *
 * Source reference: lib/curlx/version_win32.c:57-58 resolves ntdll exports
 *   with GetProcAddress(GetModuleHandle(TEXT("ntdll")), ...) and
 *   lib/curlx/version_win32.c:33-46 defines the matching OSVERSIONINFOEXW
 *   layout that this test mirrors for RTL_OSVERSIONINFOW.
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
#define TEST_NAME "rtl_get_version"

#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

typedef struct {
  ULONG dwOSVersionInfoSize;
  ULONG dwMajorVersion;
  ULONG dwMinorVersion;
  ULONG dwBuildNumber;
  ULONG dwPlatformId;
  WCHAR szCSDVersion[128];
} OUR_RTL_OSVERSIONINFOW;

typedef LONG (WINAPI *RtlGetVersion_fn)(OUR_RTL_OSVERSIONINFOW *);

int main(void)
{
  HMODULE ntdll;
  RtlGetVersion_fn p_rtl;
  OUR_RTL_OSVERSIONINFOW osv;
  LONG status;
  size_t i;
  BOOL terminated = FALSE;

  ntdll = GetModuleHandleW(L"ntdll.dll");
  if(!ntdll) {
    printf("FAIL %s: ntdll.dll not mapped (GetLastError=%lu)\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }
  p_rtl = (RtlGetVersion_fn)(void *)GetProcAddress(ntdll, "RtlGetVersion");
  if(!p_rtl) {
    printf("FAIL %s: RtlGetVersion export absent (GetLastError=%lu)\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }

  memset(&osv, 0, sizeof(osv));
  osv.dwOSVersionInfoSize = sizeof(osv);
  for(i = 0; i < 128; i++)
    osv.szCSDVersion[i] = (WCHAR)0xFFFF; /* non-zero sentinel */
  status = p_rtl(&osv);
  if(status != 0) {
    printf("FAIL %s: RtlGetVersion returned NTSTATUS 0x%08lx\n",
           TEST_NAME, (unsigned long)status);
    return 1;
  }
  if(osv.dwOSVersionInfoSize != sizeof(osv)) {
    printf("FAIL %s: dwOSVersionInfoSize changed to %lu\n",
           TEST_NAME, (unsigned long)osv.dwOSVersionInfoSize);
    return 1;
  }
  if(osv.dwPlatformId != VER_PLATFORM_WIN32_NT) {
    printf("FAIL %s: dwPlatformId=%lu (want VER_PLATFORM_WIN32_NT=2)\n",
           TEST_NAME, (unsigned long)osv.dwPlatformId);
    return 1;
  }
  if(osv.dwMajorVersion < 5) {
    printf("FAIL %s: dwMajorVersion=%lu below 5\n",
           TEST_NAME, (unsigned long)osv.dwMajorVersion);
    return 1;
  }
  if(osv.dwBuildNumber == 0) {
    printf("FAIL %s: dwBuildNumber is 0\n", TEST_NAME);
    return 1;
  }
  for(i = 0; i < 128; i++) {
    if(osv.szCSDVersion[i] == L'\0') {
      terminated = TRUE;
      break;
    }
  }
  if(!terminated) {
    printf("FAIL %s: szCSDVersion not NUL-terminated within 128 characters\n", TEST_NAME);
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
