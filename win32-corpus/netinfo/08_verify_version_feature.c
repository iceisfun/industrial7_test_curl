/*
 * Test: verify_version_feature
 *
 * Purpose: Feature-detect the OS the way curl does, with VerifyVersionInfoW
 *   and a VerSetConditionMask condition mask, rather than comparing against
 *   GetVersion. Implements an IsWindows8OrGreater-style check and the
 *   build-number refinement curl applies when major.minor are equal.
 *   Verifies that the answers agree with RtlGetVersion (resolved at run
 *   time from ntdll) and that failing checks report ERROR_OLD_WIN_VERSION.
 *
 * APIs: VerifyVersionInfoW, VerSetConditionMask (kernel32), RtlGetVersion
 *   (ntdll, resolved with GetProcAddress), OSVERSIONINFOEXW.
 *
 * Without an application manifest VerifyVersionInfoW sees a compatibility-
 *   shimmed OS version (Win10 22H2 oracle, every run): a build-only
 *   comparison GE(real build) is FALSE with ERROR_OLD_WIN_VERSION, while
 *   GE(1) is TRUE; the combined 10.0.16299 and 10.0.19045 checks are FALSE
 *   as well. RtlVerifyVersionInfo (ntdll) gives the true answer, which is
 *   why curl resolves it at run time. This test pins both behaviours.
 *
 * Success means: GE(6.2) matches (RtlGetVersion major.minor >= 6.2); GE(99.0)
 *   is FALSE with GetLastError()==ERROR_OLD_WIN_VERSION (1150); GE(5.0) is
 *   TRUE; GE(6.2) TRUE implies GE(6.1) TRUE (monotonic); the real build check
 *   through RtlVerifyVersionInfo is GE(current build) STATUS_SUCCESS and
 *   GE(current build + 1) STATUS_REVISION_MISMATCH (0xC0000059); the
 *   VerifyVersionInfoW build-only check shows the shim described above. A missing API is a FAIL (Win10 22H2 has it).
 *
 * Source reference: lib/curlx/version_win32.c:84-236
 *   (curlx_verify_windows_version) builds the same mask with
 *   VerSetConditionMask and calls VerifyVersionInfoW, or RtlVerifyVersionInfo
 *   when resolved (lines 57-58). Its callers include lib/vtls/schannel_verify.c:506
 *   (6.2 gate) and lib/cf-socket.c:209 (10.0.16299 gate).
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
#define TEST_NAME "verify_version_feature"

#include <windows.h>
#include <stdio.h>
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
typedef LONG (WINAPI *RtlVerifyVersionInfo_fn)(OSVERSIONINFOEXW *, ULONG, ULONGLONG);

static LONG rtl_verify_build(RtlVerifyVersionInfo_fn fn, DWORD build, BYTE cond)
{
  OSVERSIONINFOEXW osvi;
  memset(&osvi, 0, sizeof(osvi));
  osvi.dwOSVersionInfoSize = sizeof(osvi);
  osvi.dwBuildNumber = build;
  return fn(&osvi, VER_BUILDNUMBER, VerSetConditionMask(0, VER_BUILDNUMBER, cond));
}

/* Returns TRUE if the running OS is >= (or <=, per cond) major.minor(.build).
 * On a failing check, *err receives GetLastError(). */
static BOOL verify_ver(DWORD major, DWORD minor, BYTE cond, DWORD *err)
{
  OSVERSIONINFOEXW osvi;
  DWORDLONG mask = 0;
  DWORD type_mask = VER_MAJORVERSION | VER_MINORVERSION | VER_PLATFORMID;
  BOOL ok;

  memset(&osvi, 0, sizeof(osvi));
  osvi.dwOSVersionInfoSize = sizeof(osvi);
  osvi.dwMajorVersion = major;
  osvi.dwMinorVersion = minor;
  osvi.dwPlatformId = VER_PLATFORM_WIN32_NT;

  mask = VerSetConditionMask(mask, VER_MAJORVERSION, cond);
  mask = VerSetConditionMask(mask, VER_MINORVERSION, cond);
  mask = VerSetConditionMask(mask, VER_PLATFORMID, VER_EQUAL);

  SetLastError(0);
  ok = VerifyVersionInfoW(&osvi, type_mask, mask);
  *err = ok ? 0 : GetLastError();
  return ok;
}

/* Build comparison as in curl: a separate VerifyVersionInfoW call that
 * compares only VER_BUILDNUMBER. */
static BOOL verify_build(DWORD build, BYTE cond, DWORD *err)
{
  OSVERSIONINFOEXW osvi;
  DWORDLONG mask;
  BOOL ok;

  memset(&osvi, 0, sizeof(osvi));
  osvi.dwOSVersionInfoSize = sizeof(osvi);
  osvi.dwBuildNumber = build;
  mask = VerSetConditionMask(0, VER_BUILDNUMBER, cond);

  SetLastError(0);
  ok = VerifyVersionInfoW(&osvi, VER_BUILDNUMBER, mask);
  *err = ok ? 0 : GetLastError();
  return ok;
}

int main(void)
{
  HMODULE ntdll;
  RtlGetVersion_fn p_rtl;
  OUR_RTL_OSVERSIONINFOW real;
  BOOL ge62, ge99, ge50, ge61, expect62, bge, bgt;
  RtlVerifyVersionInfo_fn p_rvi;
  LONG st;
  DWORD err = 0;

  ntdll = GetModuleHandleW(L"ntdll.dll");
  p_rtl = ntdll ? (RtlGetVersion_fn)(void *)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
  if(!p_rtl) {
    printf("FAIL %s: RtlGetVersion unavailable to cross-check\n", TEST_NAME);
    return 1;
  }
  memset(&real, 0, sizeof(real));
  real.dwOSVersionInfoSize = sizeof(real);
  if(p_rtl(&real) != 0) {
    printf("FAIL %s: RtlGetVersion failed\n", TEST_NAME);
    return 1;
  }

  /* IsWindows8OrGreater-style check. */
  ge62 = verify_ver(6, 2, VER_GREATER_EQUAL, &err);
  expect62 = (real.dwMajorVersion > 6) ||
             (real.dwMajorVersion == 6 && real.dwMinorVersion >= 2);
  if(ge62 != expect62) {
    printf("FAIL %s: VerifyVersionInfoW GE 6.2=%d but RtlGetVersion says %lu.%lu\n",
           TEST_NAME, (int)ge62, (unsigned long)real.dwMajorVersion,
           (unsigned long)real.dwMinorVersion);
    return 1;
  }

  /* Far-future version must fail with ERROR_OLD_WIN_VERSION. */
  ge99 = verify_ver(99, 0, VER_GREATER_EQUAL, &err);
  if(ge99) {
    printf("FAIL %s: VerifyVersionInfoW GE 99.0 unexpectedly TRUE\n", TEST_NAME);
    return 1;
  }
  if(err != ERROR_OLD_WIN_VERSION) {
    printf("FAIL %s: GE 99.0 failed with GetLastError=%lu (want ERROR_OLD_WIN_VERSION=1150)\n",
           TEST_NAME, (unsigned long)err);
    return 1;
  }

  /* 5.0 is the floor of any NT the corpus runs on. */
  ge50 = verify_ver(5, 0, VER_GREATER_EQUAL, &err);
  if(!ge50) {
    printf("FAIL %s: GE 5.0 is FALSE on NT %lu.%lu (err=%lu)\n",
           TEST_NAME, (unsigned long)real.dwMajorVersion,
           (unsigned long)real.dwMinorVersion, (unsigned long)err);
    return 1;
  }

  /* Monotonicity: GE 6.2 implies GE 6.1. */
  ge61 = verify_ver(6, 1, VER_GREATER_EQUAL, &err);
  if(ge62 && !ge61) {
    printf("FAIL %s: GE 6.2 TRUE but GE 6.1 FALSE\n", TEST_NAME);
    return 1;
  }

  /* Build refinement via RtlVerifyVersionInfo (what curlx resolves). */
  p_rvi = (RtlVerifyVersionInfo_fn)(void *)GetProcAddress(ntdll, "RtlVerifyVersionInfo");
  if(!p_rvi) {
    printf("FAIL %s: ntdll!RtlVerifyVersionInfo not exported\n", TEST_NAME);
    return 1;
  }
  st = rtl_verify_build(p_rvi, real.dwBuildNumber, VER_GREATER_EQUAL);
  if(st != 0) {
    printf("FAIL %s: RtlVerifyVersionInfo GE build %lu = 0x%08lX, want 0\n",
           TEST_NAME, (unsigned long)real.dwBuildNumber, (unsigned long)st);
    return 1;
  }
  st = rtl_verify_build(p_rvi, real.dwBuildNumber + 1, VER_GREATER_EQUAL);
  if((unsigned long)st != 0xC0000059UL) {
    printf("FAIL %s: RtlVerifyVersionInfo GE build+1 = 0x%08lX, want STATUS_REVISION_MISMATCH\n",
           TEST_NAME, (unsigned long)st);
    return 1;
  }

  /* No manifest: VerifyVersionInfoW sees the shimmed version. */
  bge = verify_build(1, VER_GREATER_EQUAL, &err);
  if(!bge) {
    printf("FAIL %s: VerifyVersionInfoW GE build 1 is FALSE (err=%lu)\n", TEST_NAME, (unsigned long)err);
    return 1;
  }
  bgt = verify_build(real.dwBuildNumber, VER_GREATER_EQUAL, &err);
  if(bgt || err != ERROR_OLD_WIN_VERSION) {
    printf("FAIL %s: unmanifested VerifyVersionInfoW GE real build %lu: ok=%d err=%lu (Win10 22H2: FALSE, 1150)\n",
           TEST_NAME, (unsigned long)real.dwBuildNumber, (int)bgt, (unsigned long)err);
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
