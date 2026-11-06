/*
 * Test: icmp_create_file_dynamic
 *
 * Purpose: Resolve IcmpCreateFile and IcmpCloseHandle at run time from
 *   iphlpapi.dll with LoadLibraryW/GetProcAddress, instead of linking them,
 *   and verify that the ICMP echo handle lifecycle works: two handles can be
 *   created, both are valid and distinct, and both close successfully.
 *   A missing iphlpapi or export is a FAIL (present on Win10 22H2).
 *
 * APIs: LoadLibraryW, GetProcAddress, FreeLibrary, IcmpCreateFile,
 *   IcmpCloseHandle (iphlpapi.dll, resolved dynamically).
 *
 * Success means: both IcmpCreateFile calls return a handle other than
 *   INVALID_HANDLE_VALUE, the handles differ, and IcmpCloseHandle returns
 *   TRUE for each. No echo packet is sent, so no network traffic occurs.
 *
 * Source reference: none. curl's tree has no IcmpCreateFile call site; this
 *   covers the ICMP handle primitive for the network-configuration corpus.
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
#define TEST_NAME "icmp_create_file_dynamic"

#include <windows.h>
#include <stdio.h>

typedef HANDLE (WINAPI *IcmpCreateFile_fn)(void);
typedef BOOL (WINAPI *IcmpCloseHandle_fn)(HANDLE);

int main(void)
{
  HMODULE lib;
  IcmpCreateFile_fn p_create;
  IcmpCloseHandle_fn p_close;
  HANDLE h1, h2;
  BOOL ok1, ok2;

  lib = LoadLibraryW(L"iphlpapi.dll");
  if(!lib) {
    printf("FAIL %s: iphlpapi.dll not loadable (GetLastError=%lu)\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }

  p_create = (IcmpCreateFile_fn)(void *)GetProcAddress(lib, "IcmpCreateFile");
  p_close = (IcmpCloseHandle_fn)(void *)GetProcAddress(lib, "IcmpCloseHandle");
  if(!p_create || !p_close) {
    FreeLibrary(lib);
    printf("FAIL %s: IcmpCreateFile/IcmpCloseHandle export absent (GetLastError=%lu)\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }

  h1 = p_create();
  if(h1 == INVALID_HANDLE_VALUE || h1 == NULL) {
    FreeLibrary(lib);
    printf("FAIL %s: first IcmpCreateFile failed GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }

  h2 = p_create();
  if(h2 == INVALID_HANDLE_VALUE || h2 == NULL) {
    p_close(h1);
    FreeLibrary(lib);
    printf("FAIL %s: second IcmpCreateFile failed GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    return 1;
  }

  if(h1 == h2) {
    p_close(h1);
    p_close(h2);
    FreeLibrary(lib);
    printf("FAIL %s: two IcmpCreateFile calls returned the same handle\n", TEST_NAME);
    return 1;
  }

  ok1 = p_close(h1);
  ok2 = p_close(h2);
  FreeLibrary(lib);
  if(!ok1 || !ok2) {
    printf("FAIL %s: IcmpCloseHandle returned FALSE (h1=%d h2=%d) GetLastError=%lu\n",
           TEST_NAME, (int)ok1, (int)ok2, (unsigned long)GetLastError());
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
