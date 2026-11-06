/*
 * Test: internet_settings_registry
 * Area: netinfo
 * Purpose: Proxy detection on Windows reads the per-user Internet Settings
 *   key (WinINet/WinHTTP "IE proxy"); tools that mimic curl's system-proxy
 *   behaviour read ProxyEnable/ProxyServer/AutoConfigURL from HKCU. Verify the
 *   key is readable read-only by the test user with the documented value types
 *   and that write access is not needed.
 * APIs: RegOpenKeyExW, RegQueryValueExW, RegCloseKey,
 *   WinHttpGetIEProxyConfigForCurrentUser (winhttp, via LoadLibrary).
 * Success means: HKCU\Software\Microsoft\Windows\CurrentVersion\Internet
 *   Settings opens with KEY_READ; ProxyEnable, when present, is REG_DWORD of
 *   4 bytes; ProxyServer, AutoConfigURL, ProxyOverride, when present, are
 *   REG_SZ; a value that does not exist returns ERROR_FILE_NOT_FOUND (2);
 *   WinHttpGetIEProxyConfigForCurrentUser succeeds and its auto-detect flag
 *   agrees (when ProxyEnable is 1, lpszProxy is non-NULL).
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
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define EXPECT(cond, ...) do { if(!(cond)) { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } } while(0)
#define INFO(...) do { printf("INFO "); printf(__VA_ARGS__); printf("\n"); } while(0)

#define TEST_NAME "internet_settings_registry"

typedef struct { BOOL fAutoDetect; LPWSTR lpszAutoConfigUrl; LPWSTR lpszProxy; LPWSTR lpszProxyBypass; } IEPC;
typedef BOOL (WINAPI *IEPC_fn)(IEPC *);

int main(void)
{
  HKEY k;
  LONG rc;
  DWORD type = 0, sz = 0, pe = 0;
  const wchar_t *sv[] = { L"ProxyServer", L"AutoConfigURL", L"ProxyOverride" };
  size_t i;
  HMODULE wh;
  IEPC_fn fn;
  IEPC cfg;

  rc = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &k);
  EXPECT(rc == ERROR_SUCCESS, "RegOpenKeyExW rc=%ld", (long)rc);
  sz = sizeof(pe);
  rc = RegQueryValueExW(k, L"ProxyEnable", NULL, &type, (BYTE *)&pe, &sz);
  INFO("ProxyEnable rc=%ld type=%lu size=%lu val=%lu", (long)rc, type, sz, pe);
  if(rc == ERROR_SUCCESS)
    EXPECT(type == REG_DWORD && sz == 4, "ProxyEnable type=%lu size=%lu", type, sz);
  else
    EXPECT(rc == ERROR_FILE_NOT_FOUND, "ProxyEnable rc=%ld", (long)rc);
  for(i = 0; i < 3; i++) {
    wchar_t buf[2048]; sz = sizeof(buf);
    rc = RegQueryValueExW(k, sv[i], NULL, &type, (BYTE *)buf, &sz);
    INFO("%ls rc=%ld type=%lu", sv[i], (long)rc, type);
    if(rc == ERROR_SUCCESS) EXPECT(type == REG_SZ, "%ls type=%lu", sv[i], type);
    else EXPECT(rc == ERROR_FILE_NOT_FOUND, "%ls rc=%ld", sv[i], (long)rc);
  }
  sz = 0;
  rc = RegQueryValueExW(k, L"NoSuchValueForCurlCorpus", NULL, &type, NULL, &sz);
  EXPECT(rc == ERROR_FILE_NOT_FOUND, "missing value rc=%ld want 2", (long)rc);
  RegCloseKey(k);

  wh = LoadLibraryW(L"winhttp.dll");
  EXPECT(wh != NULL, "winhttp.dll load %lu", GetLastError());
  fn = (IEPC_fn)(void *)GetProcAddress(wh, "WinHttpGetIEProxyConfigForCurrentUser");
  EXPECT(fn != NULL, "WinHttpGetIEProxyConfigForCurrentUser not exported");
  memset(&cfg, 0, sizeof(cfg));
  EXPECT(fn(&cfg), "WinHttpGetIEProxyConfigForCurrentUser err=%lu", GetLastError());
  INFO("autodetect=%d proxy=%ls pac=%ls", (int)cfg.fAutoDetect, cfg.lpszProxy ? cfg.lpszProxy : L"(null)", cfg.lpszAutoConfigUrl ? cfg.lpszAutoConfigUrl : L"(null)");
  if(pe == 1) EXPECT(cfg.lpszProxy != NULL, "ProxyEnable=1 but lpszProxy NULL");
  if(cfg.lpszProxy) GlobalFree(cfg.lpszProxy);
  if(cfg.lpszAutoConfigUrl) GlobalFree(cfg.lpszAutoConfigUrl);
  if(cfg.lpszProxyBypass) GlobalFree(cfg.lpszProxyBypass);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
