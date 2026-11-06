/*
 * Test: dynamic_bcrypt_crypt32_load
 *
 * Purpose: resolve the random-number and certificate entry points at run time
 *   with LoadLibraryW and GetProcAddress rather than linking them, which is the
 *   pattern used for APIs that are optional on older Windows. Covers
 *   bcrypt.dll BCryptGenRandom and BCryptOpenAlgorithmProvider /
 *   BCryptCloseAlgorithmProvider, and crypt32.dll CertOpenStore /
 *   CertCloseStore with a memory store. Each module is freed at the end.
 *
 * APIs: LoadLibraryW(L"bcrypt.dll"), LoadLibraryW(L"crypt32.dll"),
 *       GetProcAddress (BCryptGenRandom, BCryptOpenAlgorithmProvider,
 *       BCryptCloseAlgorithmProvider, CertOpenStore, CertCloseStore),
 *       FreeLibrary
 *
 * Success: both modules load, every needed export resolves, BCryptGenRandom
 *   through the resolved pointer returns STATUS_SUCCESS with non-zero output,
 *   a provider opened through the resolved pointer closes successfully, and
 *   CertOpenStore(CERT_STORE_PROV_MEMORY) returns a handle that CertCloseStore
 *   accepts. FAIL when a module or export is absent (all exist on Win10).
 *
 * Source: the dynamic lookup mirrors the GetProcAddress use in
 *   lib/curlx/version_win32.c:58 and lib/vtls/schannel.c:2625 (both resolve
 *   ntdll exports). curl does not LoadLibrary bcrypt or crypt32; it links them
 *   (bcrypt at lib/curlx/winapi.c:118, CertOpenStore at lib/vtls/schannel.c:547).
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
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>

#define NAME "dynamic_bcrypt_crypt32_load"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef NTSTATUS (WINAPI *pfn_BCryptGenRandom)(BCRYPT_ALG_HANDLE, PUCHAR,
                                               ULONG, ULONG);
typedef NTSTATUS (WINAPI *pfn_BCryptOpenAlgorithmProvider)(
  BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *pfn_BCryptCloseAlgorithmProvider)(
  BCRYPT_ALG_HANDLE, ULONG);
typedef HCERTSTORE (WINAPI *pfn_CertOpenStore)(LPCSTR, DWORD, HCRYPTPROV,
                                               DWORD, const void *);
typedef BOOL (WINAPI *pfn_CertCloseStore)(HCERTSTORE, DWORD);

#define RESOLVE(mod, type, var, sym)                                  \
  do {                                                                \
    var = (type)(void *)GetProcAddress((mod), sym);                           \
    if(!var) {                                                        \
      printf("FAIL %s: %s not exported (GetLastError %lu)\n", NAME,   \
             sym, (unsigned long)GetLastError());                     \
      rc = 1;                                                        \
      goto out;                                                       \
    }                                                                 \
  } while(0)

int main(void)
{
  HMODULE hBcrypt = NULL, hCrypt32 = NULL;
  pfn_BCryptGenRandom pGenRandom = NULL;
  pfn_BCryptOpenAlgorithmProvider pOpen = NULL;
  pfn_BCryptCloseAlgorithmProvider pClose = NULL;
  pfn_CertOpenStore pCertOpen = NULL;
  pfn_CertCloseStore pCertClose = NULL;
  BCRYPT_ALG_HANDLE hAlg = NULL;
  unsigned char buf[32], zero[32];
  NTSTATUS st;
  HCERTSTORE mem = NULL;
  int rc = 1;

  memset(zero, 0, sizeof(zero));

  hBcrypt = LoadLibraryW(L"bcrypt.dll");
  if(!hBcrypt) {
    printf("FAIL %s: bcrypt.dll not loadable (GetLastError %lu)\n", NAME,
           (unsigned long)GetLastError());
    return 1;
  }
  hCrypt32 = LoadLibraryW(L"crypt32.dll");
  if(!hCrypt32) {
    printf("FAIL %s: crypt32.dll not loadable (GetLastError %lu)\n", NAME,
           (unsigned long)GetLastError());
    rc = 1;
    goto out;
  }

  RESOLVE(hBcrypt, pfn_BCryptGenRandom, pGenRandom, "BCryptGenRandom");
  RESOLVE(hBcrypt, pfn_BCryptOpenAlgorithmProvider, pOpen,
          "BCryptOpenAlgorithmProvider");
  RESOLVE(hBcrypt, pfn_BCryptCloseAlgorithmProvider, pClose,
          "BCryptCloseAlgorithmProvider");
  RESOLVE(hCrypt32, pfn_CertOpenStore, pCertOpen, "CertOpenStore");
  RESOLVE(hCrypt32, pfn_CertCloseStore, pCertClose, "CertCloseStore");

  /* Random bytes through the resolved system-preferred RNG. */
  memset(buf, 0, sizeof(buf));
  st = pGenRandom(NULL, buf, (ULONG)sizeof(buf),
                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: resolved BCryptGenRandom status 0x%08lx\n", NAME,
           (unsigned long)st);
    goto out;
  }
  if(memcmp(buf, zero, sizeof(buf)) == 0) {
    printf("FAIL %s: resolved BCryptGenRandom produced all-zero output\n",
           NAME);
    goto out;
  }

  /* Provider opened and closed through the resolved pointers. */
  st = pOpen(&hAlg, BCRYPT_RNG_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
  if(st != STATUS_SUCCESS || !hAlg) {
    printf("FAIL %s: resolved BCryptOpenAlgorithmProvider status 0x%08lx\n",
           NAME, (unsigned long)st);
    goto out;
  }
  st = pGenRandom(hAlg, buf, (ULONG)sizeof(buf), 0);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: BCryptGenRandom on provider handle status 0x%08lx\n",
           NAME, (unsigned long)st);
    pClose(hAlg, 0);
    goto out;
  }
  st = pClose(hAlg, 0);
  hAlg = NULL;
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: resolved BCryptCloseAlgorithmProvider status 0x%08lx\n",
           NAME, (unsigned long)st);
    goto out;
  }

  /* In-memory certificate store through the resolved pointers. */
  mem = pCertOpen(CERT_STORE_PROV_MEMORY, 0, (HCRYPTPROV)0,
                  CERT_STORE_CREATE_NEW_FLAG, NULL);
  if(!mem) {
    printf("FAIL %s: resolved CertOpenStore(MEMORY) GetLastError 0x%08lx\n",
           NAME, (unsigned long)GetLastError());
    goto out;
  }
  if(!pCertClose(mem, 0)) {
    printf("FAIL %s: resolved CertCloseStore GetLastError 0x%08lx\n", NAME,
           (unsigned long)GetLastError());
    mem = NULL;
    goto out;
  }
  mem = NULL;

  rc = 0;
  printf("PASS %s\n", NAME);

out:
  if(hAlg)
    pClose(hAlg, 0);
  if(mem && pCertClose)
    pCertClose(mem, 0);
  if(hCrypt32)
    FreeLibrary(hCrypt32);
  if(hBcrypt)
    FreeLibrary(hBcrypt);
  return rc;
}
