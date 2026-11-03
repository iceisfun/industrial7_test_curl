/*
 * Test: cert_root_store_enumerate
 *
 * Purpose: open the current-user ROOT certificate store read-only through the
 *   system store provider and enumerate it, using the same provider and
 *   enumeration calls curl's schannel code uses for a named system store. curl
 *   itself opens its store without CERT_STORE_READONLY_FLAG; this test adds
 *   that flag, together with CERT_STORE_OPEN_EXISTING_FLAG, so it cannot
 *   modify or create the store.
 *
 * APIs: CertOpenStore(CERT_STORE_PROV_SYSTEM_W, ..., L"ROOT"),
 *       CertEnumCertificatesInStore, CertCloseStore
 *
 * Success: CertOpenStore returns a non-NULL handle, at least one certificate
 *   is enumerated, every certificate has X509_ASN_ENCODING, a non-empty DER
 *   encoding that starts with the SEQUENCE tag 0x30, and CertCloseStore
 *   returns TRUE. SKIP when the ROOT store is present but empty, since that
 *   gives no evidence either way.
 *
 * Source: lib/vtls/schannel.c:547-560 (CertOpenStore with
 *   CERT_STORE_PROV_SYSTEM_W for a named store) and lib/vtls/schannel.c:
 *   1510-1513 (CertEnumCertificatesInStore loop).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>

#define NAME "cert_root_store_enumerate"

int main(void)
{
  HCERTSTORE hStore;
  PCCERT_CONTEXT ctx = NULL;
  DWORD count = 0;
  int bad = 0;

  hStore = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM_W, 0, (HCRYPTPROV)0,
                         CERT_SYSTEM_STORE_CURRENT_USER |
                         CERT_STORE_READONLY_FLAG |
                         CERT_STORE_OPEN_EXISTING_FLAG,
                         (const void *)L"ROOT");
  if(!hStore) {
    printf("FAIL %s: CertOpenStore(ROOT) GetLastError 0x%08lx\n", NAME,
           (unsigned long)GetLastError());
    return 1;
  }

  while((ctx = CertEnumCertificatesInStore(hStore, ctx)) != NULL) {
    count++;
    if(ctx->dwCertEncodingType != X509_ASN_ENCODING) {
      bad = 1;
      break;
    }
    if(ctx->cbCertEncoded < 4 || !ctx->pbCertEncoded ||
       ctx->pbCertEncoded[0] != 0x30) {
      bad = 2;
      break;
    }
    if(!ctx->pCertInfo) {
      bad = 3;
      break;
    }
  }
  /* CertEnumCertificatesInStore frees ctx when it returns NULL; on the
     early-exit paths above ctx is still owned by us and must be freed. */
  if(ctx)
    CertFreeCertificateContext(ctx);

  if(bad) {
    printf("FAIL %s: certificate %lu malformed (check %d), GetLastError "
           "0x%08lx\n", NAME, (unsigned long)count, bad,
           (unsigned long)GetLastError());
    CertCloseStore(hStore, 0);
    return 1;
  }

  if(!CertCloseStore(hStore, 0)) {
    printf("FAIL %s: CertCloseStore GetLastError 0x%08lx\n", NAME,
           (unsigned long)GetLastError());
    return 1;
  }

  if(count == 0) {
    printf("SKIP %s: ROOT store is present but enumerates no certificates\n",
           NAME);
    return 77;
  }

  printf("PASS %s\n", NAME);
  return 0;
}
