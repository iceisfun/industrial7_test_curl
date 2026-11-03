/*
 * Test: cert_memory_store_copy
 *
 * Purpose: the in-memory certificate store that curl's schannel code builds
 *   for a custom CA bundle. A certificate read from the read-only ROOT store
 *   is copied into a CERT_STORE_PROV_MEMORY store, found again, and the
 *   duplicate-add failure path is checked. Nothing is written to any system
 *   store: the memory store lives only in this process.
 *
 * APIs: CertOpenStore(CERT_STORE_PROV_MEMORY, CERT_STORE_CREATE_NEW_FLAG),
 *       CertOpenStore(CERT_STORE_PROV_SYSTEM_W, L"ROOT", read-only),
 *       CertEnumCertificatesInStore, CertAddCertificateContextToStore
 *       (CERT_STORE_ADD_ALWAYS and CERT_STORE_ADD_NEW),
 *       CertFindCertificateInStore(CERT_FIND_EXISTING),
 *       CertFreeCertificateContext, CertCloseStore
 *
 * Success: the memory store opens; the first ROOT certificate is added with
 *   CERT_STORE_ADD_ALWAYS and is then found with CERT_FIND_EXISTING; a second
 *   add with CERT_STORE_ADD_NEW fails with CRYPT_E_EXISTS (0x80092005); the
 *   memory store enumerates exactly one certificate with identical DER bytes.
 *   SKIP when the ROOT store has no certificates.
 *
 * Source: lib/vtls/schannel_verify.c:680-690 (CertOpenStore with
 *   CERT_STORE_PROV_MEMORY and CERT_STORE_CREATE_NEW_FLAG, the trust store
 *   used for a custom CA file).
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

#define NAME "cert_memory_store_copy"

#define CURL_CRYPT_E_EXISTS ((DWORD)0x80092005L)

int main(void)
{
  HCERTSTORE root = NULL, mem = NULL;
  PCCERT_CONTEXT src = NULL, found = NULL, dup = NULL;
  DWORD n = 0;
  int same = 0;
  int rc = 1;

  root = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM_W, 0, (HCRYPTPROV)0,
                       CERT_SYSTEM_STORE_CURRENT_USER |
                       CERT_STORE_READONLY_FLAG |
                       CERT_STORE_OPEN_EXISTING_FLAG,
                       (const void *)L"ROOT");
  if(!root) {
    printf("FAIL %s: CertOpenStore(ROOT) GetLastError 0x%08lx\n", NAME,
           (unsigned long)GetLastError());
    return 1;
  }

  src = CertEnumCertificatesInStore(root, NULL);
  if(!src) {
    CertCloseStore(root, 0);
    printf("SKIP %s: ROOT store enumerates no certificates\n", NAME);
    return 77;
  }

  mem = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (HCRYPTPROV)0,
                      CERT_STORE_CREATE_NEW_FLAG, NULL);
  if(!mem) {
    printf("FAIL %s: CertOpenStore(MEMORY) GetLastError 0x%08lx\n", NAME,
           (unsigned long)GetLastError());
    goto out;
  }

  if(!CertAddCertificateContextToStore(mem, src, CERT_STORE_ADD_ALWAYS,
                                       NULL)) {
    printf("FAIL %s: add to memory store GetLastError 0x%08lx\n", NAME,
           (unsigned long)GetLastError());
    goto out;
  }

  found = CertFindCertificateInStore(mem, X509_ASN_ENCODING, 0,
                                     CERT_FIND_EXISTING, src, NULL);
  if(!found) {
    printf("FAIL %s: CERT_FIND_EXISTING did not find the added certificate, "
           "GetLastError 0x%08lx\n", NAME, (unsigned long)GetLastError());
    goto out;
  }

  /* Adding the same certificate with ADD_NEW must be refused. */
  if(CertAddCertificateContextToStore(mem, src, CERT_STORE_ADD_NEW, NULL)) {
    printf("FAIL %s: CERT_STORE_ADD_NEW accepted a duplicate certificate\n",
           NAME);
    goto out;
  }
  if(GetLastError() != CURL_CRYPT_E_EXISTS) {
    printf("FAIL %s: duplicate ADD_NEW error 0x%08lx, expected CRYPT_E_EXISTS "
           "(0x80092005)\n", NAME, (unsigned long)GetLastError());
    goto out;
  }

  /* Exactly one certificate, identical bytes to the source. The enumerator
     frees each context it returns, so the bytes are compared inside the loop
     while the context is still valid. */
  while((dup = CertEnumCertificatesInStore(mem, dup)) != NULL) {
    n++;
    if(dup->cbCertEncoded == src->cbCertEncoded &&
       memcmp(dup->pbCertEncoded, src->pbCertEncoded,
              src->cbCertEncoded) == 0)
      same = 1;
  }
  if(n != 1) {
    printf("FAIL %s: memory store holds %lu certificates, expected 1\n", NAME,
           (unsigned long)n);
    goto out;
  }
  if(!same) {
    printf("FAIL %s: memory store certificate DER differs from source\n",
           NAME);
    goto out;
  }

  rc = 0;
  printf("PASS %s\n", NAME);

out:
  if(found)
    CertFreeCertificateContext(found);
  if(src)
    CertFreeCertificateContext(src);
  if(mem)
    CertCloseStore(mem, 0);
  if(root)
    CertCloseStore(root, 0);
  return rc;
}
