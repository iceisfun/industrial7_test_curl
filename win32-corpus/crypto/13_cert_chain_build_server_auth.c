/*
 * Test: cert_chain_build_server_auth
 *
 * Purpose: build a certificate chain with the same CERT_CHAIN_PARA shape curl's
 *   schannel verifier uses: a single server-auth usage OID. Unlike curl, which
 *   passes a custom chain engine and CERT_CHAIN_REVOCATION_CHECK_CHAIN, this
 *   test uses the default (NULL) engine and CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
 *   so no network access is attempted. The leaf is a certificate from the
 *   read-only ROOT
 *   store, so no key or store is created or changed. The result is judged on
 *   the chain structure, not on trust status (a root CA certificate used as a
 *   leaf is not valid for server auth and reports that in TrustStatus, which
 *   is informational here).
 *
 * APIs: CertOpenStore(ROOT, read-only), CertEnumCertificatesInStore,
 *       CertGetCertificateChain, CertFreeCertificateChain,
 *       CertFreeCertificateContext, CertCloseStore
 *
 * Success: CertGetCertificateChain returns TRUE with a non-NULL chain
 *   context, cChain >= 1, the first chain's first element has a non-empty
 *   chain element whose DER bytes are identical to the leaf.
 *   SKIP when the ROOT store has no certificates.
 *
 * Source: lib/vtls/schannel_verify.c:752-768 (CERT_CHAIN_PARA with
 *   RequestedUsage set to szOID_PKIX_KP_SERVER_AUTH, then CertGetCertificateChain
 *   with CERT_CHAIN_REVOCATION_CHECK_CHAIN, or 0 when no_revoke is set).
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

#define NAME "cert_chain_build_server_auth"

static char server_auth_oid[] = "1.3.6.1.5.5.7.3.1";

int main(void)
{
  HCERTSTORE root = NULL;
  PCCERT_CONTEXT leaf = NULL;
  PCCERT_CHAIN_CONTEXT chain = NULL;
  CERT_CHAIN_PARA para;
  char *oid_list[1];
  PCERT_SIMPLE_CHAIN simple;
  PCCERT_CONTEXT first = NULL;
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

  leaf = CertEnumCertificatesInStore(root, NULL);
  if(!leaf) {
    CertCloseStore(root, 0);
    printf("SKIP %s: ROOT store enumerates no certificates\n", NAME);
    return 77;
  }

  memset(&para, 0, sizeof(para));
  para.cbSize = sizeof(para);
  para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
  para.RequestedUsage.Usage.cUsageIdentifier = 1;
  oid_list[0] = server_auth_oid;
  para.RequestedUsage.Usage.rgpszUsageIdentifier = oid_list;

  if(!CertGetCertificateChain(NULL, leaf, NULL, leaf->hCertStore, &para,
                              CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, NULL,
                              &chain)) {
    printf("FAIL %s: CertGetCertificateChain GetLastError 0x%08lx\n", NAME,
           (unsigned long)GetLastError());
    goto out;
  }
  if(!chain) {
    printf("FAIL %s: CertGetCertificateChain returned TRUE with NULL chain\n",
           NAME);
    goto out;
  }
  if(chain->cChain < 1 || !chain->rgpChain || !chain->rgpChain[0]) {
    printf("FAIL %s: chain context has no simple chains (cChain %lu)\n", NAME,
           (unsigned long)chain->cChain);
    goto out;
  }

  simple = chain->rgpChain[0];
  if(simple->cElement < 1 || !simple->rgpElement ||
     !simple->rgpElement[0] || !simple->rgpElement[0]->pCertContext) {
    printf("FAIL %s: first simple chain has no elements (cElement %lu)\n",
           NAME, (unsigned long)simple->cElement);
    goto out;
  }

  first = simple->rgpElement[0]->pCertContext;
  if(first->cbCertEncoded != leaf->cbCertEncoded ||
     memcmp(first->pbCertEncoded, leaf->pbCertEncoded,
            leaf->cbCertEncoded) != 0) {
    printf("FAIL %s: chain element 0 is not the leaf certificate\n", NAME);
    goto out;
  }

  rc = 0;
  printf("PASS %s\n", NAME);

out:
  if(chain)
    CertFreeCertificateChain(chain);
  if(leaf)
    CertFreeCertificateContext(leaf);
  if(root)
    CertCloseStore(root, 0);
  return rc;
}
