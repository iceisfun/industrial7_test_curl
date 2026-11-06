/*
 * Test 16_chain_engine_ssl_policy
 *
 * Purpose: the certificate verification sequence of curl's Schannel backend
 * for a user-supplied CA bundle (schannel_verify.c): put the CA into a memory
 * store, create a chain engine with that store as hExclusiveRoot, build the
 * chain for the server certificate with CertGetCertificateChain (server-auth
 * usage, no network retrieval), then judge it with
 * CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL) using
 * SSL_EXTRA_CERT_CHAIN_POLICY_PARA (AUTHTYPE_SERVER, pwszServerName,
 * fdwChecks). The certificates are test-only EC P-256 certificates generated
 * for this corpus (a root CA, a leaf with DNS and IP subjectAltNames and a
 * wildcard, an expired leaf, a clientAuth-only leaf, and a CN-only leaf);
 * all valid 2000-01-01 .. 2099-12-31 except the expired one.
 *
 * APIs: CertCreateCertificateChainEngine, CertGetCertificateChain,
 *       CertVerifyCertificateChainPolicy, CertFreeCertificateChain,
 *       CertFreeCertificateChainEngine, CertAddEncodedCertificateToStore.
 *
 * Success (policy dwError probed on Windows 10 22H2):
 *   leaf.corpus.test (any case), foo.wild.corpus.test, the IP literals
 *   127.0.0.1, ::1 and [::1] (matched against iPAddress entries), the literal
 *   "*.wild.corpus.test" and a NULL server name -> 0.
 *   a.b.wild.corpus.test, wild.corpus.test, other.test, 127.0.0.2, a trailing
 *   dot ("leaf.corpus.test.") and an empty name -> CERT_E_CN_NOT_MATCHED
 *   (0x800B010F). SECURITY_FLAG_IGNORE_CERT_CN_INVALID turns that into 0.
 *   An engine whose exclusive root store is empty -> CERT_E_UNTRUSTEDROOT
 *   (0x800B0109) with CERT_TRUST_IS_PARTIAL_CHAIN (0x10000) on the chain, and
 *   SECURITY_FLAG_IGNORE_UNKNOWN_CA turns the policy result into 0. The expired
 *   leaf -> CERT_E_EXPIRED (0x800B0101), chain status NOT_TIME_VALID, 0 with
 *   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID. The clientAuth-only leaf with a
 *   server-auth usage request -> CERT_E_WRONG_USAGE (0x800B0110), chain status
 *   NOT_VALID_FOR_USAGE (0x10), 0 with SECURITY_FLAG_IGNORE_WRONG_USAGE and 0
 *   when no usage is requested. A leaf without a SAN extension matches its
 *   subject CN. CERT_CHAIN_REVOCATION_CHECK_CHAIN on a chain without CRL
 *   distribution points builds the chain with
 *   CERT_TRUST_REVOCATION_STATUS_UNKNOWN (0x40) and the SSL policy then
 *   reports CRYPT_E_NO_REVOCATION_CHECK (0x80092012); this is why curl has
 *   CURLSSLOPT_NO_REVOKE / CURLSSLOPT_REVOKE_BEST_EFFORT. A root used as the leaf yields a one-element chain. The chain for
 *   a good leaf has 2 elements and trust info 0x2100.
 *
 * Source: lib/vtls/schannel_verify.c (verify_certificate path).
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
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define T "16_chain_engine_ssl_policy"

#ifndef SECURITY_FLAG_IGNORE_UNKNOWN_CA
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA 0x00000100
#endif
#ifndef SECURITY_FLAG_IGNORE_WRONG_USAGE
#define SECURITY_FLAG_IGNORE_WRONG_USAGE 0x00000200
#endif
#ifndef SECURITY_FLAG_IGNORE_CERT_CN_INVALID
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID 0x00001000
#endif
#ifndef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#endif

#define E_CN_NOT_MATCHED 0x800B010FUL
#define E_UNTRUSTEDROOT 0x800B0109UL
#define E_EXPIRED 0x800B0101UL
#define E_WRONG_USAGE 0x800B0110UL

static int status = 0;
#define NOTE_FAIL(...) do { printf("FAIL %s: ", T); printf(__VA_ARGS__); printf("\n"); status = 1; } while(0)

static const char PEM_CA[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBdTCCARugAwIBAgIBATAKBggqhkjOPQQDAjAhMR8wHQYDVQQDDBZJNyBDb3Jw\n"
  "dXMgVGVzdCBSb290IENBMCAXDTAwMDEwMTAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5\n"
  "WjAhMR8wHQYDVQQDDBZJNyBDb3JwdXMgVGVzdCBSb290IENBMFkwEwYHKoZIzj0C\n"
  "AQYIKoZIzj0DAQcDQgAEH2J2WhflL1CsN0MddOJGEN/szQ/LgNW7J6BqQy1LFK9I\n"
  "BqcZnRF5XAUsGdg356IHXfV+9foMVqDP9RJRKphN+6NCMEAwDwYDVR0TAQH/BAUw\n"
  "AwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFCXxLS3zPTWKThfiwvIEecLl\n"
  "5eNRMAoGCCqGSM49BAMCA0gAMEUCIHRstcj96SNrFmRC5jNEc+m5xUaO/89F/TUJ\n"
  "/zKs961zAiEArUr9pOQHd1HRt5TCpy9TyOnwEmK0AaZWblKiqLxXdtM=\n"
  "-----END CERTIFICATE-----\n";

static const char PEM_LEAF[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIB5jCCAY2gAwIBAgIBAjAKBggqhkjOPQQDAjAhMR8wHQYDVQQDDBZJNyBDb3Jw\n"
  "dXMgVGVzdCBSb290IENBMCAXDTAwMDEwMTAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5\n"
  "WjAbMRkwFwYDVQQDDBBsZWFmLmNvcnB1cy50ZXN0MFkwEwYHKoZIzj0CAQYIKoZI\n"
  "zj0DAQcDQgAE1xMbFYGhI/6LB8wEcHPoPGIkexC0Ft1q7G0AfLL0HQjZ+dfwoPiV\n"
  "YRT5qc8Dmwrti2xolTFeGZ++4HUaYLkAC6OBuTCBtjAJBgNVHRMEAjAAMAsGA1Ud\n"
  "DwQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATBHBgNVHREEQDA+ghBsZWFmLmNv\n"
  "cnB1cy50ZXN0ghIqLndpbGQuY29ycHVzLnRlc3SHBH8AAAGHEAAAAAAAAAAAAAAA\n"
  "AAAAAAEwHQYDVR0OBBYEFPw4Pff2fmrpbOpDd8jF94khP1hlMB8GA1UdIwQYMBaA\n"
  "FCXxLS3zPTWKThfiwvIEecLl5eNRMAoGCCqGSM49BAMCA0cAMEQCICKWxVN/Tlx6\n"
  "n+uqVE8XdVGVJ4GoI11L2GgQvFcwn4q1AiARKc1IHgwsjrE0kQqLfhchINhKWYQL\n"
  "0wO0qRqgaufGpQ==\n"
  "-----END CERTIFICATE-----\n";

static const char PEM_EXPIRED[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBsjCCAVigAwIBAgIBAzAKBggqhkjOPQQDAjAhMR8wHQYDVQQDDBZJNyBDb3Jw\n"
  "dXMgVGVzdCBSb290IENBMB4XDTAwMDEwMTAwMDAwMFoXDTAxMDEwMTAwMDAwMFow\n"
  "HjEcMBoGA1UEAwwTZXhwaXJlZC5jb3JwdXMudGVzdDBZMBMGByqGSM49AgEGCCqG\n"
  "SM49AwEHA0IABDUcmqKX+vYLhW4f4J+zOZMDKwxavZDqjW7uS2FX+l5RXb+Dc0/f\n"
  "GtXyehodf0d8U3T5d2GiQldZvTUkM4CKt5yjgYMwgYAwCQYDVR0TBAIwADATBgNV\n"
  "HSUEDDAKBggrBgEFBQcDATAeBgNVHREEFzAVghNleHBpcmVkLmNvcnB1cy50ZXN0\n"
  "MB0GA1UdDgQWBBSKAjLIAPAbPsxYfy6gGypAm7sRozAfBgNVHSMEGDAWgBQl8S0t\n"
  "8z01ik4X4sLyBHnC5eXjUTAKBggqhkjOPQQDAgNIADBFAiEAwTokMOEImBaUz9IO\n"
  "PTjg/YAwnbutI50Otpt0gOIxZwACIGlSAiRVaTMUdy2NmzgXkK5Nbczmcemr4i+y\n"
  "1Wc0/k9L\n"
  "-----END CERTIFICATE-----\n";

static const char PEM_CLIENT[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBsTCCAVegAwIBAgIBBDAKBggqhkjOPQQDAjAhMR8wHQYDVQQDDBZJNyBDb3Jw\n"
  "dXMgVGVzdCBSb290IENBMCAXDTAwMDEwMTAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5\n"
  "WjAdMRswGQYDVQQDDBJjbGllbnQuY29ycHVzLnRlc3QwWTATBgcqhkjOPQIBBggq\n"
  "hkjOPQMBBwNCAARFXxEk3D8+++xfQN5vhv0RP8iF7w0TA7a4MUTjM5PQqsDvktcI\n"
  "6rcmIbpNWzXvEWmQQLWO8fLt0Lfb9lNGuKm/o4GBMH8wCQYDVR0TBAIwADATBgNV\n"
  "HSUEDDAKBggrBgEFBQcDAjAdBgNVHREEFjAUghJjbGllbnQuY29ycHVzLnRlc3Qw\n"
  "HQYDVR0OBBYEFBnFLSiyQhL235XPK70K69oI23sCMB8GA1UdIwQYMBaAFCXxLS3z\n"
  "PTWKThfiwvIEecLl5eNRMAoGCCqGSM49BAMCA0gAMEUCID3PCJP4SfkijU5l4KiW\n"
  "dPnvfue0hSZOtjxVyK5cj54mAiEApyXmrXL4FJSdI6HzmJ7jJwBvImlYudaNn5cK\n"
  "tucWrSY=\n"
  "-----END CERTIFICATE-----\n";

static const char PEM_CNONLY[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBkDCCATegAwIBAgIBBTAKBggqhkjOPQQDAjAhMR8wHQYDVQQDDBZJNyBDb3Jw\n"
  "dXMgVGVzdCBSb290IENBMCAXDTAwMDEwMTAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5\n"
  "WjAdMRswGQYDVQQDDBJjbm9ubHkuY29ycHVzLnRlc3QwWTATBgcqhkjOPQIBBggq\n"
  "hkjOPQMBBwNCAAQhtTxp4iPkPVqzfOXjFx7QfBIJUMxKX3kbAZFVuJq2nMqd3kUj\n"
  "lnInJb+m4vXLy42LL3JVNKErNoB2T+QSfR2ho2IwYDAJBgNVHRMEAjAAMBMGA1Ud\n"
  "JQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBSQc738lI4tuuDddv9dh5wAr4v6cDAf\n"
  "BgNVHSMEGDAWgBQl8S0t8z01ik4X4sLyBHnC5eXjUTAKBggqhkjOPQQDAgNHADBE\n"
  "AiBhV/H+GLB8aeMlMSji620CG4BQ1Ma7sIPk0mxw2RpbyQIgOOFIhIepj0FJ/tC4\n"
  "a1eESpoIwz4cLI/hpXEGxzu0J5g=\n"
  "-----END CERTIFICATE-----\n";

static PCCERT_CONTEXT load(const char *pem)
{
  DWORD n = 0;
  BYTE *b;
  PCCERT_CONTEXT c;
  if(!CryptStringToBinaryA(pem, 0, CRYPT_STRING_BASE64HEADER, NULL, &n, NULL, NULL))
    return NULL;
  b = malloc(n);
  if(!b || !CryptStringToBinaryA(pem, 0, CRYPT_STRING_BASE64HEADER, b, &n, NULL, NULL))
    return NULL;
  c = CertCreateCertificateContext(X509_ASN_ENCODING, b, n);
  free(b);
  return c;
}

/* returns 1 on success and fills the outputs */
static int verify(HCERTSTORE root, PCCERT_CONTEXT leaf, const wchar_t *host,
                  DWORD checks, int want_usage, DWORD extra_chain_flags,
                  DWORD *policy_err, DWORD *trust_err, DWORD *trust_info,
                  DWORD *elements)
{
  CERT_CHAIN_ENGINE_CONFIG cfg;
  HCERTCHAINENGINE eng = NULL;
  LPSTR usage[1];
  CERT_CHAIN_PARA cp;
  PCCERT_CHAIN_CONTEXT chain = NULL;
  SSL_EXTRA_CERT_CHAIN_POLICY_PARA ex;
  CERT_CHAIN_POLICY_PARA pp;
  CERT_CHAIN_POLICY_STATUS ps;
  int ok;

  memset(&cfg, 0, sizeof(cfg));
  cfg.cbSize = sizeof(cfg);
  cfg.hExclusiveRoot = root;
  if(!CertCreateCertificateChainEngine(&cfg, &eng))
    return 0;
  usage[0] = (LPSTR)szOID_PKIX_KP_SERVER_AUTH;
  memset(&cp, 0, sizeof(cp));
  cp.cbSize = sizeof(cp);
  if(want_usage) {
    cp.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    cp.RequestedUsage.Usage.cUsageIdentifier = 1;
    cp.RequestedUsage.Usage.rgpszUsageIdentifier = usage;
  }
  if(!CertGetCertificateChain(eng, leaf, NULL, NULL, &cp,
                              CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | extra_chain_flags,
                              NULL, &chain)) {
    CertFreeCertificateChainEngine(eng);
    return 0;
  }
  memset(&ex, 0, sizeof(ex));
  ex.cbSize = sizeof(ex);
  ex.dwAuthType = AUTHTYPE_SERVER;
  ex.fdwChecks = checks;
  ex.pwszServerName = (LPWSTR)host;
  memset(&pp, 0, sizeof(pp));
  pp.cbSize = sizeof(pp);
  pp.pvExtraPolicyPara = &ex;
  memset(&ps, 0, sizeof(ps));
  ps.cbSize = sizeof(ps);
  ok = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &pp, &ps) ? 1 : 0;
  *policy_err = ps.dwError;
  *trust_err = chain->TrustStatus.dwErrorStatus;
  *trust_info = chain->TrustStatus.dwInfoStatus;
  *elements = chain->cChain ? chain->rgpChain[0]->cElement : 0;
  CertFreeCertificateChain(chain);
  CertFreeCertificateChainEngine(eng);
  return ok;
}

static void check(const char *tag, HCERTSTORE root, PCCERT_CONTEXT leaf, const wchar_t *host,
                  DWORD checks, int want_usage, DWORD want_policy, DWORD want_trust_err,
                  DWORD want_elements)
{
  DWORD pe = 0xDEAD, te = 0xDEAD, ti = 0, el = 0;
  if(!verify(root, leaf, host, checks, want_usage, 0, &pe, &te, &ti, &el)) {
    NOTE_FAIL("%s: chain building / policy call failed (GLE=0x%lx)", tag, (unsigned long)GetLastError());
    return;
  }
  if(pe != want_policy)
    NOTE_FAIL("%s: policy error 0x%lx, expected 0x%lx", tag, (unsigned long)pe, (unsigned long)want_policy);
  if(te != want_trust_err)
    NOTE_FAIL("%s: chain trust error 0x%lx, expected 0x%lx", tag, (unsigned long)te, (unsigned long)want_trust_err);
  if(el != want_elements)
    NOTE_FAIL("%s: %lu chain elements, expected %lu", tag, (unsigned long)el, (unsigned long)want_elements);
}

int main(void)
{
  PCCERT_CONTEXT ca = load(PEM_CA), leaf = load(PEM_LEAF), expired = load(PEM_EXPIRED);
  PCCERT_CONTEXT client = load(PEM_CLIENT), cnonly = load(PEM_CNONLY);
  HCERTSTORE root, empty;
  DWORD pe, te, ti, el;
  static const wchar_t *good[] = { L"leaf.corpus.test", L"LEAF.Corpus.TEST", L"foo.wild.corpus.test",
                                   L"127.0.0.1", L"::1", L"[::1]", L"*.wild.corpus.test", NULL };
  static const wchar_t *bad[] = { L"a.b.wild.corpus.test", L"wild.corpus.test", L"other.test",
                                  L"127.0.0.2", L"leaf.corpus.test.", L"", NULL };
  int i;

  if(!ca || !leaf || !expired || !client || !cnonly) {
    printf("FAIL %s: could not decode the embedded certificates (GLE=0x%lx)\n", T, (unsigned long)GetLastError());
    return 1;
  }
  root = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
  empty = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
  if(!root || !empty ||
     !CertAddCertificateContextToStore(root, ca, CERT_STORE_ADD_NEW, NULL)) {
    printf("FAIL %s: memory store setup failed (GLE=0x%lx)\n", T, (unsigned long)GetLastError());
    return 1;
  }

  for(i = 0; good[i]; i++)
    check("good name", root, leaf, good[i], 0, 1, 0, 0, 2);
  for(i = 0; bad[i]; i++)
    check("bad name", root, leaf, bad[i], 0, 1, E_CN_NOT_MATCHED, 0, 2);
  check("NULL server name", root, leaf, NULL, 0, 1, 0, 0, 2);
  check("good leaf without usage request", root, leaf, L"leaf.corpus.test", 0, 0, 0, 0, 2);
  check("ignore CN mismatch", root, leaf, L"other.test", SECURITY_FLAG_IGNORE_CERT_CN_INVALID, 1, 0, 0, 2);
  check("empty exclusive root", empty, leaf, L"leaf.corpus.test", 0, 1, E_UNTRUSTEDROOT, 0x10000, 1);
  check("empty root + IGNORE_UNKNOWN_CA", empty, leaf, L"leaf.corpus.test",
        SECURITY_FLAG_IGNORE_UNKNOWN_CA, 1, 0, 0x10000, 1);
  check("expired leaf", root, expired, L"expired.corpus.test", 0, 1, E_EXPIRED, 0x1, 2);
  check("expired + IGNORE_CERT_DATE_INVALID", root, expired, L"expired.corpus.test",
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID, 1, 0, 0x1, 2);
  check("clientAuth-only leaf", root, client, L"client.corpus.test", 0, 1, E_WRONG_USAGE, 0x10, 2);
  check("clientAuth-only + IGNORE_WRONG_USAGE", root, client, L"client.corpus.test",
        SECURITY_FLAG_IGNORE_WRONG_USAGE, 1, 0, 0x10, 2);
  check("clientAuth-only, no usage requested", root, client, L"client.corpus.test", 0, 0, 0, 0, 2);
  check("CN-only leaf, matching CN", root, cnonly, L"cnonly.corpus.test", 0, 1, 0, 0, 2);
  check("CN-only leaf, other name", root, cnonly, L"x.test", 0, 1, E_CN_NOT_MATCHED, 0, 2);
  check("root as leaf", root, ca, L"I7 Corpus Test Root CA", 0, 1, 0, 0, 1);

  /* trust info of a good chain and the revocation-unknown status */
  if(!verify(root, leaf, L"leaf.corpus.test", 0, 1, 0, &pe, &te, &ti, &el))
    NOTE_FAIL("good chain failed");
  else if(ti != 0x2100)
    NOTE_FAIL("good chain trust info 0x%lx, expected 0x2100", (unsigned long)ti);
  if(!verify(root, leaf, L"leaf.corpus.test", 0, 1, CERT_CHAIN_REVOCATION_CHECK_CHAIN, &pe, &te, &ti, &el))
    NOTE_FAIL("revocation-check chain failed");
  else if(pe != 0x80092012UL || te != 0x40)
    NOTE_FAIL("revocation check without CDP: policy 0x%lx trust 0x%lx, expected 0x80092012 / 0x40",
              (unsigned long)pe, (unsigned long)te);

  /* engine creation with a bad cbSize */
  {
    CERT_CHAIN_ENGINE_CONFIG cfg;
    HCERTCHAINENGINE eng = NULL;
    memset(&cfg, 0, sizeof(cfg));
    cfg.cbSize = 1;
    SetLastError(0);
    if(CertCreateCertificateChainEngine(&cfg, &eng))
      NOTE_FAIL("engine with cbSize=1 was created");
  }

  CertCloseStore(root, 0);
  CertCloseStore(empty, 0);
  CertFreeCertificateContext(ca);
  CertFreeCertificateContext(leaf);
  CertFreeCertificateContext(expired);
  CertFreeCertificateContext(client);
  CertFreeCertificateContext(cnonly);
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
