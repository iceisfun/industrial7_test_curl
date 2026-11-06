/*
 * Test 17_cert_san_decode_name_string
 *
 * Purpose: reading a server certificate's names the way curl's Schannel
 * backend does when it checks a host itself (schannel_verify.c: locate the
 * subjectAltName extension with CertFindExtension, decode it with
 * CryptDecodeObjectEx(X509_ALTERNATE_NAME), compare dNSName and iPAddress
 * entries, and fall back to the subject CN). Uses test-only EC P-256
 * certificates generated for this corpus: a leaf whose SAN is
 * DNS:leaf.corpus.test, DNS:*.wild.corpus.test, IP:127.0.0.1, IP:::1, and a
 * leaf with no SAN extension and CN=cnonly.corpus.test.
 *
 * APIs: CryptStringToBinaryA, CertCreateCertificateContext, CertFindExtension,
 *       CryptDecodeObjectEx, CertGetNameStringW, CertCompareCertificateName,
 *       CertVerifyTimeValidity, CertVerifySubjectCertificateContext,
 *       CryptVerifyCertificateSignatureEx.
 *
 * Success (probed on Windows 10 22H2): the leaf has an szOID_SUBJECT_ALT_NAME2
 * (2.5.29.17) extension (not critical, 64 bytes) and no extension under the
 * legacy szOID_SUBJECT_ALT_NAME (2.5.29.7); decoding yields 4 entries in
 * order: DNS "leaf.corpus.test", DNS "*.wild.corpus.test", IP of 4 bytes
 * 7f000001, IP of 16 bytes ::1. A truncated extension fails with
 * CRYPT_E_ASN1_EOD (0x80093102); the size query reports 216 bytes. The CN-only
 * certificate has no SAN extension. CertGetNameStringW returns the CN for
 * SIMPLE_DISPLAY, DNS (even without a SAN), RDN, ATTR(CN) and FRIENDLY
 * display, the issuer CN with the issuer flag, and an empty string (length 1)
 * for EMAIL, URL and UPN; a 4-character buffer yields 4 characters including
 * the NUL. The certificate is version 3 (dwVersion 2), signed ecdsa-with-SHA256
 * (1.2.840.10045.4.3.2) with an id-ecPublicKey key (1.2.840.10045.2.1), serial
 * 02. The CA's subject equals its issuer, the leaf's issuer equals the CA's
 * subject, the signature verifies against the CA, and does not verify
 * (CERT_STORE_SIGNATURE_FLAG set, NTE_BAD_SIGNATURE-class 0xC000A000) the
 * other way round. The current time is inside the leaf's validity.
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

#define T "17_cert_san_decode_name_string"

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [GLE=0x%lx]\n", (unsigned long)GetLastError()); \
    return 1; } while(0)

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

static int name_is(PCCERT_CONTEXT c, DWORD type, DWORD flags, void *para,
                   const wchar_t *want, const char *tag)
{
  wchar_t buf[128];
  DWORD n = CertGetNameStringW(c, type, flags, para, buf, 128);
  DWORD wantn = (DWORD)wcslen(want) + 1;
  if(n != wantn || wcscmp(buf, want) != 0) {
    printf("FAIL %s: CertGetNameStringW %s returned %lu [%ls], expected %lu [%ls]\n",
           T, tag, (unsigned long)n, n > 1 ? buf : L"", (unsigned long)wantn, want);
    return 1;
  }
  return 0;
}

int main(void)
{
  PCCERT_CONTEXT ca = load(PEM_CA), leaf = load(PEM_LEAF), cno = load(PEM_CNONLY);
  PCERT_EXTENSION ext;
  PCERT_ALT_NAME_INFO info = NULL;
  DWORD sz = 0, flags;
  wchar_t small[4];
  const CERT_ALT_NAME_ENTRY *en;

  if(!ca || !leaf || !cno)
    FAILF("could not decode the embedded certificates");

  /* extension lookup */
  ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2, leaf->pCertInfo->cExtension, leaf->pCertInfo->rgExtension);
  if(!ext || ext->fCritical || ext->Value.cbData != 64)
    FAILF("leaf SAN2 extension missing, critical, or not 64 bytes");
  if(CertFindExtension(szOID_SUBJECT_ALT_NAME, leaf->pCertInfo->cExtension, leaf->pCertInfo->rgExtension))
    FAILF("leaf unexpectedly has a legacy 2.5.29.7 extension");
  if(CertFindExtension(szOID_SUBJECT_ALT_NAME2, cno->pCertInfo->cExtension, cno->pCertInfo->rgExtension))
    FAILF("CN-only certificate has a SAN extension");
  if(CertFindExtension(szOID_SUBJECT_ALT_NAME2, ca->pCertInfo->cExtension, ca->pCertInfo->rgExtension))
    FAILF("CA certificate has a SAN extension");

  /* decode */
  if(!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, ext->Value.pbData, ext->Value.cbData,
                          CRYPT_DECODE_ALLOC_FLAG, NULL, &info, &sz) || !info)
    FAILF("CryptDecodeObjectEx(X509_ALTERNATE_NAME) failed");
  if(info->cAltEntry != 4)
    FAILF("SAN has %lu entries, expected 4", (unsigned long)info->cAltEntry);
  en = &info->rgAltEntry[0];
  if(en->dwAltNameChoice != CERT_ALT_NAME_DNS_NAME || wcscmp(en->pwszDNSName, L"leaf.corpus.test") != 0)
    FAILF("SAN[0] is not DNS leaf.corpus.test");
  en = &info->rgAltEntry[1];
  if(en->dwAltNameChoice != CERT_ALT_NAME_DNS_NAME || wcscmp(en->pwszDNSName, L"*.wild.corpus.test") != 0)
    FAILF("SAN[1] is not DNS *.wild.corpus.test");
  en = &info->rgAltEntry[2];
  if(en->dwAltNameChoice != CERT_ALT_NAME_IP_ADDRESS || en->IPAddress.cbData != 4 ||
     memcmp(en->IPAddress.pbData, "\x7f\x00\x00\x01", 4) != 0)
    FAILF("SAN[2] is not IP 127.0.0.1 (4 bytes)");
  en = &info->rgAltEntry[3];
  if(en->dwAltNameChoice != CERT_ALT_NAME_IP_ADDRESS || en->IPAddress.cbData != 16 ||
     memcmp(en->IPAddress.pbData, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01", 16) != 0)
    FAILF("SAN[3] is not IP ::1 (16 bytes)");
  LocalFree(info);

  /* truncated and size query */
  sz = 0;
  SetLastError(0);
  if(CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, ext->Value.pbData, ext->Value.cbData - 3,
                         CRYPT_DECODE_ALLOC_FLAG, NULL, &info, &sz) ||
     GetLastError() != (DWORD)0x80093102)
    FAILF("truncated SAN: expected CRYPT_E_ASN1_EOD 0x80093102");
  sz = 0;
  if(!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, ext->Value.pbData, ext->Value.cbData,
                          0, NULL, NULL, &sz) || sz != 216)
    FAILF("SAN size query returned %lu, expected 216", (unsigned long)sz);

  /* names */
  if(name_is(leaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, L"leaf.corpus.test", "simple") ||
     name_is(leaf, CERT_NAME_DNS_TYPE, 0, NULL, L"leaf.corpus.test", "dns") ||
     name_is(leaf, CERT_NAME_DNS_TYPE, CERT_NAME_ISSUER_FLAG, NULL, L"I7 Corpus Test Root CA", "dns issuer") ||
     name_is(leaf, CERT_NAME_RDN_TYPE, 0, NULL, L"leaf.corpus.test", "rdn") ||
     name_is(leaf, CERT_NAME_ATTR_TYPE, 0, (void *)szOID_COMMON_NAME, L"leaf.corpus.test", "attr CN") ||
     name_is(leaf, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, L"leaf.corpus.test", "friendly") ||
     name_is(leaf, CERT_NAME_EMAIL_TYPE, 0, NULL, L"", "email") ||
     name_is(leaf, CERT_NAME_URL_TYPE, 0, NULL, L"", "url") ||
     name_is(leaf, CERT_NAME_UPN_TYPE, 0, NULL, L"", "upn") ||
     name_is(cno, CERT_NAME_DNS_TYPE, 0, NULL, L"cnonly.corpus.test", "dns of CN-only cert") ||
     name_is(ca, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, L"I7 Corpus Test Root CA", "ca issuer"))
    return 1;
  if(CertGetNameStringW(leaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0) != 17)
    FAILF("name size query did not return 17");
  if(CertGetNameStringW(leaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, small, 4) != 4 ||
     wcscmp(small, L"lea") != 0)
    FAILF("4-character buffer did not give 'lea' + NUL");

  /* certificate fields and issuer relationships */
  if(leaf->pCertInfo->dwVersion != 2 || leaf->pCertInfo->SerialNumber.cbData != 1 ||
     leaf->pCertInfo->SerialNumber.pbData[0] != 0x02)
    FAILF("leaf version/serial unexpected");
  if(strcmp(leaf->pCertInfo->SignatureAlgorithm.pszObjId, "1.2.840.10045.4.3.2") != 0 ||
     strcmp(leaf->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, "1.2.840.10045.2.1") != 0)
    FAILF("leaf algorithm OIDs unexpected: %s / %s", leaf->pCertInfo->SignatureAlgorithm.pszObjId,
          leaf->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
  if(!CertCompareCertificateName(X509_ASN_ENCODING, &ca->pCertInfo->Subject, &ca->pCertInfo->Issuer))
    FAILF("CA is not self-issued");
  if(!CertCompareCertificateName(X509_ASN_ENCODING, &leaf->pCertInfo->Issuer, &ca->pCertInfo->Subject))
    FAILF("leaf issuer is not the CA subject");
  if(CertVerifyTimeValidity(NULL, leaf->pCertInfo) != 0)
    FAILF("leaf is not time-valid now");
  flags = CERT_STORE_SIGNATURE_FLAG | CERT_STORE_TIME_VALIDITY_FLAG;
  if(!CertVerifySubjectCertificateContext(leaf, ca, &flags) || flags != 0)
    FAILF("leaf signature/time check against CA: flags 0x%lx", (unsigned long)flags);
  flags = CERT_STORE_SIGNATURE_FLAG;
  if(!CertVerifySubjectCertificateContext(ca, leaf, &flags) || flags != CERT_STORE_SIGNATURE_FLAG)
    FAILF("CA checked against the leaf's key: flags 0x%lx, expected CERT_STORE_SIGNATURE_FLAG", (unsigned long)flags);
  if(!CryptVerifyCertificateSignatureEx(0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void *)leaf,
                                        CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)ca, 0, NULL))
    FAILF("CryptVerifyCertificateSignatureEx(leaf, ca) failed");
  SetLastError(0);
  if(CryptVerifyCertificateSignatureEx(0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void *)ca,
                                       CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)leaf, 0, NULL) ||
     GetLastError() != (DWORD)0xC000A000)
    FAILF("CryptVerifyCertificateSignatureEx(ca, leaf) should fail with 0xC000A000");

  CertFreeCertificateContext(ca);
  CertFreeCertificateContext(leaf);
  CertFreeCertificateContext(cno);
  printf("PASS %s\n", T);
  return 0;
}
