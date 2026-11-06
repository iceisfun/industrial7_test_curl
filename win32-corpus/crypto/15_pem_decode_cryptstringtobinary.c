/*
 * Test 15_pem_decode_cryptstringtobinary
 *
 * Purpose: PEM handling of curl's Schannel CA-bundle loader
 * (schannel_verify.c: it locates "-----BEGIN CERTIFICATE-----" and
 * "-----END CERTIFICATE-----" itself, hands the text to
 * CryptStringToBinaryA(CRYPT_STRING_BASE64HEADER), then wraps the DER with
 * CertCreateCertificateContext / CertAddEncodedCertificateToStore). The
 * certificate is a test-only EC P-256 root generated for this corpus (public
 * part only, no secret material).
 *
 * APIs: CryptStringToBinaryA, CertCreateCertificateContext,
 *       CertAddEncodedCertificateToStore, CertOpenStore(MEMORY),
 *       CertEnumCertificatesInStore, CertCloseStore, CertGetNameStringW.
 *
 * Success (values probed on Windows 10 22H2):
 *   CRYPT_STRING_BASE64HEADER / ANY / BASE64_ANY / STRICT decode the PEM to a
 *   377-byte DER starting 30 82 01 75. Plain CRYPT_STRING_BASE64 and HEX fail
 *   with ERROR_INVALID_DATA (13); BINARY "succeeds" and returns the PEM text
 *   itself (566 bytes). Garbage, an empty string and BEGIN without END fail
 *   with 13; an empty BEGIN/END pair succeeds with 0 bytes. Text before the
 *   BEGIN line is skipped (pdwSkip == 15 for two junk lines). A character that
 *   is not base64 ends the data silently (6 bytes, success). A too-small
 *   output buffer fails with ERROR_MORE_DATA (234). Truncated DER fails in
 *   CertCreateCertificateContext with CRYPT_E_ASN1_EOD (0x80093102), garbage
 *   with CRYPT_E_ASN1_BADTAG (0x8009310b), encoding type 0 with
 *   E_INVALIDARG (0x80070057). The memory store takes the DER with ADD_NEW,
 *   rejects a duplicate with CRYPT_E_EXISTS (0x80092005) and a garbage blob
 *   with CRYPT_E_ASN1_BADTAG; CertGetNameStringW returns the subject CN.
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

#define T "15_pem_decode_cryptstringtobinary"

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

static BYTE *decode(const char *pem, DWORD len, DWORD flags, DWORD *outlen,
                    DWORD *skip, DWORD *outflags, DWORD *gle)
{
  DWORD n = 0;
  BYTE *b;
  *skip = 99;
  *outflags = 99;
  SetLastError(0);
  if(!CryptStringToBinaryA(pem, len, flags, NULL, &n, skip, outflags)) {
    *gle = GetLastError();
    *outlen = 0;
    return NULL;
  }
  b = malloc(n ? n : 1);
  if(!b)
    return NULL;
  if(!CryptStringToBinaryA(pem, len, flags, b, &n, skip, outflags)) {
    *gle = GetLastError();
    free(b);
    *outlen = 0;
    return NULL;
  }
  *gle = 0;
  *outlen = n;
  return b;
}

/* expect success with a given length, or failure with a given error */
static int expect(const char *tag, const char *pem, DWORD len, DWORD flags,
                  int ok, DWORD want_len, DWORD want_gle)
{
  DWORD n, skip, fl, gle;
  BYTE *b = decode(pem, len, flags, &n, &skip, &fl, &gle);
  if(ok) {
    if(!b)
      FAILF("%s: decode failed with 0x%lx, expected success", tag, (unsigned long)gle);
    if(n != want_len)
      FAILF("%s: decoded %lu bytes, expected %lu", tag, (unsigned long)n, (unsigned long)want_len);
    free(b);
  }
  else {
    if(b)
      FAILF("%s: decode succeeded (%lu bytes), expected error 0x%lx", tag,
            (unsigned long)n, (unsigned long)want_gle);
    if(gle != want_gle)
      FAILF("%s: error 0x%lx, expected 0x%lx", tag, (unsigned long)gle, (unsigned long)want_gle);
  }
  return 0;
}

int main(void)
{
  DWORD n, skip, fl, gle;
  BYTE *der;
  PCCERT_CONTEXT ctx, ctx2;
  HCERTSTORE store;
  PCCERT_CONTEXT out = NULL, e;
  wchar_t name[64];
  int count = 0;
  const char *bad_b64 =
    "-----BEGIN CERTIFICATE-----\nMIIBdTCC$RugAwIBAgIBATAKBggqhkjOPQQDAjAh\n-----END CERTIFICATE-----\n";
  const char *junk =
    "junk\nmore junk\n-----BEGIN CERTIFICATE-----\nMIIBdTCCARugAwIBAgIBATAKBggqhkjOPQQDAjAh\n-----END CERTIFICATE-----\n";
  const char *crlf =
    "-----BEGIN CERTIFICATE-----\r\nMIIBdTCCARugAwIBAgIBATAKBggqhkjOPQQDAjAh\r\n-----END CERTIFICATE-----\r\n";

  if(expect("BASE64HEADER", PEM_CA, 0, CRYPT_STRING_BASE64HEADER, 1, 377, 0) ||
     expect("ANY", PEM_CA, 0, CRYPT_STRING_ANY, 1, 377, 0) ||
     expect("BASE64_ANY", PEM_CA, 0, CRYPT_STRING_BASE64_ANY, 1, 377, 0) ||
     expect("BASE64HEADER|STRICT", PEM_CA, 0,
            CRYPT_STRING_BASE64HEADER | CRYPT_STRING_STRICT, 1, 377, 0) ||
     expect("BASE64 (headers are not base64)", PEM_CA, 0, CRYPT_STRING_BASE64, 0, 0, ERROR_INVALID_DATA) ||
     expect("HEX", PEM_CA, 0, CRYPT_STRING_HEX, 0, 0, ERROR_INVALID_DATA) ||
     expect("BINARY returns the text", PEM_CA, 0, CRYPT_STRING_BINARY, 1,
            (DWORD)strlen(PEM_CA), 0) ||
     expect("garbage", "this is not a cert", 0, CRYPT_STRING_BASE64HEADER, 0, 0, ERROR_INVALID_DATA) ||
     expect("empty", "", 0, CRYPT_STRING_BASE64HEADER, 0, 0, ERROR_INVALID_DATA) ||
     expect("empty BEGIN/END pair", "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", 0,
            CRYPT_STRING_BASE64HEADER, 1, 0, 0) ||
     expect("BEGIN without END",
            "-----BEGIN CERTIFICATE-----\nMIIBdTCCARugAwIBAgIBATAKBggqhkjOPQQDAjAh\n", 0,
            CRYPT_STRING_BASE64HEADER, 0, 0, ERROR_INVALID_DATA) ||
     expect("CRLF line ends", crlf, 0, CRYPT_STRING_BASE64HEADER, 1, 30, 0) ||
     expect("non-base64 char ends the data", bad_b64, 0, CRYPT_STRING_BASE64HEADER, 1, 6, 0) ||
     expect("junk before BEGIN", junk, 0, CRYPT_STRING_BASE64HEADER, 1, 30, 0))
    return 1;

  /* pdwSkip reports the bytes before the BEGIN line */
  der = decode(junk, 0, CRYPT_STRING_BASE64HEADER, &n, &skip, &fl, &gle);
  if(!der || skip != 15)
    FAILF("junk-before-BEGIN: pdwSkip=%lu, expected 15", (unsigned long)skip);
  free(der);

  /* explicit length, as curl passes (END marker included / cut off) */
  {
    const char *end = strstr(PEM_CA, "-----END CERTIFICATE-----");
    DWORD with_end = (DWORD)(end - PEM_CA) + 25;
    DWORD no_end = (DWORD)(end - PEM_CA);
    if(expect("explicit length incl. END", PEM_CA, with_end, CRYPT_STRING_BASE64HEADER, 1, 377, 0) ||
       expect("explicit length cut before END", PEM_CA, no_end, CRYPT_STRING_BASE64HEADER, 0, 0,
              ERROR_INVALID_DATA))
      return 1;
  }

  /* too-small output buffer */
  {
    BYTE small[4];
    DWORD sl = sizeof(small);
    SetLastError(0);
    if(CryptStringToBinaryA(PEM_CA, 0, CRYPT_STRING_BASE64HEADER, small, &sl, NULL, NULL))
      FAILF("4-byte output buffer unexpectedly succeeded");
    if(GetLastError() != ERROR_MORE_DATA)
      FAILF("4-byte output buffer: error 0x%lx, expected ERROR_MORE_DATA", (unsigned long)GetLastError());
  }

  /* DER -> certificate context */
  der = decode(PEM_CA, 0, CRYPT_STRING_BASE64HEADER, &n, &skip, &fl, &gle);
  if(!der || n != 377 || der[0] != 0x30 || der[1] != 0x82 || der[2] != 0x01 || der[3] != 0x75)
    FAILF("DER header is not 30 82 01 75");
  SetLastError(0);
  if(CertCreateCertificateContext(X509_ASN_ENCODING, der, n - 5) || GetLastError() != (DWORD)0x80093102)
    FAILF("truncated DER: expected CRYPT_E_ASN1_EOD 0x80093102");
  SetLastError(0);
  if(CertCreateCertificateContext(X509_ASN_ENCODING, (const BYTE *)"hello", 5) ||
     GetLastError() != (DWORD)0x8009310b)
    FAILF("garbage DER: expected CRYPT_E_ASN1_BADTAG 0x8009310b");
  SetLastError(0);
  if(CertCreateCertificateContext(0, der, n) || GetLastError() != (DWORD)0x80070057)
    FAILF("encoding type 0: expected E_INVALIDARG 0x80070057");
  ctx = CertCreateCertificateContext(X509_ASN_ENCODING, der, n);
  if(!ctx)
    FAILF("CertCreateCertificateContext failed");
  if(CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, 64) != 23 ||
     wcscmp(name, L"I7 Corpus Test Root CA") != 0)
    FAILF("subject name is not 'I7 Corpus Test Root CA'");
  if(CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0) != 23)
    FAILF("CertGetNameStringW size query did not return 23");

  /* memory store: add, duplicate, garbage */
  store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
  if(!store)
    FAILF("CertOpenStore(MEMORY) failed");
  if(!CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, der, n, CERT_STORE_ADD_NEW, &out) || !out)
    FAILF("CertAddEncodedCertificateToStore(ADD_NEW) failed");
  CertFreeCertificateContext(out);
  SetLastError(0);
  if(CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, der, n, CERT_STORE_ADD_NEW, NULL) ||
     GetLastError() != (DWORD)0x80092005)
    FAILF("duplicate ADD_NEW: expected CRYPT_E_EXISTS 0x80092005");
  if(!CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, der, n, CERT_STORE_ADD_USE_EXISTING, NULL))
    FAILF("ADD_USE_EXISTING on a duplicate failed");
  if(!CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, der, n, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
    FAILF("ADD_REPLACE_EXISTING on a duplicate failed");
  SetLastError(0);
  if(CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, (const BYTE *)"hello", 5,
                                      CERT_STORE_ADD_NEW, NULL) || GetLastError() != (DWORD)0x8009310b)
    FAILF("garbage blob: expected CRYPT_E_ASN1_BADTAG 0x8009310b");
  e = NULL;
  while((e = CertEnumCertificatesInStore(store, e)) != NULL)
    count++;
  if(count != 1)
    FAILF("store holds %d certificates, expected 1", count);
  ctx2 = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_W,
                                    L"I7 Corpus Test Root CA", NULL);
  if(!ctx2)
    FAILF("CertFindCertificateInStore by subject string failed");
  CertFreeCertificateContext(ctx2);
  if(CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_W, L"nonexistent", NULL))
    FAILF("found a certificate that is not in the store");
  if(GetLastError() != (DWORD)0x80092004)
    FAILF("not-found error 0x%lx, expected CRYPT_E_NOT_FOUND 0x80092004", (unsigned long)GetLastError());

  CertCloseStore(store, 0);
  CertFreeCertificateContext(ctx);
  free(der);
  printf("PASS %s\n", T);
  return 0;
}
