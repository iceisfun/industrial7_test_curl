/*
 * Test: cryptcreatehash_sha256_kat
 *
 * Purpose: the CryptoAPI SHA-256 hash path, as curl's sha256 backend uses it:
 *   a verify-only PROV_RSA_AES context, CryptCreateHash(CALG_SHA_256),
 *   CryptHashData, then reading HP_HASHSIZE and HP_HASHVAL. The digest of
 *   "abc" is checked against the FIPS 180-2 known answer.
 *
 * APIs: CryptAcquireContextW(PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT),
 *       CryptCreateHash(CALG_SHA_256), CryptHashData,
 *       CryptGetHashParam(HP_HASHSIZE / HP_HASHVAL), CryptDestroyHash,
 *       CryptReleaseContext
 *
 * Success: HP_HASHSIZE is 32 and the digest equals
 *   ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
 *   SKIP when the AES provider type is not registered (NTE_PROV_TYPE_NOT_DEF
 *   or NTE_BAD_PROV_TYPE).
 *
 * Source: lib/sha256.c:211-215 (my_sha256_init) and the digest read-back in
 *   lib/sha256.c that follows it.
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

#define NAME "cryptcreatehash_sha256_kat"

#define CURL_NTE_BAD_PROV_TYPE     ((DWORD)0x80090014UL)
#define CURL_NTE_PROV_TYPE_NOT_DEF ((DWORD)0x80090017UL)

static const unsigned char expect[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

int main(void)
{
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  DWORD size = 0, len = sizeof(size);
  unsigned char digest[64];
  DWORD dlen = sizeof(digest);
  int rc = 1;

  if(!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES,
                           CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
    DWORD err = GetLastError();
    if(err == CURL_NTE_PROV_TYPE_NOT_DEF || err == CURL_NTE_BAD_PROV_TYPE) {
      printf("SKIP %s: PROV_RSA_AES not registered (0x%08lx)\n",
             NAME, (unsigned long)err);
      return 77;
    }
    printf("FAIL %s: CryptAcquireContextW(PROV_RSA_AES) GetLastError 0x%08lx\n",
           NAME, (unsigned long)err);
    return 1;
  }

  if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
    printf("FAIL %s: CryptCreateHash(CALG_SHA_256) GetLastError 0x%08lx\n",
           NAME, (unsigned long)GetLastError());
    goto out;
  }

  if(!CryptHashData(hHash, (const BYTE *)"abc", 3, 0)) {
    printf("FAIL %s: CryptHashData GetLastError 0x%08lx\n",
           NAME, (unsigned long)GetLastError());
    goto out;
  }

  len = sizeof(size);
  if(!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&size, &len, 0)) {
    printf("FAIL %s: CryptGetHashParam(HP_HASHSIZE) GetLastError 0x%08lx\n",
           NAME, (unsigned long)GetLastError());
    goto out;
  }
  if(size != 32) {
    printf("FAIL %s: HP_HASHSIZE is %lu, expected 32\n", NAME,
           (unsigned long)size);
    goto out;
  }

  if(!CryptGetHashParam(hHash, HP_HASHVAL, digest, &dlen, 0)) {
    printf("FAIL %s: CryptGetHashParam(HP_HASHVAL) GetLastError 0x%08lx\n",
           NAME, (unsigned long)GetLastError());
    goto out;
  }
  if(dlen != 32 || memcmp(digest, expect, 32) != 0) {
    printf("FAIL %s: SHA-256(\"abc\") digest mismatch (len %lu)\n",
           NAME, (unsigned long)dlen);
    goto out;
  }

  rc = 0;
  printf("PASS %s\n", NAME);

out:
  if(hHash)
    CryptDestroyHash(hHash);
  CryptReleaseContext(hProv, 0);
  return rc;
}
