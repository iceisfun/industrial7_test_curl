/*
 * Test 18_digest_kats_capi_cng
 *
 * Purpose: the message digests curl's Windows crypto backends compute, through
 * both Windows APIs, against published known answers: MD5 (lib/md5.c,
 * CryptoAPI PROV_RSA_FULL + CALG_MD5, used by digest auth), SHA-1, SHA-256
 * (lib/sha256.c, PROV_RSA_AES + CALG_SHA_256), SHA-384 and SHA-512, MD4
 * (NTLM, lib/md4.c, CALG_MD4) and MD2 (CALG_MD2). Also pins which provider
 * type supports which algorithm.
 *
 * APIs: CryptAcquireContextW, CryptCreateHash, CryptHashData,
 *       CryptGetHashParam(HP_HASHSIZE / HP_HASHVAL), BCryptOpenAlgorithmProvider,
 *       BCryptGetProperty(OBJECT_LENGTH / HASH_LENGTH), BCryptCreateHash,
 *       BCryptHashData, BCryptFinishHash, BCryptDestroyHash.
 *
 * Success (probed on Windows 10 22H2): for the input "abc" every digest below
 * equals the standard test vector (RFC 1319 MD2, RFC 1320 MD4, RFC 1321 MD5,
 * FIPS 180 SHA-1/2). The CryptoAPI path works for MD5, SHA-1, MD4 and MD2 on
 * PROV_RSA_FULL (type 1) and on PROV_RSA_AES (type 24); SHA-256, SHA-384 and
 * SHA-512 only on PROV_RSA_AES: on PROV_RSA_FULL CryptCreateHash fails with
 * NTE_BAD_ALGID (0x80090008), as does an undefined ALG_ID. SHA-256 of the
 * empty string is e3b0c442... CNG digest sizes: MD5 16, SHA-1 20, SHA-256 32,
 * SHA-384 48, SHA-512 64; MD4 and MD2 are available as "MD4" and "MD2".
 * The PP_NAME of the PROV_RSA_FULL provider is "Microsoft Strong Cryptographic
 * Provider" and its PP_IMPTYPE is CRYPT_IMPL_SOFTWARE (2).
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
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define T "18_digest_kats_capi_cng"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

static int status = 0;
#define NOTE_FAIL(...) do { printf("FAIL %s: ", T); printf(__VA_ARGS__); printf("\n"); status = 1; } while(0)

static void tohex(const unsigned char *b, unsigned n, char *o)
{
  unsigned i;
  for(i = 0; i < n; i++)
    sprintf(o + 2 * i, "%02x", b[i]);
}

/* CryptoAPI digest: want == NULL means CryptCreateHash must fail with want_gle */
static void capi(const char *tag, DWORD prov, ALG_ID alg, const char *data, DWORD len,
                 const char *want, DWORD want_size, DWORD want_gle)
{
  HCRYPTPROV p = 0;
  HCRYPTHASH h = 0;
  unsigned char v[128];
  DWORD l = sizeof(v), sz = 0, sl = sizeof(sz);
  char hex[300];

  if(!CryptAcquireContextW(&p, NULL, NULL, prov, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
    NOTE_FAIL("%s: CryptAcquireContextW(type %lu) failed 0x%lx", tag, (unsigned long)prov,
              (unsigned long)GetLastError());
    return;
  }
  SetLastError(0);
  if(!CryptCreateHash(p, alg, 0, 0, &h)) {
    if(want || GetLastError() != want_gle)
      NOTE_FAIL("%s: CryptCreateHash(0x%x) failed with 0x%lx, expected %s", tag, (unsigned)alg,
                (unsigned long)GetLastError(), want ? "success" : "the documented error");
    CryptReleaseContext(p, 0);
    return;
  }
  if(!want) {
    NOTE_FAIL("%s: CryptCreateHash(0x%x) unexpectedly succeeded", tag, (unsigned)alg);
    CryptDestroyHash(h);
    CryptReleaseContext(p, 0);
    return;
  }
  if(!CryptHashData(h, (const BYTE *)data, len, 0) ||
     !CryptGetHashParam(h, HP_HASHSIZE, (BYTE *)&sz, &sl, 0) ||
     !CryptGetHashParam(h, HP_HASHVAL, v, &l, 0)) {
    NOTE_FAIL("%s: hashing failed 0x%lx", tag, (unsigned long)GetLastError());
  }
  else {
    tohex(v, l, hex);
    if(sz != want_size || l != want_size || strcmp(hex, want) != 0)
      NOTE_FAIL("%s: size %lu digest %s, expected %lu %s", tag, (unsigned long)sz, hex,
                (unsigned long)want_size, want);
  }
  CryptDestroyHash(h);
  CryptReleaseContext(p, 0);
}

static void cng(const char *tag, LPCWSTR alg, const char *data, ULONG len, const char *want, ULONG want_size)
{
  BCRYPT_ALG_HANDLE a = NULL;
  BCRYPT_HASH_HANDLE h = NULL;
  ULONG objlen = 0, hashlen = 0, r;
  PUCHAR obj;
  unsigned char v[128];
  char hex[300];
  NTSTATUS s = BCryptOpenAlgorithmProvider(&a, alg, NULL, 0);
  if(s != STATUS_SUCCESS) {
    NOTE_FAIL("%s: BCryptOpenAlgorithmProvider status 0x%lx", tag, (unsigned long)s);
    return;
  }
  BCryptGetProperty(a, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objlen, 4, &r, 0);
  BCryptGetProperty(a, BCRYPT_HASH_LENGTH, (PUCHAR)&hashlen, 4, &r, 0);
  obj = malloc(objlen);
  if(hashlen != want_size)
    NOTE_FAIL("%s: BCRYPT_HASH_LENGTH %lu, expected %lu", tag, (unsigned long)hashlen, (unsigned long)want_size);
  else if(!obj || BCryptCreateHash(a, &h, obj, objlen, NULL, 0, 0) != STATUS_SUCCESS ||
          BCryptHashData(h, (PUCHAR)data, len, 0) != STATUS_SUCCESS ||
          BCryptFinishHash(h, v, hashlen, 0) != STATUS_SUCCESS)
    NOTE_FAIL("%s: CNG hashing failed", tag);
  else {
    tohex(v, hashlen, hex);
    if(strcmp(hex, want) != 0)
      NOTE_FAIL("%s: digest %s, expected %s", tag, hex, want);
  }
  if(h)
    BCryptDestroyHash(h);
  free(obj);
  BCryptCloseAlgorithmProvider(a, 0);
}

int main(void)
{
  static const char *const MD5 = "900150983cd24fb0d6963f7d28e17f72";
  static const char *const SHA1 = "a9993e364706816aba3e25717850c26c9cd0d89d";
  static const char *const SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  static const char *const SHA384 =
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
  static const char *const SHA512 =
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
    "454d4423643ce80e2a9ac94fa54ca49f";
  static const char *const MD4 = "a448017aaf21d8525fc10ae87aa6729d";
  static const char *const MD2 = "da853b0d3f88d99b30283a69e6ded6bb";
  static const char *const SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const DWORD E_BAD_ALGID = (DWORD)0x80090008;
  HCRYPTPROV p = 0;
  char name[200];
  DWORD nl = sizeof(name), impl = 0, il = sizeof(impl);

  /* CryptoAPI: type 1 (PROV_RSA_FULL) and type 24 (PROV_RSA_AES) */
  capi("md5/full", PROV_RSA_FULL, CALG_MD5, "abc", 3, MD5, 16, 0);
  capi("md5/aes", PROV_RSA_AES, CALG_MD5, "abc", 3, MD5, 16, 0);
  capi("sha1/full", PROV_RSA_FULL, CALG_SHA1, "abc", 3, SHA1, 20, 0);
  capi("sha1/aes", PROV_RSA_AES, CALG_SHA1, "abc", 3, SHA1, 20, 0);
  capi("md4/full", PROV_RSA_FULL, CALG_MD4, "abc", 3, MD4, 16, 0);
  capi("md4/aes", PROV_RSA_AES, CALG_MD4, "abc", 3, MD4, 16, 0);
  capi("md2/full", PROV_RSA_FULL, CALG_MD2, "abc", 3, MD2, 16, 0);
  capi("sha256/aes", PROV_RSA_AES, CALG_SHA_256, "abc", 3, SHA256, 32, 0);
  capi("sha256 empty/aes", PROV_RSA_AES, CALG_SHA_256, "", 0, SHA256_EMPTY, 32, 0);
  capi("sha384/aes", PROV_RSA_AES, CALG_SHA_384, "abc", 3, SHA384, 48, 0);
  capi("sha512/aes", PROV_RSA_AES, CALG_SHA_512, "abc", 3, SHA512, 64, 0);
  capi("sha256/full", PROV_RSA_FULL, CALG_SHA_256, "abc", 3, NULL, 0, E_BAD_ALGID);
  capi("sha512/full", PROV_RSA_FULL, CALG_SHA_512, "abc", 3, NULL, 0, E_BAD_ALGID);
  capi("undefined alg", PROV_RSA_AES, (ALG_ID)0x7777, "abc", 3, NULL, 0, E_BAD_ALGID);

  /* CNG */
  cng("md5", BCRYPT_MD5_ALGORITHM, "abc", 3, MD5, 16);
  cng("sha1", BCRYPT_SHA1_ALGORITHM, "abc", 3, SHA1, 20);
  cng("sha256", BCRYPT_SHA256_ALGORITHM, "abc", 3, SHA256, 32);
  cng("sha384", BCRYPT_SHA384_ALGORITHM, "abc", 3, SHA384, 48);
  cng("sha512", BCRYPT_SHA512_ALGORITHM, "abc", 3, SHA512, 64);
  cng("md4", L"MD4", "abc", 3, MD4, 16);
  cng("md2", BCRYPT_MD2_ALGORITHM, "abc", 3, MD2, 16);

  /* provider properties */
  if(!CryptAcquireContextW(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    NOTE_FAIL("acquire for provider properties failed");
  else {
    if(!CryptGetProvParam(p, PP_NAME, (BYTE *)name, &nl, 0) ||
       strcmp(name, "Microsoft Strong Cryptographic Provider") != 0)
      NOTE_FAIL("PP_NAME is \"%s\"", name);
    if(!CryptGetProvParam(p, PP_IMPTYPE, (BYTE *)&impl, &il, 0) || impl != CRYPT_IMPL_SOFTWARE)
      NOTE_FAIL("PP_IMPTYPE is %lu, expected CRYPT_IMPL_SOFTWARE", (unsigned long)impl);
    CryptReleaseContext(p, 0);
  }

  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
