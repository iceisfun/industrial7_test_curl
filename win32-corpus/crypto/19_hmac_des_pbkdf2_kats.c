/*
 * Test 19_hmac_des_pbkdf2_kats
 *
 * Purpose: the keyed primitives behind curl's authentication code on
 * Windows, against published known answers: HMAC-MD5 (digest/NTLMv2,
 * lib/hmac.c), HMAC-SHA-1/256/512 (AWS SigV4, SCRAM; CNG
 * BCRYPT_ALG_HANDLE_HMAC_FLAG and the CryptoAPI CALG_HMAC + HMAC_INFO path),
 * PBKDF2 (SCRAM) and single-block DES in ECB mode (NTLM response, lib/des.c
 * -> CryptImportKey(PLAINTEXTKEYBLOB, CALG_DES) + CryptEncrypt).
 *
 * APIs: BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE_HMAC_FLAG),
 *       BCryptCreateHash(key), BCryptHashData, BCryptFinishHash,
 *       BCryptDeriveKeyPBKDF2, CryptImportKey, CryptSetKeyParam(KP_MODE),
 *       CryptEncrypt, CryptCreateHash(CALG_HMAC), CryptSetHashParam(HP_HMAC_INFO),
 *       CryptGetHashParam.
 *
 * Success (probed on Windows 10 22H2): HMAC with key "Jefe" and data "what do
 * ya want for nothing?" gives RFC 2202/4231 vectors: MD5 750c783e6ab0b503eaa86e310a5db738,
 * SHA-1 effcdf6ae5eb2fa2d27416d5f184df9c259a7c79, SHA-256
 * 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843, SHA-512
 * 164b7a7b...ce737; the CryptoAPI HMAC-SHA-256 equals the CNG one. PBKDF2-HMAC-
 * SHA1("password", "salt", 1 iteration, 20 bytes) is
 * 0c60c80f961f0e71f3a9b524af6012062fe037a6 (RFC 6070). DES-ECB with key
 * 133457799BBCDFF1 encrypts 0123456789ABCDEF to 85E813540F0AB405 (the classic
 * worked example). A reusable CNG hash (BCRYPT_HASH_REUSABLE_FLAG) produces the
 * same digest on a second round. An HMAC provider handle with no key creates a
 * hash object (STATUS_SUCCESS).
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

#define T "19_hmac_des_pbkdf2_kats"

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

static void hmac(const char *tag, LPCWSTR alg, const char *want)
{
  BCRYPT_ALG_HANDLE a = NULL;
  BCRYPT_HASH_HANDLE h = NULL;
  ULONG objlen = 0, hashlen = 0, r;
  PUCHAR obj;
  unsigned char v[128];
  char hex[300];
  const char *data = "what do ya want for nothing?";

  if(BCryptOpenAlgorithmProvider(&a, alg, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != STATUS_SUCCESS) {
    NOTE_FAIL("%s: open failed", tag);
    return;
  }
  BCryptGetProperty(a, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objlen, 4, &r, 0);
  BCryptGetProperty(a, BCRYPT_HASH_LENGTH, (PUCHAR)&hashlen, 4, &r, 0);
  obj = malloc(objlen);
  if(!obj || BCryptCreateHash(a, &h, obj, objlen, (PUCHAR)"Jefe", 4, 0) != STATUS_SUCCESS ||
     BCryptHashData(h, (PUCHAR)data, 28, 0) != STATUS_SUCCESS ||
     BCryptFinishHash(h, v, hashlen, 0) != STATUS_SUCCESS)
    NOTE_FAIL("%s: HMAC computation failed", tag);
  else {
    tohex(v, hashlen, hex);
    if(strcmp(hex, want) != 0)
      NOTE_FAIL("%s: %s, expected %s", tag, hex, want);
  }
  if(h)
    BCryptDestroyHash(h);
  free(obj);
  BCryptCloseAlgorithmProvider(a, 0);
}

int main(void)
{
  HCRYPTPROV p = 0;
  HCRYPTKEY k = 0;
  HCRYPTHASH h = 0;
  unsigned char out[32];
  char hex[100];
  BCRYPT_ALG_HANDLE a = NULL;
  BCRYPT_HASH_HANDLE bh = NULL;
  UCHAR obj[1024], d1[32], d2[32];
  NTSTATUS s;

  hmac("hmac-md5", BCRYPT_MD5_ALGORITHM, "750c783e6ab0b503eaa86e310a5db738");
  hmac("hmac-sha1", BCRYPT_SHA1_ALGORITHM, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
  hmac("hmac-sha256", BCRYPT_SHA256_ALGORITHM, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  hmac("hmac-sha512", BCRYPT_SHA512_ALGORITHM,
       "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fd"
       "caeab1a34d4a6b4b636e070a38bce737");

  /* no key: still creates a hash object */
  if(BCryptOpenAlgorithmProvider(&a, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) == STATUS_SUCCESS) {
    s = BCryptCreateHash(a, &bh, obj, sizeof(obj), NULL, 0, 0);
    if(s != STATUS_SUCCESS)
      NOTE_FAIL("HMAC hash without a key: status 0x%lx, expected success", (unsigned long)s);
    else
      BCryptDestroyHash(bh);
    BCryptCloseAlgorithmProvider(a, 0);
  }

  /* reusable hash: second round gives the same digest */
  if(BCryptOpenAlgorithmProvider(&a, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_HASH_REUSABLE_FLAG) != STATUS_SUCCESS)
    NOTE_FAIL("reusable provider open failed");
  else {
    bh = NULL;
    s = BCryptCreateHash(a, &bh, obj, sizeof(obj), NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
    if(s != STATUS_SUCCESS)
      NOTE_FAIL("reusable create: 0x%lx", (unsigned long)s);
    else {
      BCryptHashData(bh, (PUCHAR)"abc", 3, 0);
      BCryptFinishHash(bh, d1, 32, 0);
      BCryptHashData(bh, (PUCHAR)"abc", 3, 0);
      s = BCryptFinishHash(bh, d2, 32, 0);
      if(s != STATUS_SUCCESS || memcmp(d1, d2, 32) != 0)
        NOTE_FAIL("reusable hash second round: status 0x%lx or digest differs", (unsigned long)s);
      BCryptDestroyHash(bh);
    }
    BCryptCloseAlgorithmProvider(a, 0);
  }

  /* PBKDF2 */
  if(BCryptOpenAlgorithmProvider(&a, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != STATUS_SUCCESS)
    NOTE_FAIL("PBKDF2 provider open failed");
  else {
    s = BCryptDeriveKeyPBKDF2(a, (PUCHAR)"password", 8, (PUCHAR)"salt", 4, 1, out, 20, 0);
    tohex(out, 20, hex);
    if(s != STATUS_SUCCESS || strcmp(hex, "0c60c80f961f0e71f3a9b524af6012062fe037a6") != 0)
      NOTE_FAIL("PBKDF2: status 0x%lx %s", (unsigned long)s, hex);
    BCryptCloseAlgorithmProvider(a, 0);
  }

  /* CryptoAPI HMAC-SHA-256 */
  if(!CryptAcquireContextW(&p, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    NOTE_FAIL("PROV_RSA_AES acquire failed");
  else {
    struct { BLOBHEADER hd; DWORD len; BYTE key[4]; } kb;
    HMAC_INFO hi;
    DWORD l = 32;
    memset(&kb, 0, sizeof(kb));
    kb.hd.bType = PLAINTEXTKEYBLOB;
    kb.hd.bVersion = CUR_BLOB_VERSION;
    kb.hd.aiKeyAlg = CALG_RC2;
    kb.len = 4;
    memcpy(kb.key, "Jefe", 4);
    memset(&hi, 0, sizeof(hi));
    hi.HashAlgid = CALG_SHA_256;
    if(!CryptImportKey(p, (BYTE *)&kb, sizeof(kb), 0, CRYPT_IPSEC_HMAC_KEY, &k) ||
       !CryptCreateHash(p, CALG_HMAC, k, 0, &h) ||
       !CryptSetHashParam(h, HP_HMAC_INFO, (BYTE *)&hi, 0) ||
       !CryptHashData(h, (const BYTE *)"what do ya want for nothing?", 28, 0) ||
       !CryptGetHashParam(h, HP_HASHVAL, out, &l, 0))
      NOTE_FAIL("CryptoAPI HMAC failed (GLE=0x%lx)", (unsigned long)GetLastError());
    else {
      tohex(out, l, hex);
      if(l != 32 || strcmp(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") != 0)
        NOTE_FAIL("CryptoAPI HMAC-SHA-256 %s", hex);
    }
    if(h)
      CryptDestroyHash(h);
    if(k)
      CryptDestroyKey(k);
    CryptReleaseContext(p, 0);
  }

  /* DES-ECB, as lib/des.c does for the NTLM response */
  p = 0;
  k = 0;
  if(!CryptAcquireContextW(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    NOTE_FAIL("PROV_RSA_FULL acquire failed");
  else {
    struct { BLOBHEADER hd; DWORD len; BYTE key[8]; } kb;
    DWORD mode = CRYPT_MODE_ECB, n = 8;
    BYTE d[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    memset(&kb, 0, sizeof(kb));
    kb.hd.bType = PLAINTEXTKEYBLOB;
    kb.hd.bVersion = CUR_BLOB_VERSION;
    kb.hd.aiKeyAlg = CALG_DES;
    kb.len = 8;
    memcpy(kb.key, "\x13\x34\x57\x79\x9b\xbc\xdf\xf1", 8);
    if(!CryptImportKey(p, (BYTE *)&kb, sizeof(kb), 0, CRYPT_EXPORTABLE, &k) ||
       !CryptSetKeyParam(k, KP_MODE, (BYTE *)&mode, 0) ||
       !CryptEncrypt(k, 0, FALSE, 0, d, &n, 16))
      NOTE_FAIL("DES-ECB failed (GLE=0x%lx)", (unsigned long)GetLastError());
    else {
      tohex(d, n, hex);
      if(n != 8 || strcmp(hex, "85e813540f0ab405") != 0)
        NOTE_FAIL("DES-ECB ciphertext %s (%lu bytes)", hex, (unsigned long)n);
    }
    if(k)
      CryptDestroyKey(k);
    CryptReleaseContext(p, 0);
  }

  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
