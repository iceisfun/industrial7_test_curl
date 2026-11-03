/*
 * Test: bcrypt_sha256_hash_object
 *
 * Purpose: the CNG (bcrypt) SHA-256 hash object lifecycle, the way a CNG-based
 *   hash backend drives it: open the SHA256 provider, query
 *   BCRYPT_OBJECT_LENGTH and BCRYPT_HASH_LENGTH, allocate the hash object
 *   memory, then hash in one or several BCryptHashData calls and finish.
 *   Three known-answer vectors are checked:
 *     "" -> e3b0c442...b855
 *     "abc" -> ba7816bf...15ad (single update)
 *     1,000,000 x 'a' -> cdc76e5c...cc112cd0 (fed in 4096-byte chunks)
 *   The "abc" vector is also fed as "a" + "bc" to confirm incremental hashing
 *   matches one-shot hashing.
 *
 * APIs: BCryptOpenAlgorithmProvider(BCRYPT_SHA256_ALGORITHM),
 *       BCryptGetProperty(BCRYPT_OBJECT_LENGTH / BCRYPT_HASH_LENGTH),
 *       BCryptCreateHash, BCryptHashData, BCryptFinishHash,
 *       BCryptDestroyHash, BCryptCloseAlgorithmProvider
 *
 * Success: every digest matches its known answer and all BCrypt calls return
 *   STATUS_SUCCESS.
 *
 * Source: lib/sha256.c is the CryptoAPI counterpart (see test 07). This tree
 *   has no CNG (bcrypt) hashing call site, so this test has no curl line
 *   reference; it checks the CNG hash object API independently of curl.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME "bcrypt_sha256_hash_object"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#define CURL_STATUS_NOT_FOUND       ((NTSTATUS)0xC0000225L)
#define CURL_STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#define CURL_STATUS_NOT_SUPPORTED   ((NTSTATUS)0xC00000BBL)

static const unsigned char kat_empty[32] = {
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
  0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
  0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};
static const unsigned char kat_abc[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};
static const unsigned char kat_million_a[32] = {
  0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
  0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
  0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
  0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0
};

static BCRYPT_ALG_HANDLE g_alg = NULL;
static DWORD g_objlen = 0;
static DWORD g_hashlen = 0;

/* Hash the given pieces (array of {ptr,len}) and compare with expect. */
static int run_hash(const char *what, const void *const *parts,
                    const ULONG *lens, int nparts,
                    const unsigned char *expect)
{
  BCRYPT_HASH_HANDLE h = NULL;
  unsigned char *obj = NULL;
  unsigned char digest[64];
  NTSTATUS st;
  int i, rc = 0;

  obj = (unsigned char *)malloc(g_objlen);
  if(!obj) {
    printf("FAIL %s: malloc(%lu) for hash object failed\n", NAME,
           (unsigned long)g_objlen);
    return 0;
  }
  memset(digest, 0, sizeof(digest));

  st = BCryptCreateHash(g_alg, &h, obj, g_objlen, NULL, 0, 0);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: BCryptCreateHash(%s) status 0x%08lx\n", NAME, what,
           (unsigned long)st);
    goto out;
  }
  for(i = 0; i < nparts; i++) {
    if(lens[i] == 0)
      continue;
    st = BCryptHashData(h, (PUCHAR)parts[i], lens[i], 0);
    if(st != STATUS_SUCCESS) {
      printf("FAIL %s: BCryptHashData(%s, part %d) status 0x%08lx\n", NAME,
             what, i, (unsigned long)st);
      goto out;
    }
  }
  st = BCryptFinishHash(h, digest, g_hashlen, 0);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: BCryptFinishHash(%s) status 0x%08lx\n", NAME, what,
           (unsigned long)st);
    goto out;
  }
  if(memcmp(digest, expect, 32) != 0) {
    printf("FAIL %s: %s digest does not match known answer\n", NAME, what);
    goto out;
  }
  rc = 1;

out:
  if(h)
    BCryptDestroyHash(h);
  free(obj);
  return rc;
}

int main(void)
{
  NTSTATUS st;
  ULONG got = 0;
  static unsigned char chunk[4096];
  const void *parts[4];
  ULONG lens[4];
  size_t fed;
  int rc = 1;
  BCRYPT_HASH_HANDLE h = NULL;
  unsigned char *obj = NULL;
  unsigned char digest[64];

  st = BCryptOpenAlgorithmProvider(&g_alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
  if(st == CURL_STATUS_NOT_FOUND || st == CURL_STATUS_NOT_IMPLEMENTED ||
     st == CURL_STATUS_NOT_SUPPORTED) {
    printf("SKIP %s: SHA256 provider absent (status 0x%08lx)\n", NAME,
           (unsigned long)st);
    return 77;
  }
  if(st != STATUS_SUCCESS || !g_alg) {
    printf("FAIL %s: BCryptOpenAlgorithmProvider(SHA256) status 0x%08lx\n",
           NAME, (unsigned long)st);
    return 1;
  }

  st = BCryptGetProperty(g_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&g_objlen,
                         sizeof(g_objlen), &got, 0);
  if(st != STATUS_SUCCESS || got != sizeof(g_objlen) || g_objlen == 0) {
    printf("FAIL %s: BCRYPT_OBJECT_LENGTH status 0x%08lx, size %lu\n", NAME,
           (unsigned long)st, (unsigned long)got);
    goto out;
  }
  st = BCryptGetProperty(g_alg, BCRYPT_HASH_LENGTH, (PUCHAR)&g_hashlen,
                         sizeof(g_hashlen), &got, 0);
  if(st != STATUS_SUCCESS || g_hashlen != 32) {
    printf("FAIL %s: BCRYPT_HASH_LENGTH is %lu (status 0x%08lx), expected 32\n",
           NAME, (unsigned long)g_hashlen, (unsigned long)st);
    goto out;
  }

  /* Empty input. */
  parts[0] = "";
  lens[0] = 0;
  if(!run_hash("empty", parts, lens, 1, kat_empty))
    goto out;

  /* "abc" in one update. */
  parts[0] = "abc";
  lens[0] = 3;
  if(!run_hash("abc one-shot", parts, lens, 1, kat_abc))
    goto out;

  /* "abc" as "a" + "bc": incremental must equal one-shot. */
  parts[0] = "a";
  lens[0] = 1;
  parts[1] = "bc";
  lens[1] = 2;
  if(!run_hash("abc incremental", parts, lens, 2, kat_abc))
    goto out;

  /* One million 'a' in 4096-byte chunks (244 full chunks plus remainder). */
  memset(chunk, 'a', sizeof(chunk));
  obj = (unsigned char *)malloc(g_objlen);
  if(!obj) {
    printf("FAIL %s: malloc for million-a hash object failed\n", NAME);
    goto out;
  }
  st = BCryptCreateHash(g_alg, &h, obj, g_objlen, NULL, 0, 0);
  if(st != STATUS_SUCCESS) {
    printf("FAIL %s: BCryptCreateHash(million-a) status 0x%08lx\n", NAME,
           (unsigned long)st);
    goto out;
  }
  fed = 0;
  while(fed < 1000000) {
    ULONG n = (ULONG)(1000000 - fed < sizeof(chunk) ? 1000000 - fed
                                                   : sizeof(chunk));
    st = BCryptHashData(h, chunk, n, 0);
    if(st != STATUS_SUCCESS) {
      printf("FAIL %s: BCryptHashData(million-a) at %lu status 0x%08lx\n",
             NAME, (unsigned long)fed, (unsigned long)st);
      goto out;
    }
    fed += n;
  }
  memset(digest, 0, sizeof(digest));
  st = BCryptFinishHash(h, digest, g_hashlen, 0);
  if(st != STATUS_SUCCESS || memcmp(digest, kat_million_a, 32) != 0) {
    printf("FAIL %s: million-a digest mismatch (status 0x%08lx)\n", NAME,
           (unsigned long)st);
    goto out;
  }
  BCryptDestroyHash(h);
  h = NULL;

  rc = 0;
  printf("PASS %s\n", NAME);

out:
  if(h)
    BCryptDestroyHash(h);
  free(obj);
  BCryptCloseAlgorithmProvider(g_alg, 0);
  g_alg = NULL;
  return rc;
}
