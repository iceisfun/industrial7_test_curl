/*
 * Test: bcrypt_genrandom_bulk_entropy
 *
 * Purpose: statistical sanity check of BCryptGenRandom output over a larger
 *   volume and with awkward request sizes (1, 7, 31, 4096 bytes), mirroring
 *   the mix of small and bulk requests that curlx_win32_random serves (its
 *   callers in lib/rand.c). The checks are coarse on
 *   purpose: they catch a stub that returns constant or zero bytes, not a
 *   weak generator.
 *
 * APIs: BCryptGenRandom(NULL, buf, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
 *
 * Success: every call returns STATUS_SUCCESS; across 64 KiB of output at
 *   least 240 of the 256 byte values occur; no 64-byte window is constant;
 *   the 1-byte samples are not all equal.
 *
 * Source: lib/curlx/winapi.c:118-122 (curlx_win32_random is called with
 *   arbitrary lengths).
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
#include <string.h>

#define NAME "bcrypt_genrandom_bulk_entropy"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#define CURL_STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#define CURL_STATUS_NOT_SUPPORTED   ((NTSTATUS)0xC00000BBL)

#define BULK_TOTAL (64 * 1024)

static unsigned char bulk[BULK_TOTAL];

static NTSTATUS gen(unsigned char *p, size_t n)
{
  return BCryptGenRandom(NULL, p, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

int main(void)
{
  static const size_t sizes[] = { 1, 7, 31, 4096 };
  unsigned long seen[256];
  unsigned long distinct = 0;
  unsigned char one[64];
  size_t off = 0, i, k, run;
  NTSTATUS st;

  /* Small requests first: 1-byte samples must not all be equal. */
  for(i = 0; i < sizeof(one); i++) {
    st = gen(&one[i], 1);
    if(st == CURL_STATUS_NOT_IMPLEMENTED || st == CURL_STATUS_NOT_SUPPORTED) {
      printf("SKIP %s: BCryptGenRandom not supported (status 0x%08lx)\n",
             NAME, (unsigned long)st);
      return 77;
    }
    if(st != STATUS_SUCCESS) {
      printf("FAIL %s: 1-byte request %lu status 0x%08lx, GetLastError %lu\n",
             NAME, (unsigned long)i, (unsigned long)st,
             (unsigned long)GetLastError());
      return 1;
    }
  }
  {
    int all_same = 1;
    for(i = 1; i < sizeof(one); i++)
      if(one[i] != one[0])
        all_same = 0;
    if(all_same) {
      printf("FAIL %s: 64 one-byte samples are all 0x%02x\n", NAME, one[0]);
      return 1;
    }
  }

  /* Fill the bulk buffer with a mix of request sizes. */
  while(off < BULK_TOTAL) {
    size_t want = sizes[(off / 7) % (sizeof(sizes) / sizeof(sizes[0]))];
    if(want > BULK_TOTAL - off)
      want = BULK_TOTAL - off;
    st = gen(bulk + off, want);
    if(st != STATUS_SUCCESS) {
      printf("FAIL %s: request of %lu bytes at offset %lu status 0x%08lx, "
             "GetLastError %lu\n", NAME, (unsigned long)want,
             (unsigned long)off, (unsigned long)st,
             (unsigned long)GetLastError());
      return 1;
    }
    off += want;
  }

  memset(seen, 0, sizeof(seen));
  for(i = 0; i < BULK_TOTAL; i++) {
    if(seen[bulk[i]]++ == 0)
      distinct++;
  }
  if(distinct < 240) {
    printf("FAIL %s: only %lu of 256 byte values seen in %d bytes\n",
           NAME, distinct, BULK_TOTAL);
    return 1;
  }

  /* No constant 64-byte window (a stuck or zeroed generator fails here). */
  run = 1;
  for(i = 1; i < BULK_TOTAL; i++) {
    if(bulk[i] == bulk[i - 1]) {
      run++;
      if(run >= 64) {
        printf("FAIL %s: 64 consecutive identical bytes near offset %lu\n",
               NAME, (unsigned long)i);
        return 1;
      }
    }
    else {
      run = 1;
    }
  }

  /* Sanity: the buffer is not a repeat of its first 4 KiB. */
  for(k = 4096; k < BULK_TOTAL; k += 4096) {
    if(memcmp(bulk, bulk + k, 4096) == 0) {
      printf("FAIL %s: 4096-byte block at offset %lu repeats the first block\n",
             NAME, (unsigned long)k);
      return 1;
    }
  }

  printf("PASS %s\n", NAME);
  return 0;
}
