/*
 * Test: random_threads_concurrent
 *
 * Purpose: concurrency of the random sources curl uses. Eight threads each
 *   open their own PROV_RSA_FULL verify-only context and their own use of the
 *   system-preferred CNG RNG, draw many small outputs, and release. Each
 *   thread records its first output; the outputs must all differ, which
 *   shows the generator is not shared-stateful or repeated across threads.
 *   Each thread asks for randomness on its own, as concurrent curl code paths
 *   would.
 *
 * APIs: CryptAcquireContextW, CryptGenRandom, CryptReleaseContext,
 *       BCryptGenRandom(NULL, ..., BCRYPT_USE_SYSTEM_PREFERRED_RNG),
 *       CreateThread, WaitForMultipleObjects, GetExitCodeThread, CloseHandle
 *
 * Success: all threads return success, every thread completes 300 iterations
 *   with no call failing, and the 8 recorded 16-byte first outputs are
 *   pairwise distinct.
 *
 * Source: lib/curlx/winapi.c:118 (curlx_win32_random, called from multiple
 *   threads); lib/md5.c:206 and lib/sha256.c:211 (per-use CryptoAPI contexts).
 *   The thread fan-out itself is the test's own; curl has no such call site.
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
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>

#define NAME "random_threads_concurrent"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#define CURL_STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#define CURL_STATUS_NOT_SUPPORTED   ((NTSTATUS)0xC00000BBL)

#define NTHREADS 8
#define ITERS    300

typedef struct {
  int index;
  int ok;
  DWORD err;
  unsigned char first[16];
} worker_t;

static LONG g_total_draws = 0;

static DWORD WINAPI worker(LPVOID arg)
{
  worker_t *w = (worker_t *)arg;
  HCRYPTPROV hProv = 0;
  unsigned char buf[16];
  int i;

  w->ok = 0;
  w->err = 0;
  memset(w->first, 0, sizeof(w->first));

  if(!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT)) {
    w->err = GetLastError();
    return 1;
  }

  for(i = 0; i < ITERS; i++) {
    NTSTATUS st;

    if(!CryptGenRandom(hProv, sizeof(buf), buf)) {
      w->err = GetLastError();
      CryptReleaseContext(hProv, 0);
      return 1;
    }
    if(i == 0)
      memcpy(w->first, buf, sizeof(w->first));

    st = BCryptGenRandom(NULL, buf, sizeof(buf),
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(st != STATUS_SUCCESS) {
      w->err = (DWORD)st;
      CryptReleaseContext(hProv, 0);
      return 1;
    }
    InterlockedIncrement(&g_total_draws);
  }

  if(!CryptReleaseContext(hProv, 0)) {
    w->err = GetLastError();
    return 1;
  }
  w->ok = 1;
  return 0;
}

int main(void)
{
  HANDLE th[NTHREADS];
  worker_t w[NTHREADS];
  DWORD code;
  int i, j;

  /* Probe the CNG RNG once so a missing feature is a SKIP, not a FAIL. */
  {
    unsigned char probe[1];
    NTSTATUS st = BCryptGenRandom(NULL, probe, 1,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(st == CURL_STATUS_NOT_IMPLEMENTED || st == CURL_STATUS_NOT_SUPPORTED) {
      printf("SKIP %s: BCryptGenRandom not supported (status 0x%08lx)\n",
             NAME, (unsigned long)st);
      return 77;
    }
  }

  for(i = 0; i < NTHREADS; i++) {
    w[i].index = i;
    w[i].ok = 0;
    w[i].err = 0;
    th[i] = CreateThread(NULL, 0, worker, &w[i], 0, NULL);
    if(!th[i]) {
      printf("FAIL %s: CreateThread %d GetLastError %lu\n", NAME, i,
             (unsigned long)GetLastError());
      for(j = 0; j < i; j++)
        WaitForSingleObject(th[j], INFINITE);
      for(j = 0; j < i; j++)
        CloseHandle(th[j]);
      return 1;
    }
  }

  if(WaitForMultipleObjects(NTHREADS, th, TRUE, 50000) != WAIT_OBJECT_0) {
    printf("FAIL %s: worker threads did not all finish within 50 s "
           "(GetLastError %lu)\n", NAME, (unsigned long)GetLastError());
    return 1;
  }

  for(i = 0; i < NTHREADS; i++) {
    code = 0;
    GetExitCodeThread(th[i], &code);
    CloseHandle(th[i]);
    if(!w[i].ok || code != 0) {
      printf("FAIL %s: thread %d failed (err 0x%08lx, exit %lu)\n", NAME, i,
             (unsigned long)w[i].err, (unsigned long)code);
      return 1;
    }
  }

  if(g_total_draws != NTHREADS * ITERS) {
    printf("FAIL %s: completed %ld draws, expected %d\n", NAME,
           (long)g_total_draws, NTHREADS * ITERS);
    return 1;
  }

  for(i = 0; i < NTHREADS; i++) {
    for(j = i + 1; j < NTHREADS; j++) {
      if(memcmp(w[i].first, w[j].first, sizeof(w[i].first)) == 0) {
        printf("FAIL %s: threads %d and %d produced identical first output\n",
               NAME, i, j);
        return 1;
      }
    }
  }

  printf("PASS %s\n", NAME);
  return 0;
}
