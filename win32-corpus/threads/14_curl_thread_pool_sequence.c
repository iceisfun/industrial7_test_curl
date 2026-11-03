/*
 * Test: curl_thread_pool_sequence
 *
 * Purpose: reproduce the exact Windows threading sequence libcurl uses for its
 *   worker threads and condition-variable waits, with the same macros curl
 *   defines in lib/curl_threads.h: a CRITICAL_SECTION mutex initialised with
 *   InitializeCriticalSectionEx(m, 0, 1), a CONDITION_VARIABLE, a worker start
 *   routine created with CreateThread(NULL, 0, func, arg, 0, NULL), a timed
 *   wait mapped to CURLE_OPERATION_TIMEDOUT, and a join that uses
 *   WaitForSingleObjectEx(h, INFINITE, FALSE) followed by CloseHandle.
 *
 * APIs: InitializeCriticalSectionEx, EnterCriticalSection, LeaveCriticalSection,
 *   DeleteCriticalSection, InitializeConditionVariable, WakeConditionVariable,
 *   SleepConditionVariableCS, WaitForSingleObjectEx, CreateThread, CloseHandle,
 *   errno.
 *
 * Success: four pool workers each increment the shared counter under the
 *   mutex, the main thread waits on the condition variable until all four have
 *   checked in, every join returns success, a second destroy on a cleared handle
 *   is a no-op, and a timed wait with no signal returns the timeout code 28
 *   (CURLE_OPERATION_TIMEDOUT) within a bounded time.
 *
 * curl reference: lib/curl_threads.h:33-42 (macro set),
 *   lib/curl_threads.c:34-59 (Curl_thread_create / Curl_thread_destroy /
 *   Curl_thread_join), lib/curl_threads.c:146-158 (Curl_cond_wait and
 *   Curl_cond_timedwait).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>

#define TEST_NAME "curl_thread_pool_sequence"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

/* macro set copied from lib/curl_threads.h for the Windows configuration */
#define CURL_THREAD_RETURN_T   DWORD
#define CURL_STDCALL           WINAPI
#define curl_mutex_t           CRITICAL_SECTION
#define curl_thread_t          HANDLE
#define curl_thread_t_null     (HANDLE)0
#define Curl_mutex_init(m)     InitializeCriticalSectionEx(m, 0, 1)
#define Curl_mutex_acquire(m)  EnterCriticalSection(m)
#define Curl_mutex_release(m)  LeaveCriticalSection(m)
#define Curl_mutex_destroy(m)  DeleteCriticalSection(m)
#define curl_cond_t            CONDITION_VARIABLE
#define Curl_cond_init(c)      InitializeConditionVariable(c)
#define Curl_cond_destroy(c)   (void)(c)

#define CURLE_OK 0
#define CURLE_OPERATION_TIMEDOUT 28
#define CURLE_UNRECOVERABLE_POLL 99

/* mirrors lib/curl_threads.c:34-59 */
static curl_thread_t Curl_thread_create(CURL_THREAD_RETURN_T (CURL_STDCALL *func)(void *), void *arg)
{
  curl_thread_t t = CreateThread(NULL, 0, func, arg, 0, NULL);
  if(!t) {
    DWORD gle = GetLastError();
    errno = (gle == ERROR_ACCESS_DENIED || gle == ERROR_NOT_ENOUGH_MEMORY) ? EACCES : EINVAL;
    return curl_thread_t_null;
  }
  return t;
}

static void Curl_thread_destroy(curl_thread_t *hnd)
{
  if(*hnd != curl_thread_t_null) {
    CloseHandle(*hnd);
    *hnd = curl_thread_t_null;
  }
}

static int Curl_thread_join(curl_thread_t *hnd)
{
  int ret = (WaitForSingleObjectEx(*hnd, INFINITE, FALSE) == WAIT_OBJECT_0);
  Curl_thread_destroy(hnd);
  return ret;
}

/* mirrors lib/curl_threads.c:141-158 */
static void Curl_cond_signal(curl_cond_t *c)
{
  WakeConditionVariable(c);
}

static int Curl_cond_timedwait(curl_cond_t *c, curl_mutex_t *m, uint32_t timeout_ms)
{
  if(!SleepConditionVariableCS(c, m, (DWORD)timeout_ms)) {
    DWORD err = GetLastError();
    return (err == ERROR_TIMEOUT) ? CURLE_OPERATION_TIMEDOUT : CURLE_UNRECOVERABLE_POLL;
  }
  return CURLE_OK;
}

#define POOL 4

static curl_mutex_t mtx;
static curl_cond_t cond;
static int checked_in = 0;

static CURL_THREAD_RETURN_T CURL_STDCALL pool_worker(void *arg)
{
  int *id = (int *)arg;
  (void)id;
  Curl_mutex_acquire(&mtx);
  checked_in++;
  if(checked_in == POOL)
    Curl_cond_signal(&cond);
  Curl_mutex_release(&mtx);
  return 0;
}

int main(void)
{
  curl_thread_t hnd[POOL];
  int ids[POOL];
  int i, rc;
  int joined = 0;

  if(Curl_mutex_init(&mtx) == 0)
    FAILF("InitializeCriticalSectionEx(&mtx, 0, 1) returned FALSE (GLE=%lu)", GetLastError());
  Curl_cond_init(&cond);

  for(i = 0; i < POOL; i++) {
    ids[i] = i;
    hnd[i] = Curl_thread_create(pool_worker, &ids[i]);
    if(hnd[i] == curl_thread_t_null)
      FAILF("Curl_thread_create(%d) failed (errno=%d GLE=%lu)", i, errno, GetLastError());
  }

  /* main waits on the condition variable, as curl's wait loops do */
  Curl_mutex_acquire(&mtx);
  while(checked_in < POOL) {
    rc = Curl_cond_timedwait(&cond, &mtx, 5000);
    if(rc != CURLE_OK) {
      Curl_mutex_release(&mtx);
      FAILF("Curl_cond_timedwait returned %d while waiting for pool (GLE=%lu)", rc, GetLastError());
    }
  }
  if(checked_in != POOL) {
    Curl_mutex_release(&mtx);
    FAILF("checked_in=%d after wait, expected %d", checked_in, POOL);
  }

  /* timed wait with no signal maps to CURLE_OPERATION_TIMEDOUT */
  rc = Curl_cond_timedwait(&cond, &mtx, 10);
  Curl_mutex_release(&mtx);
  if(rc != CURLE_OPERATION_TIMEDOUT)
    FAILF("unsignaled Curl_cond_timedwait returned %d, expected %d", rc, CURLE_OPERATION_TIMEDOUT);

  for(i = 0; i < POOL; i++) {
    if(!Curl_thread_join(&hnd[i]))
      FAILF("Curl_thread_join(%d) failed (GLE=%lu)", i, GetLastError());
    joined++;
    if(hnd[i] != curl_thread_t_null)
      FAILF("Curl_thread_join did not clear handle %d", i);
  }
  if(joined != POOL)
    FAILF("joined %d threads, expected %d", joined, POOL);

  /* destroying an already-cleared handle must be a no-op */
  Curl_thread_destroy(&hnd[0]);

  Curl_cond_destroy(&cond);
  Curl_mutex_destroy(&mtx);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
