/*
 * Test: init_once_execute
 *
 * Purpose: one-time initialisation with INIT_ONCE. Eight threads race on
 *   InitOnceExecuteOnce; the callback must run exactly once, every caller must
 *   get TRUE and the context value the callback stored. A failing callback
 *   leaves the once-object uninitialised so the next caller retries. Manual
 *   InitOnceBeginInitialize / InitOnceComplete also round-trips.
 *
 * APIs: INIT_ONCE_STATIC_INIT, InitOnceExecuteOnce, InitOnceBeginInitialize,
 *   InitOnceComplete, CreateThread, WaitForMultipleObjects, GetExitCodeThread,
 *   InterlockedIncrement, Sleep.
 *
 * Success: the success callback runs once with 8 racing threads, all report
 *   TRUE and context 0xBEE8; the failing callback is invoked on the first
 *   attempt (InitOnceExecuteOnce returns FALSE) and then the next attempt
 *   succeeds and the initial state persists; manual Begin/Complete reports
 *   fPending TRUE then FALSE with the stored context.
 *
 * Context values: InitOnceExecuteOnce / InitOnceComplete require the low two
 *   bits of the context pointer to be zero (INIT_ONCE_CTX_RESERVED_BITS);
 *   Windows 10 22H2: InitOnceComplete with such a context returns FALSE with
 *   ERROR_INVALID_PARAMETER (87), and InitOnceExecuteOnce whose callback stores
 *   one raises STATUS_INVALID_PARAMETER_3 (0xC00000F1). Step 5 checks both
 *   (the exception on a scratch thread); values 0x4, 0x7c, 0x78 and 0xBEE8 are
 *   accepted. (Earlier revisions stored 0xBEEF
 *   and 0x77, which Windows rejects; wine tolerates both.)
 *
 * curl reference: curl does not use INIT_ONCE directly; the once semantics are
 *   what curl's global init relies on when libcurl is initialised from several
 *   threads (lib/easy_lock.h:28 GLOBAL_INIT_IS_THREADSAFE).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "init_once_execute"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

#define RACERS 8
#define CTX_VALUE ((PVOID)(ULONG_PTR)0xBEE8)

static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
static INIT_ONCE once_fail = INIT_ONCE_STATIC_INIT;
static INIT_ONCE once_manual = INIT_ONCE_STATIC_INIT;
static volatile LONG ok_calls = 0;
static volatile LONG fail_calls = 0;
static volatile LONG fail_mode = 1;

static BOOL CALLBACK init_ok_cb(PINIT_ONCE io, PVOID param, PVOID *ctx)
{
  (void)io;
  (void)param;
  InterlockedIncrement(&ok_calls);
  Sleep(30); /* widen the race window so other callers wait on the init */
  if(ctx)
    *ctx = CTX_VALUE;
  return TRUE;
}

static BOOL CALLBACK single_ctx_cb(PINIT_ONCE io, PVOID param, PVOID *ctx)
{
  (void)io;
  (void)param;
  if(ctx)
    *ctx = CTX_VALUE;
  return TRUE;
}

static BOOL CALLBACK init_fail_cb(PINIT_ONCE io, PVOID param, PVOID *ctx)
{
  (void)io;
  (void)param;
  (void)ctx;
  InterlockedIncrement(&fail_calls);
  if(fail_mode) {
    SetLastError(ERROR_NOT_READY);
    return FALSE;
  }
  return TRUE;
}

typedef struct {
  BOOL ok;
  PVOID ctx;
} racer_result;

static racer_result results[RACERS];

static volatile LONG veh_code = 0;

/* records the exception and ends the scratch thread with a marker code */
static LONG CALLBACK veh(PEXCEPTION_POINTERS ep)
{
  veh_code = (LONG)ep->ExceptionRecord->ExceptionCode;
  ExitThread(0xDEAD);
  return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL CALLBACK bad_ctx_cb(PINIT_ONCE io, PVOID param, PVOID *ctx)
{
  (void)io;
  (void)param;
  *ctx = (PVOID)(ULONG_PTR)0x77; /* low two bits set */
  return TRUE;
}

static DWORD WINAPI bad_ctx_thread(LPVOID p)
{
  static INIT_ONCE bad = INIT_ONCE_STATIC_INIT;
  PVOID c = NULL;
  (void)p;
  InitOnceExecuteOnce(&bad, bad_ctx_cb, NULL, &c);
  return 0;
}

static DWORD WINAPI racer(LPVOID p)
{
  racer_result *r = (racer_result *)p;
  PVOID ctx = NULL;
  r->ok = InitOnceExecuteOnce(&once, init_ok_cb, (PVOID)(ULONG_PTR)42, &ctx);
  r->ctx = ctx;
  return 0;
}

int main(void)
{
  HANDLE th[RACERS];
  int i;
  BOOL ok;
  PVOID ctx = NULL;
  BOOL pending = FALSE;

  /* 0. single caller with a context out-parameter: must succeed and return
   * the context. */
  {
    static INIT_ONCE once_single = INIT_ONCE_STATIC_INIT;
    PVOID sctx = NULL;
    ok = InitOnceExecuteOnce(&once_single, single_ctx_cb, NULL, &sctx);
    if(!ok)
      FAILF("single InitOnceExecuteOnce with context out-param returned FALSE although callback returned TRUE (GLE=%lu)", GetLastError());
    if(sctx != CTX_VALUE)
      FAILF("single InitOnceExecuteOnce context %p, expected 0xBEE8", sctx);
  }

  /* 1. race: 8 threads, exactly one callback invocation */
  for(i = 0; i < RACERS; i++) {
    th[i] = CreateThread(NULL, 0, racer, &results[i], 0, NULL);
    if(!th[i])
      FAILF("CreateThread(%d) failed (GLE=%lu)", i, GetLastError());
  }
  if(WaitForMultipleObjects(RACERS, th, TRUE, 20000) != WAIT_OBJECT_0)
    FAILF("racers did not finish (GLE=%lu)", GetLastError());
  for(i = 0; i < RACERS; i++)
    CloseHandle(th[i]);

  if(InterlockedCompareExchange(&ok_calls, 0, 0) != 1)
    FAILF("init callback ran %ld times, expected exactly 1", (long)ok_calls);
  for(i = 0; i < RACERS; i++) {
    if(!results[i].ok)
      FAILF("racer %d got FALSE from InitOnceExecuteOnce", i);
    if(results[i].ctx != CTX_VALUE)
      FAILF("racer %d context %p, expected 0xBEE8", i, results[i].ctx);
  }

  /* 2. a second call after success does not run the callback again */
  ok = InitOnceExecuteOnce(&once, init_ok_cb, (PVOID)(ULONG_PTR)42, &ctx);
  if(!ok || ctx != CTX_VALUE)
    FAILF("post-init call returned %d ctx=%p (GLE=%lu)", ok, ctx, GetLastError());
  if(InterlockedCompareExchange(&ok_calls, 0, 0) != 1)
    FAILF("callback re-ran after success (count=%ld)", (long)ok_calls);

  /* 3. failing callback: first call FALSE, next call retries and succeeds */
  ok = InitOnceExecuteOnce(&once_fail, init_fail_cb, NULL, NULL);
  if(ok)
    FAILF("InitOnceExecuteOnce returned TRUE although callback failed");
  if(InterlockedCompareExchange(&fail_calls, 0, 0) != 1)
    FAILF("failing callback count %ld, expected 1", (long)fail_calls);
  fail_mode = 0;
  ok = InitOnceExecuteOnce(&once_fail, init_fail_cb, NULL, NULL);
  if(!ok)
    FAILF("retry after failed init returned FALSE (GLE=%lu)", GetLastError());
  if(InterlockedCompareExchange(&fail_calls, 0, 0) != 2)
    FAILF("callback count after retry %ld, expected 2", (long)fail_calls);
  ok = InitOnceExecuteOnce(&once_fail, init_fail_cb, NULL, NULL);
  if(!ok || InterlockedCompareExchange(&fail_calls, 0, 0) != 2)
    FAILF("completed once re-ran callback or returned FALSE");

  /* 4. manual Begin / Complete round trip */
  ok = InitOnceBeginInitialize(&once_manual, 0, &pending, NULL);
  if(!ok || !pending)
    FAILF("InitOnceBeginInitialize first call: ok=%d pending=%d (GLE=%lu)", ok, pending, GetLastError());
  if(!InitOnceComplete(&once_manual, 0, (PVOID)(ULONG_PTR)0x78))
    FAILF("InitOnceComplete failed (GLE=%lu)", GetLastError());
  pending = TRUE;
  ctx = NULL;
  ok = InitOnceBeginInitialize(&once_manual, 0, &pending, &ctx);
  if(!ok || pending)
    FAILF("InitOnceBeginInitialize after complete: ok=%d pending=%d", ok, pending);
  if(ctx != (PVOID)(ULONG_PTR)0x78)
    FAILF("manual context %p, expected 0x78", ctx);

  /* 5. a context with low bits set: InitOnceComplete fails with
   * ERROR_INVALID_PARAMETER, InitOnceExecuteOnce (callback stores the bad
   * value) raises STATUS_INVALID_PARAMETER_3 */
  {
    static INIT_ONCE manual = INIT_ONCE_STATIC_INIT;
    BOOL pend = FALSE;
    if(!InitOnceBeginInitialize(&manual, 0, &pend, NULL) || !pend)
      FAILF("Begin for the bad-context check failed");
    SetLastError(0);
    if(InitOnceComplete(&manual, 0, (PVOID)(ULONG_PTR)0x77) || GetLastError() != ERROR_INVALID_PARAMETER)
      FAILF("InitOnceComplete(context 0x77): expected FALSE / 87 (GLE=%lu)", (unsigned long)GetLastError());
    if(!InitOnceComplete(&manual, 0, (PVOID)(ULONG_PTR)0x7c))
      FAILF("InitOnceComplete(context 0x7c) failed (GLE=%lu)", (unsigned long)GetLastError());
  }
  {
    PVOID h = AddVectoredExceptionHandler(1, veh);
    HANDLE t = CreateThread(NULL, 0, bad_ctx_thread, NULL, 0, NULL);
    DWORD code = 0;
    if(!t)
      FAILF("CreateThread(bad ctx) failed (GLE=%lu)", GetLastError());
    if(WaitForSingleObject(t, 20000) != WAIT_OBJECT_0)
      FAILF("bad-context thread did not end");
    GetExitCodeThread(t, &code);
    CloseHandle(t);
    RemoveVectoredExceptionHandler(h);
    if(code != 0xDEAD || (ULONG)veh_code != 0xC00000F1UL)
      FAILF("InitOnceExecuteOnce storing context 0x77: thread=0x%lx exception=0x%lx, "
            "expected 0xDEAD / 0xC00000F1", (unsigned long)code, (unsigned long)veh_code);
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
