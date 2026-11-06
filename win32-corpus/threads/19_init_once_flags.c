/*
 * Test: init_once_flags
 *
 * Purpose: the INIT_ONCE begin/complete protocol beyond InitOnceExecuteOnce
 * (test 10): INIT_ONCE_CHECK_ONLY, INIT_ONCE_INIT_FAILED and INIT_ONCE_ASYNC.
 * libcurl's global init (lib/easy_lock.h GLOBAL_INIT_IS_THREADSAFE, lib/easy.c
 * global_init) needs exactly-once semantics and a retry after a failed init;
 * these flags are how a Windows implementation expresses that.
 *
 * APIs: InitOnceInitialize, InitOnceBeginInitialize, InitOnceComplete,
 *   InitOnceExecuteOnce, INIT_ONCE_CHECK_ONLY, INIT_ONCE_INIT_FAILED,
 *   INIT_ONCE_ASYNC.
 *
 * Success (probed on Windows 10 22H2). CHECK_ONLY on a fresh object returns
 * FALSE with ERROR_GEN_FAILURE (31), also while a synchronous initialisation
 * is in progress. A failed completion (INIT_ONCE_INIT_FAILED) returns TRUE and
 * the next Begin reports pending again. After a successful completion with
 * context 0x40, CHECK_ONLY returns TRUE with fPending FALSE and the context. A
 * second InitOnceComplete (or one without Begin) returns FALSE with 31. In
 * async mode two Begin calls both return TRUE with fPending TRUE; the first
 * completion wins (TRUE, context 0x20), the second returns FALSE with 31 and
 * the stored context stays 0x20. Context values must have the low two bits
 * clear (see test 10).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "init_once_flags"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static BOOL CALLBACK cb_ok(PINIT_ONCE io, PVOID param, PVOID *ctx)
{
  (void)io;
  (void)param;
  (void)ctx;
  return TRUE;
}

int main(void)
{
  INIT_ONCE o = INIT_ONCE_STATIC_INIT;
  BOOL pending = FALSE, ok;
  PVOID ctx = NULL;

  SetLastError(0);
  ok = InitOnceBeginInitialize(&o, INIT_ONCE_CHECK_ONLY, &pending, &ctx);
  if(ok || GetLastError() != ERROR_GEN_FAILURE)
    FAILF("CHECK_ONLY on a fresh object: ok=%d GLE=%lu, expected FALSE / 31", ok, (unsigned long)GetLastError());

  ok = InitOnceBeginInitialize(&o, 0, &pending, &ctx);
  if(!ok || !pending)
    FAILF("Begin: ok=%d pending=%d", ok, pending);
  SetLastError(0);
  ok = InitOnceBeginInitialize(&o, INIT_ONCE_CHECK_ONLY, &pending, &ctx);
  if(ok || GetLastError() != ERROR_GEN_FAILURE)
    FAILF("CHECK_ONLY during init: ok=%d GLE=%lu, expected FALSE / 31", ok, (unsigned long)GetLastError());

  if(!InitOnceComplete(&o, INIT_ONCE_INIT_FAILED, NULL))
    FAILF("InitOnceComplete(INIT_ONCE_INIT_FAILED) failed (GLE=%lu)", (unsigned long)GetLastError());
  pending = FALSE;
  ok = InitOnceBeginInitialize(&o, 0, &pending, &ctx);
  if(!ok || !pending)
    FAILF("Begin after failed init: ok=%d pending=%d, expected TRUE/TRUE", ok, pending);

  if(!InitOnceComplete(&o, 0, (PVOID)(ULONG_PTR)0x40))
    FAILF("InitOnceComplete failed (GLE=%lu)", (unsigned long)GetLastError());
  ctx = NULL;
  pending = TRUE;
  ok = InitOnceBeginInitialize(&o, INIT_ONCE_CHECK_ONLY, &pending, &ctx);
  if(!ok || pending || ctx != (PVOID)(ULONG_PTR)0x40)
    FAILF("CHECK_ONLY after completion: ok=%d pending=%d ctx=%p, expected TRUE/FALSE/0x40", ok, pending, ctx);
  SetLastError(0);
  if(InitOnceComplete(&o, 0, (PVOID)(ULONG_PTR)0x40) || GetLastError() != ERROR_GEN_FAILURE)
    FAILF("second InitOnceComplete: GLE=%lu, expected FALSE / 31", (unsigned long)GetLastError());

  /* async: both callers run the initialiser, the first completion wins */
  {
    INIT_ONCE a = INIT_ONCE_STATIC_INIT;
    BOOL p1 = FALSE, p2 = FALSE, b1, b2;
    b1 = InitOnceBeginInitialize(&a, INIT_ONCE_ASYNC, &p1, &ctx);
    b2 = InitOnceBeginInitialize(&a, INIT_ONCE_ASYNC, &p2, &ctx);
    if(!b1 || !p1 || !b2 || !p2)
      FAILF("ASYNC Begin x2: %d/%d %d/%d, expected TRUE/TRUE twice", b1, p1, b2, p2);
    if(!InitOnceComplete(&a, INIT_ONCE_ASYNC, (PVOID)(ULONG_PTR)0x20))
      FAILF("first ASYNC completion failed");
    SetLastError(0);
    if(InitOnceComplete(&a, INIT_ONCE_ASYNC, (PVOID)(ULONG_PTR)0x24) || GetLastError() != ERROR_GEN_FAILURE)
      FAILF("second ASYNC completion: GLE=%lu, expected FALSE / 31", (unsigned long)GetLastError());
    ctx = NULL;
    if(!InitOnceBeginInitialize(&a, 0, &p1, &ctx) || p1 || ctx != (PVOID)(ULONG_PTR)0x20)
      FAILF("ASYNC final: pending=%d ctx=%p, expected FALSE / 0x20", p1, ctx);
    InitOnceInitialize(&a);
    if(!InitOnceExecuteOnce(&a, cb_ok, NULL, NULL))
      FAILF("InitOnceExecuteOnce with a NULL context failed after InitOnceInitialize");
  }

  /* Complete without Begin */
  {
    INIT_ONCE z = INIT_ONCE_STATIC_INIT;
    SetLastError(0);
    if(InitOnceComplete(&z, 0, NULL) || GetLastError() != ERROR_GEN_FAILURE)
      FAILF("InitOnceComplete without Begin: GLE=%lu, expected FALSE / 31", (unsigned long)GetLastError());
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
