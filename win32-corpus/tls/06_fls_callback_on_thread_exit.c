/*
 * Test: 06_fls_callback_on_thread_exit
 * Area: tls
 * Purpose: FLS (fiber local storage) slots allocated with FlsAlloc can carry a
 *          destructor callback. When a thread exits, the callback runs on that
 *          thread for every non-NULL value in the slot. Threads whose slot is
 *          NULL must not trigger the callback.
 * APIs: FlsAlloc, FlsSetValue, FlsGetValue, FlsFree, CreateThread,
 *       WaitForSingleObject, GetExitCodeThread, CloseHandle, GetCurrentThreadId
 * curl relevance: curl creates its Win32 threads with CreateThread
 *          (lib/curl_threads.c:35) but uses no FLS (no FlsAlloc hits in lib/ or
 *          src/). The test covers the destructor-on-thread-exit rule that
 *          FLS-tracked per-thread resources would depend on.
 * Success: after worker A (value set) exits, the callback has run exactly once
 *          with that value on worker A's own thread id; after worker B (value
 *          never set) exits, the callback count stays at 1.
 * Exit: 0 PASS, 1 FAIL, 77 SKIP.
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
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#define TEST_NAME "06_fls_callback_on_thread_exit"

static DWORD g_idx = FLS_OUT_OF_INDEXES;
static volatile LONG g_calls = 0;
static volatile uintptr_t g_last_value = 0;
static volatile DWORD g_last_tid = 0;

static void WINAPI fls_dtor(void *value)
{
    g_last_value = (uintptr_t)value;
    g_last_tid = GetCurrentThreadId();
    InterlockedIncrement(&g_calls);
}

static DWORD WINAPI worker_set(LPVOID arg)
{
    DWORD *tid_out = (DWORD *)arg;
    *tid_out = GetCurrentThreadId();
    if(!FlsSetValue(g_idx, (void *)(uintptr_t)0xABC0))
        return 1;
    if((uintptr_t)FlsGetValue(g_idx) != 0xABC0)
        return 2;
    return 0;
}

static DWORD WINAPI worker_unset(LPVOID arg)
{
    (void)arg;
    if(FlsGetValue(g_idx) != NULL)
        return 3;   /* a new thread must start with NULL */
    return 0;
}

static int run_worker(LPTHREAD_START_ROUTINE fn, LPVOID arg, DWORD *code)
{
    HANDLE th = CreateThread(NULL, 0, fn, arg, 0, NULL);
    if(!th)
        return 0;
    if(WaitForSingleObject(th, 10000) != WAIT_OBJECT_0) {
        CloseHandle(th);
        return 0;
    }
    GetExitCodeThread(th, code);
    CloseHandle(th);
    return 1;
}

int main(void)
{
    DWORD tid_a = 0, code = 99;

    g_idx = FlsAlloc(fls_dtor);
    if(g_idx == FLS_OUT_OF_INDEXES) {
        printf("FAIL %s: FlsAlloc failed (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        return 1;
    }

    /* Worker A stores a value, then exits: callback must fire once. */
    if(!run_worker(worker_set, &tid_a, &code)) {
        printf("FAIL %s: worker A did not run (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        FlsFree(g_idx);
        return 1;
    }
    if(code != 0) {
        printf("FAIL %s: worker A reported step %lu\n", TEST_NAME,
               (unsigned long)code);
        FlsFree(g_idx);
        return 1;
    }
    if(g_calls != 1) {
        printf("FAIL %s: callback ran %ld times after worker A exit, expected 1\n",
               TEST_NAME, (long)g_calls);
        FlsFree(g_idx);
        return 1;
    }
    if(g_last_value != 0xABC0) {
        printf("FAIL %s: callback received 0x%llx, expected 0xabc0\n", TEST_NAME,
               (unsigned long long)g_last_value);
        FlsFree(g_idx);
        return 1;
    }
    if(g_last_tid != tid_a) {
        printf("FAIL %s: callback ran on thread %lu, expected worker A thread %lu\n",
               TEST_NAME, (unsigned long)g_last_tid, (unsigned long)tid_a);
        FlsFree(g_idx);
        return 1;
    }

    /* Worker B never sets a value: no callback may run for it. */
    if(!run_worker(worker_unset, NULL, &code)) {
        printf("FAIL %s: worker B did not run (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        FlsFree(g_idx);
        return 1;
    }
    if(code != 0) {
        printf("FAIL %s: worker B reported step %lu (slot not NULL on entry)\n",
               TEST_NAME, (unsigned long)code);
        FlsFree(g_idx);
        return 1;
    }
    if(g_calls != 1) {
        printf("FAIL %s: callback ran for a NULL slot (count=%ld)\n", TEST_NAME,
               (long)g_calls);
        FlsFree(g_idx);
        return 1;
    }

    FlsFree(g_idx);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
