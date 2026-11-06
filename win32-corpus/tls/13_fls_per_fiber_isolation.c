/*
 * Test: 13_fls_per_fiber_isolation
 * Area: tls
 * Purpose: Inside a thread that has been converted to a fiber, FLS values are
 *          per fiber: a new fiber starts with NULL in an index the thread
 *          already wrote, and writes in the child fiber do not appear in the
 *          thread's own fiber. The thread's own value is checked after the
 *          child fiber has run.
 * APIs: FlsAlloc, FlsSetValue, FlsGetValue, FlsFree, ConvertThreadToFiber,
 *       CreateFiber, SwitchToFiber, DeleteFiber, ConvertFiberToThread,
 *       CreateThread, WaitForSingleObject, GetExitCodeThread, CloseHandle
 * curl relevance: curl uses no FLS (no FlsAlloc hits in lib/ or src/). The
 *          test covers the per-fiber FLS isolation that fiber-based code on a
 *          curl thread would rely on.
 * Success: thread's FLS value 0x1111 is still there after the child fiber
 *          runs; the child reads NULL on entry and then 0x2222 after its own
 *          write; the thread fiber reads 0x1111 after the switch back.
 * Exit: 0 PASS, 1 FAIL (every API used exists on Win10 22H2: no SKIP).
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

#define TEST_NAME "13_fls_per_fiber_isolation"

static DWORD g_idx = FLS_OUT_OF_INDEXES;
static LPVOID g_main_fiber = NULL;
static LPVOID g_child = NULL;
static volatile LONG g_child_entry_null = 0;
static volatile LONG g_child_own_ok = 0;

static VOID CALLBACK child_proc(LPVOID param)
{
    (void)param;
    g_child_entry_null = (FlsGetValue(g_idx) == NULL);
    g_child_own_ok = (FlsSetValue(g_idx, (void *)(uintptr_t)0x2222) &&
                      (uintptr_t)FlsGetValue(g_idx) == 0x2222);
    SwitchToFiber(g_main_fiber);
}

static DWORD WINAPI worker_main(LPVOID arg)
{
    int *result = (int *)arg;
    int rc = 0;

    *result = 0;
    g_main_fiber = ConvertThreadToFiber(NULL);
    if(!g_main_fiber)
        return 1;

    if(!FlsSetValue(g_idx, (void *)(uintptr_t)0x1111))
        rc = 2;
    else if((uintptr_t)FlsGetValue(g_idx) != 0x1111)
        rc = 3;
    else {
        g_child = CreateFiber(0, child_proc, NULL);
        if(!g_child) {
            rc = 4;
        }
        else {
            SwitchToFiber(g_child);

            /* Back on the thread's own fiber: its value must be intact. */
            if((uintptr_t)FlsGetValue(g_idx) != 0x1111)
                rc = 5;
            else if(g_child_entry_null != 1)
                rc = 6;
            else if(g_child_own_ok != 1)
                rc = 7;
            DeleteFiber(g_child);
            g_child = NULL;
        }
    }

    if(!ConvertFiberToThread())
        return rc ? rc : 8;

    if(rc == 0)
        *result = 1;
    return (DWORD)rc;
}

int main(void)
{
    HANDLE th;
    DWORD code = 99;
    int result = 0;

    g_idx = FlsAlloc(NULL);
    if(g_idx == FLS_OUT_OF_INDEXES) {
        printf("FAIL %s: FlsAlloc failed (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        return 1;
    }

    th = CreateThread(NULL, 0, worker_main, &result, 0, NULL);
    if(!th) {
        printf("FAIL %s: CreateThread failed (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        FlsFree(g_idx);
        return 1;
    }
    if(WaitForSingleObject(th, 10000) != WAIT_OBJECT_0) {
        printf("FAIL %s: worker did not finish\n", TEST_NAME);
        CloseHandle(th);
        FlsFree(g_idx);
        return 1;
    }
    GetExitCodeThread(th, &code);
    CloseHandle(th);

    if(code != 0 || result != 1) {
        printf("FAIL %s: worker step code %lu (result=%d, GetLastError=%lu)\n",
               TEST_NAME, (unsigned long)code, result,
               (unsigned long)GetLastError());
        FlsFree(g_idx);
        return 1;
    }

    /* The main thread's own FLS value was never written and must still be NULL. */
    if(FlsGetValue(g_idx) != NULL) {
        printf("FAIL %s: main thread FLS value leaked from worker fiber\n", TEST_NAME);
        FlsFree(g_idx);
        return 1;
    }

    FlsFree(g_idx);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
