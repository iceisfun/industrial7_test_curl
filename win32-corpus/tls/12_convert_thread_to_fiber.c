/*
 * Test: 12_convert_thread_to_fiber
 * Area: tls
 * Purpose: A worker thread converts itself to a fiber, creates a second
 *          fiber, switches into it, the fiber switches back, and the thread
 *          converts back to a plain thread. Checks the fiber state each step:
 *          IsThreadAFiber, GetCurrentFiber, and that the fiber ran.
 * APIs: ConvertThreadToFiber, CreateFiber, SwitchToFiber, DeleteFiber,
 *       ConvertFiberToThread, GetCurrentFiber, IsThreadAFiber,
 *       CreateThread, WaitForSingleObject, GetExitCodeThread, CloseHandle
 * curl relevance: curl uses no fibers (no ConvertThreadToFiber or CreateFiber
 *          hits in lib/ or src/). The test covers the minimal thread-to-fiber
 *          conversion sequence. It runs on a worker so the test process's main
 *          thread stays a plain thread.
 * Success: ConvertThreadToFiber returns non-NULL and GetCurrentFiber returns
 *          it; IsThreadAFiber is TRUE; the fiber body runs and observes that
 *          it is not the main fiber; control returns to the main fiber; the
 *          thread is no longer a fiber after ConvertFiberToThread.
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

#define TEST_NAME "12_convert_thread_to_fiber"

static LPVOID g_main_fiber = NULL;
static LPVOID g_child_fiber = NULL;
static volatile LONG g_steps = 0;
static volatile LONG g_fiber_saw_other = 0;

static VOID CALLBACK child_proc(LPVOID param)
{
    LONG *counter = (LONG *)param;
    /* Running inside the child fiber: the current fiber must differ from main. */
    g_fiber_saw_other = (GetCurrentFiber() != g_main_fiber);
    *counter += 1;
    g_steps = *counter;
    SwitchToFiber(g_main_fiber);
    /* Never resumed in this test. */
}

static DWORD WINAPI worker_main(LPVOID arg)
{
    static LONG counter = 0;
    LPVOID self;
    int *result = (int *)arg;
    int rc = 0;

    *result = 0;
    if(IsThreadAFiber()) {
        /* Should be FALSE for a fresh thread. */
        return 1;
    }

    self = ConvertThreadToFiber(NULL);
    if(!self)
        return 2;
    g_main_fiber = self;

    if(GetCurrentFiber() != self)
        return 3;
    if(!IsThreadAFiber())
        return 4;

    g_child_fiber = CreateFiber(0, child_proc, &counter);
    if(!g_child_fiber) {
        rc = 5;
        goto out_convert_back;
    }

    SwitchToFiber(g_child_fiber);

    /* Back on the main fiber after the child switched to us. */
    if(GetCurrentFiber() != g_main_fiber) {
        rc = 6;
        goto out_delete;
    }
    if(g_steps != 1) {
        rc = 7;
        goto out_delete;
    }
    if(!g_fiber_saw_other) {
        rc = 8;
        goto out_delete;
    }

    *result = 1;

out_delete:
    DeleteFiber(g_child_fiber);
    g_child_fiber = NULL;

out_convert_back:
    if(!ConvertFiberToThread())
        return rc ? rc : 9;
    if(IsThreadAFiber())
        return rc ? rc : 10;

    return rc;
}

int main(void)
{
    HANDLE th;
    DWORD code = 99;
    int result = 0;

    th = CreateThread(NULL, 0, worker_main, &result, 0, NULL);
    if(!th) {
        printf("FAIL %s: CreateThread failed (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        return 1;
    }
    if(WaitForSingleObject(th, 10000) != WAIT_OBJECT_0) {
        printf("FAIL %s: worker did not finish\n", TEST_NAME);
        CloseHandle(th);
        return 1;
    }
    GetExitCodeThread(th, &code);
    CloseHandle(th);

    if(code != 0) {
        printf("FAIL %s: worker step code %lu (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)code, (unsigned long)GetLastError());
        return 1;
    }
    if(result != 1) {
        printf("FAIL %s: fiber round-trip did not complete\n", TEST_NAME);
        return 1;
    }

    printf("PASS %s\n", TEST_NAME);
    return 0;
}
