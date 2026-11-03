/*
 * Test: 08_fls_thread_isolation_and_errors
 * Area: tls
 * Purpose: FLS values are per thread (and per fiber, see test 13). The main
 *          thread's FLS value must survive worker threads writing the same
 *          index, and a new thread must start NULL. Invalid index use must
 *          fail: FlsSetValue(FLS_OUT_OF_INDEXES) returns FALSE and
 *          FlsGetValue(FLS_OUT_OF_INDEXES) returns NULL.
 * APIs: FlsAlloc, FlsSetValue, FlsGetValue, FlsFree, CreateThread,
 *       WaitForSingleObject, GetExitCodeThread, CloseHandle, GetLastError
 * curl relevance: curl starts its Win32 workers with CreateThread
 *          (lib/curl_threads.c:35) and uses no FLS (no FlsAlloc hits in lib/ or
 *          src/). The test covers the isolation contract FLS-based code on such
 *          threads would rely on.
 * Success: main reads back 0x5151 after two workers have each written their
 *          own value; each worker reads NULL on entry and its own value on
 *          exit; main's value is unchanged; invalid index calls fail as above.
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

#define TEST_NAME "08_fls_thread_isolation_and_errors"
#define NWORKERS 2

static DWORD g_idx = FLS_OUT_OF_INDEXES;
static volatile LONG g_ready = 0;
static HANDLE g_go = NULL;

typedef struct {
    uintptr_t tag;
    int entry_null;
    int exit_ok;
} worker_t;

static DWORD WINAPI worker_main(LPVOID arg)
{
    worker_t *w = (worker_t *)arg;
    w->entry_null = (FlsGetValue(g_idx) == NULL);
    if(!FlsSetValue(g_idx, (void *)w->tag))
        return 1;
    InterlockedIncrement(&g_ready);
    if(WaitForSingleObject(g_go, 10000) != WAIT_OBJECT_0)
        return 2;
    w->exit_ok = ((uintptr_t)FlsGetValue(g_idx) == w->tag);
    return 0;
}

int main(void)
{
    HANDLE th[NWORKERS];
    worker_t w[NWORKERS];
    uintptr_t main_tag = 0x5151;
    DWORD waited = 0;
    int i, ok = 1;

    g_idx = FlsAlloc(NULL);
    if(g_idx == FLS_OUT_OF_INDEXES) {
        printf("FAIL %s: FlsAlloc failed (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        return 1;
    }
    g_go = CreateEventW(NULL, TRUE, FALSE, NULL);
    if(!g_go) {
        printf("FAIL %s: CreateEvent failed (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        FlsFree(g_idx);
        return 1;
    }

    if(!FlsSetValue(g_idx, (void *)main_tag)) {
        printf("FAIL %s: FlsSetValue(main) failed (GetLastError=%lu)\n",
               TEST_NAME, (unsigned long)GetLastError());
        return 1;
    }

    for(i = 0; i < NWORKERS; i++) {
        w[i].tag = 0x9000 + (uintptr_t)i;
        w[i].entry_null = 0;
        w[i].exit_ok = 0;
        th[i] = CreateThread(NULL, 0, worker_main, &w[i], 0, NULL);
        if(!th[i]) {
            printf("FAIL %s: CreateThread %d failed (GetLastError=%lu)\n",
                   TEST_NAME, i, (unsigned long)GetLastError());
            return 1;
        }
    }

    while(g_ready < NWORKERS) {
        Sleep(1);
        if(++waited > 10000) {
            printf("FAIL %s: workers did not reach the barrier\n", TEST_NAME);
            return 1;
        }
    }

    if((uintptr_t)FlsGetValue(g_idx) != main_tag) {
        printf("FAIL %s: main FLS value overwritten by a worker\n", TEST_NAME);
        return 1;
    }

    SetEvent(g_go);
    WaitForMultipleObjects(NWORKERS, th, TRUE, 10000);

    for(i = 0; i < NWORKERS; i++) {
        DWORD code = 0;
        GetExitCodeThread(th[i], &code);
        CloseHandle(th[i]);
        if(code != 0) {
            printf("FAIL %s: worker %d exit code %lu\n", TEST_NAME, i,
                   (unsigned long)code);
            ok = 0;
        } else if(!w[i].entry_null) {
            printf("FAIL %s: worker %d saw a non-NULL FLS value on entry\n",
                   TEST_NAME, i);
            ok = 0;
        } else if(!w[i].exit_ok) {
            printf("FAIL %s: worker %d read a foreign FLS value\n", TEST_NAME, i);
            ok = 0;
        }
    }
    if(!ok) {
        FlsFree(g_idx);
        return 1;
    }

    if((uintptr_t)FlsGetValue(g_idx) != main_tag) {
        printf("FAIL %s: main FLS value changed after workers exited\n", TEST_NAME);
        FlsFree(g_idx);
        return 1;
    }

    /* Invalid index: FlsSetValue must fail, FlsGetValue must return NULL. */
    if(FlsSetValue(FLS_OUT_OF_INDEXES, (void *)0x1)) {
        printf("FAIL %s: FlsSetValue(FLS_OUT_OF_INDEXES) succeeded\n", TEST_NAME);
        FlsFree(g_idx);
        return 1;
    }
    SetLastError(ERROR_SUCCESS);
    if(FlsGetValue(FLS_OUT_OF_INDEXES) != NULL) {
        printf("FAIL %s: FlsGetValue(FLS_OUT_OF_INDEXES) returned non-NULL\n",
               TEST_NAME);
        FlsFree(g_idx);
        return 1;
    }

    CloseHandle(g_go);
    FlsFree(g_idx);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
