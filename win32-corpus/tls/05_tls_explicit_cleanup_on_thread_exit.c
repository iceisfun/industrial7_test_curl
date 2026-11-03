/*
 * Test: 05_tls_explicit_cleanup_on_thread_exit
 * Area: tls
 * Purpose: TLS slots have NO destructor. When a thread exits, Windows does
 *          not free or call anything for the heap pointer stored in a TLS
 *          slot. The owning code must release it before the thread returns.
 *          This test runs that explicit-cleanup pattern in a worker, checks
 *          the worker's buffer is released exactly once, and checks that the
 *          creator's own TLS value is untouched by the worker's exit.
 * APIs: TlsAlloc, TlsSetValue, TlsGetValue, TlsFree, CreateThread,
 *       WaitForSingleObject, GetExitCodeThread, CloseHandle
 * curl relevance: curl stores no per-thread buffers in TLS (no TlsAlloc hits
 *          in lib/ or src/), so the explicit-release rule tested here is the
 *          one any TLS-based design would have to follow. Contrast with test
 *          06, where FLS does run callbacks.
 * Success: worker's explicit free runs once (counter == 1); the worker's
 *          slot reads NULL after the free; main's slot still holds main's
 *          sentinel after the worker exits; the worker reports no failures.
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
#include <stdlib.h>
#include <string.h>

#define TEST_NAME "05_tls_explicit_cleanup_on_thread_exit"

static DWORD g_idx = TLS_OUT_OF_INDEXES;
static volatile LONG g_free_calls = 0;

typedef struct {
    int ok;
} worker_result_t;

/* Release helper: the code that owns the TLS buffer does this explicitly. */
static void buffer_release(void *p)
{
    InterlockedIncrement(&g_free_calls);
    free(p);
}

static DWORD WINAPI worker_main(LPVOID arg)
{
    worker_result_t *res = (worker_result_t *)arg;
    char *buf;

    res->ok = 0;
    buf = (char *)malloc(64);
    if(!buf)
        return 1;
    strcpy(buf, "worker-owned");

    if(!TlsSetValue(g_idx, buf))
        return 2;
    if(TlsGetValue(g_idx) != buf)
        return 3;
    if(strcmp((char *)TlsGetValue(g_idx), "worker-owned") != 0)
        return 4;

    /* Explicit cleanup before the thread exits. */
    buffer_release(TlsGetValue(g_idx));
    if(!TlsSetValue(g_idx, NULL))
        return 5;
    if(TlsGetValue(g_idx) != NULL)
        return 6;

    res->ok = 1;
    return 0;
}

int main(void)
{
    static const char sentinel[] = "main-sentinel";
    HANDLE th;
    DWORD code = 99;
    worker_result_t res;

    g_idx = TlsAlloc();
    if(g_idx == TLS_OUT_OF_INDEXES) {
        printf("FAIL %s: TlsAlloc failed (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        return 1;
    }
    if(!TlsSetValue(g_idx, (void *)sentinel)) {
        printf("FAIL %s: TlsSetValue(main) failed (GetLastError=%lu)\n",
               TEST_NAME, (unsigned long)GetLastError());
        TlsFree(g_idx);
        return 1;
    }

    th = CreateThread(NULL, 0, worker_main, &res, 0, NULL);
    if(!th) {
        printf("FAIL %s: CreateThread failed (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        TlsFree(g_idx);
        return 1;
    }
    if(WaitForSingleObject(th, 10000) != WAIT_OBJECT_0) {
        printf("FAIL %s: worker did not finish\n", TEST_NAME);
        CloseHandle(th);
        TlsFree(g_idx);
        return 1;
    }
    GetExitCodeThread(th, &code);
    CloseHandle(th);

    if(code != 0) {
        printf("FAIL %s: worker returned step code %lu\n", TEST_NAME,
               (unsigned long)code);
        TlsFree(g_idx);
        return 1;
    }
    if(!res.ok) {
        printf("FAIL %s: worker did not mark success\n", TEST_NAME);
        TlsFree(g_idx);
        return 1;
    }
    if(g_free_calls != 1) {
        printf("FAIL %s: explicit release ran %ld times, expected 1\n",
               TEST_NAME, (long)g_free_calls);
        TlsFree(g_idx);
        return 1;
    }
    if((const char *)TlsGetValue(g_idx) != sentinel) {
        printf("FAIL %s: main thread slot changed after worker exit\n", TEST_NAME);
        TlsFree(g_idx);
        return 1;
    }

    TlsFree(g_idx);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
