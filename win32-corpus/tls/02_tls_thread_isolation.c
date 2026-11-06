/*
 * Test: 02_tls_thread_isolation
 * Area: tls
 * Purpose: A TLS index is a per-thread slot. Two worker threads and the main
 *          thread each store their own value in the SAME index and must not
 *          observe each other's writes. A new thread must start with NULL in
 *          a slot that another thread has already written.
 * APIs: TlsAlloc, TlsGetValue, TlsSetValue, TlsFree, CreateThread,
 *       WaitForSingleObject, CloseHandle, InterlockedIncrement, CreateEventW,
 *       SetEvent
 * curl relevance: curl creates its Win32 worker threads with CreateThread
 *          (lib/curl_threads.c:35) and identifies them by thread id
 *          (lib/curl_threads.c:162-170). curl has no TLS slots of its own
 *          (no TlsAlloc hits in lib/ or src/); this checks the per-thread
 *          isolation that such slots would rely on.
 * Success: every thread reads back exactly its own tag after all threads
 *          have written; the main thread's tag is unchanged; each worker's
 *          first read (before writing) is NULL.
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

#define TEST_NAME "02_tls_thread_isolation"
#define NWORKERS 2

static DWORD g_idx = TLS_OUT_OF_INDEXES;
static volatile LONG g_ready = 0;
static HANDLE g_go = NULL;

typedef struct {
    uintptr_t tag;
    int first_read_null;   /* 1 if the slot was NULL before this thread wrote */
    int own_value_ok;      /* 1 if the slot still held this thread's tag */
} worker_t;

static DWORD WINAPI worker_main(LPVOID arg)
{
    worker_t *w = (worker_t *)arg;
    void *before;

    before = TlsGetValue(g_idx);
    w->first_read_null = (before == NULL);

    if(!TlsSetValue(g_idx, (void *)w->tag))
        return 1;
    InterlockedIncrement(&g_ready);

    /* Wait until every thread has written its own tag. */
    if(WaitForSingleObject(g_go, 10000) != WAIT_OBJECT_0)
        return 2;

    w->own_value_ok = ((uintptr_t)TlsGetValue(g_idx) == w->tag);
    return 0;
}

int main(void)
{
    HANDLE th[NWORKERS];
    worker_t w[NWORKERS];
    uintptr_t main_tag = 0x111;
    int i, ok = 1;
    DWORD waited = 0;

    g_idx = TlsAlloc();
    if(g_idx == TLS_OUT_OF_INDEXES) {
        printf("FAIL %s: TlsAlloc failed (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        return 1;
    }

    g_go = CreateEventW(NULL, TRUE, FALSE, NULL);
    if(!g_go) {
        printf("FAIL %s: CreateEvent failed (GetLastError=%lu)\n", TEST_NAME,
               (unsigned long)GetLastError());
        TlsFree(g_idx);
        return 1;
    }

    if(!TlsSetValue(g_idx, (void *)main_tag)) {
        printf("FAIL %s: TlsSetValue(main) failed (GetLastError=%lu)\n",
               TEST_NAME, (unsigned long)GetLastError());
        return 1;
    }

    for(i = 0; i < NWORKERS; i++) {
        w[i].tag = 0x1000 + (uintptr_t)i;
        w[i].first_read_null = 0;
        w[i].own_value_ok = 0;
        th[i] = CreateThread(NULL, 0, worker_main, &w[i], 0, NULL);
        if(!th[i]) {
            printf("FAIL %s: CreateThread %d failed (GetLastError=%lu)\n",
                   TEST_NAME, i, (unsigned long)GetLastError());
            return 1;
        }
    }

    /* Wait for all workers to have written their tags, with a bounded spin. */
    while(g_ready < NWORKERS) {
        Sleep(1);
        if(++waited > 10000) {
            printf("FAIL %s: workers did not reach the barrier\n", TEST_NAME);
            return 1;
        }
    }

    /* Main's own slot must still hold main's tag, untouched by workers. */
    if((uintptr_t)TlsGetValue(g_idx) != main_tag) {
        printf("FAIL %s: main thread value was overwritten by a worker\n",
               TEST_NAME);
        return 1;
    }

    SetEvent(g_go);
    WaitForMultipleObjects(NWORKERS, th, TRUE, 10000);

    for(i = 0; i < NWORKERS; i++) {
        DWORD code = 0;
        GetExitCodeThread(th[i], &code);
        if(code != 0) {
            printf("FAIL %s: worker %d exit code %lu\n", TEST_NAME, i,
                   (unsigned long)code);
            ok = 0;
        }
        else if(!w[i].first_read_null) {
            printf("FAIL %s: worker %d saw a non-NULL slot on first read\n",
                   TEST_NAME, i);
            ok = 0;
        }
        else if(!w[i].own_value_ok) {
            printf("FAIL %s: worker %d read back a foreign value\n",
                   TEST_NAME, i);
            ok = 0;
        }
        CloseHandle(th[i]);
    }

    /* Final check: main still sees its own value after all workers exited. */
    if(ok && (uintptr_t)TlsGetValue(g_idx) != main_tag) {
        printf("FAIL %s: main value changed after worker exit\n", TEST_NAME);
        ok = 0;
    }

    CloseHandle(g_go);
    TlsFree(g_idx);

    if(!ok)
        return 1;
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
