/*
 * Test: 13_tls_per_thread_proc_cache
 *
 * Purpose: Thread-local storage around dynamically resolved procedures. Each
 *   worker thread (a) starts with a NULL TLS value, (b) stores its own value
 *   in a TlsAlloc slot, (c) caches a GetProcAddress result in a second TLS
 *   slot, (d) keeps a C11 _Thread_local counter, then (e) verifies that all of
 *   these survived other threads running concurrently and that the cached
 *   procedure really executes in the thread that called it. The main thread's
 *   values must be untouched by the workers.
 *
 * APIs: TlsAlloc, TlsSetValue, TlsGetValue, TlsFree, CreateThread,
 *   WaitForMultipleObjects, GetExitCodeThread, GetProcAddress, GetModuleHandleW,
 *   GetCurrentThreadId, Sleep, _Thread_local (C11)
 *
 * Success:
 *   - Each worker exits with code 0 (all checks in the worker passed).
 *   - Main thread's TLS slot still holds 0x5151 and its _Thread_local counter
 *     still reads 42 after the workers finish.
 *   - TlsAlloc returns valid indexes (not TLS_OUT_OF_INDEXES).
 *
 * Source reference: none in curl. This checks the per-thread TLS contract that
 *   any dynamically resolved, thread-cached procedure pointer would depend on.
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
#include <stdio.h>
#include <stdint.h>

#define NAME "tls_per_thread_proc_cache"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

#define NUM_THREADS 6
#define MAIN_TLS_VALUE ((LPVOID)(uintptr_t)0x5151u)

typedef DWORD (WINAPI *get_tid_fn)(void);

static DWORD g_slot_value;
static DWORD g_slot_proc;
static HMODULE g_k32;
static _Thread_local DWORD tl_count = 0;

static DWORD WINAPI worker(LPVOID arg)
{
    DWORD id = (DWORD)(uintptr_t)arg;
    DWORD i;
    FARPROC p;
    get_tid_fn gettid;
    LPVOID cur;

    /* (a) A new thread starts with a NULL TLS value and no error. */
    SetLastError(ERROR_SUCCESS);
    cur = TlsGetValue(g_slot_value);
    if (cur != NULL || GetLastError() != ERROR_SUCCESS)
        return 10;

    /* (b) Store a per-thread value. */
    if (!TlsSetValue(g_slot_value, (LPVOID)(uintptr_t)(id + 100u)))
        return 11;

    /* (c) Cache a resolved procedure in a second slot. */
    p = GetProcAddress(g_k32, "GetCurrentThreadId");
    if (!p)
        return 12;
    if (!TlsSetValue(g_slot_proc, (LPVOID)p))
        return 13;

    /* (d) Thread-local C variable. */
    for (i = 0; i < 1000; i++)
        tl_count++;

    /* Let the other threads run and overlap with us. */
    Sleep(20);

    /* (e) Everything must have survived the interleaving. */
    if ((uintptr_t)TlsGetValue(g_slot_value) != (uintptr_t)(id + 100u))
        return 14;

    gettid = (get_tid_fn)(void *)TlsGetValue(g_slot_proc);
    if (!gettid)
        return 15;
    if (gettid() != GetCurrentThreadId())
        return 16;

    if (tl_count != 1000)
        return 17;

    return 0;
}

int main(void)
{
    HANDLE threads[NUM_THREADS];
    DWORD code, i, waited;
    LPVOID v;

    g_slot_value = TlsAlloc();
    if (g_slot_value == TLS_OUT_OF_INDEXES)
        FAILF("TlsAlloc(value) err=%lu", (unsigned long)GetLastError());
    g_slot_proc = TlsAlloc();
    if (g_slot_proc == TLS_OUT_OF_INDEXES)
        FAILF("TlsAlloc(proc) err=%lu", (unsigned long)GetLastError());

    g_k32 = GetModuleHandleW(L"kernel32.dll");
    if (!g_k32)
        FAILF("GetModuleHandleW(kernel32.dll) err=%lu", (unsigned long)GetLastError());

    if (!TlsSetValue(g_slot_value, MAIN_TLS_VALUE))
        FAILF("main TlsSetValue err=%lu", (unsigned long)GetLastError());
    tl_count = 42;

    for (i = 0; i < NUM_THREADS; i++) {
        threads[i] = CreateThread(NULL, 0, worker, (LPVOID)(uintptr_t)i, 0, NULL);
        if (!threads[i])
            FAILF("CreateThread[%lu] err=%lu", (unsigned long)i, (unsigned long)GetLastError());
    }

    waited = WaitForMultipleObjects(NUM_THREADS, threads, TRUE, 50000);
    if (waited == WAIT_FAILED || waited == WAIT_TIMEOUT)
        FAILF("WaitForMultipleObjects returned 0x%lx", (unsigned long)waited);

    for (i = 0; i < NUM_THREADS; i++) {
        if (!GetExitCodeThread(threads[i], &code))
            FAILF("GetExitCodeThread[%lu] err=%lu", (unsigned long)i, (unsigned long)GetLastError());
        if (code != 0)
            FAILF("worker %lu failed check %lu", (unsigned long)i, (unsigned long)code);
        CloseHandle(threads[i]);
    }

    v = TlsGetValue(g_slot_value);
    if (v != MAIN_TLS_VALUE)
        FAILF("main TLS value clobbered: %p", v);
    if (tl_count != 42)
        FAILF("main _Thread_local counter clobbered: %lu", (unsigned long)tl_count);

    TlsFree(g_slot_value);
    TlsFree(g_slot_proc);

    printf("PASS " NAME "\n");
    return 0;
}
