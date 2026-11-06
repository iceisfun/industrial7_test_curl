/*
 * Test: 11_thread_id_identity
 * Area: tls
 * Purpose: GetCurrentThreadId returns a stable, non-zero identifier per thread,
 *          distinct across threads, and it agrees with the thread handle
 *          (GetThreadId, Vista+, resolved at runtime). The identifier that a
 *          worker records must match what a thread handle reports for it.
 * APIs: GetCurrentThreadId, GetThreadId (resolved via GetProcAddress from
 *       kernel32.dll), GetCurrentThread, CreateThread, WaitForSingleObject,
 *       GetExitCodeThread, CloseHandle, LoadLibraryW, GetProcAddress
 * curl relevance: lib/curl_threads.c:162-170 implements
 *          Curl_thread_get_current_id and Curl_thread_is_current by comparing
 *          GetCurrentThreadId() values. This test exercises exactly that
 *          identity comparison from both the thread and the creator.
 * Success: main id != 0; main id is stable across two calls; worker id != 0
 *          and != main id; the worker's own Curl_thread_is_current-style check
 *          is TRUE inside the worker and FALSE against main's id; GetThreadId of
 *          the worker handle equals the worker's self-reported id.
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
#include <string.h>

#define TEST_NAME "11_thread_id_identity"

typedef DWORD (WINAPI *GetThreadId_fn)(HANDLE);

typedef struct {
    DWORD self_id;
    DWORD second_call_id;
    int is_current_ok;
} worker_t;

static DWORD g_main_id = 0;

/* Mirrors Curl_thread_is_current(): compare against a stored id. */
static int thread_is_current(DWORD tid)
{
    return tid == GetCurrentThreadId();
}

static DWORD WINAPI worker_main(LPVOID arg)
{
    worker_t *w = (worker_t *)arg;
    w->self_id = GetCurrentThreadId();
    w->second_call_id = GetCurrentThreadId();
    w->is_current_ok = thread_is_current(w->self_id) && !thread_is_current(g_main_id);
    return 0;
}

int main(void)
{
    HMODULE k32;
    GetThreadId_fn p_GetThreadId;
    HANDLE th;
    DWORD code = 99, main_again, handle_id;
    worker_t w;

    k32 = LoadLibraryW(L"kernel32.dll");
    if(!k32) {
        printf("FAIL %s: LoadLibrary(kernel32.dll) failed\n", TEST_NAME);
        return 1;
    }
    {
        /* Convert FARPROC to the real signature without a function-pointer
           cast, which -Wcast-function-type rejects. */
        FARPROC fp = GetProcAddress(k32, "GetThreadId");
        p_GetThreadId = NULL;
        if(fp)
            memcpy(&p_GetThreadId, &fp, sizeof(fp));
    }
    if(!p_GetThreadId) {
        printf("FAIL %s: GetThreadId not exported by this kernel32\n", TEST_NAME);
        return 1;
    }

    g_main_id = GetCurrentThreadId();
    if(g_main_id == 0) {
        printf("FAIL %s: GetCurrentThreadId returned 0 (GetLastError=%lu)\n",
               TEST_NAME, (unsigned long)GetLastError());
        return 1;
    }
    main_again = GetCurrentThreadId();
    if(main_again != g_main_id) {
        printf("FAIL %s: main thread id changed between calls\n", TEST_NAME);
        return 1;
    }

    /* GetThreadId on the pseudo handle must match the calling thread's id. */
    handle_id = p_GetThreadId(GetCurrentThread());
    if(handle_id != g_main_id) {
        printf("FAIL %s: GetThreadId(GetCurrentThread())=%lu, expected %lu\n",
               TEST_NAME, (unsigned long)handle_id, (unsigned long)g_main_id);
        return 1;
    }

    w.self_id = 0;
    w.second_call_id = 0;
    w.is_current_ok = 0;
    th = CreateThread(NULL, 0, worker_main, &w, 0, NULL);
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

    if(code != 0) {
        printf("FAIL %s: worker exit code %lu\n", TEST_NAME, (unsigned long)code);
        CloseHandle(th);
        return 1;
    }
    if(w.self_id == 0) {
        printf("FAIL %s: worker id is 0\n", TEST_NAME);
        CloseHandle(th);
        return 1;
    }
    if(w.self_id == g_main_id) {
        printf("FAIL %s: worker and main share thread id %lu\n", TEST_NAME,
               (unsigned long)w.self_id);
        CloseHandle(th);
        return 1;
    }
    if(w.second_call_id != w.self_id) {
        printf("FAIL %s: worker id changed between calls\n", TEST_NAME);
        CloseHandle(th);
        return 1;
    }
    if(!w.is_current_ok) {
        printf("FAIL %s: is-current comparison wrong inside worker\n", TEST_NAME);
        CloseHandle(th);
        return 1;
    }

    /* The thread handle must report the same id the worker recorded. */
    handle_id = p_GetThreadId(th);
    CloseHandle(th);
    if(handle_id != w.self_id) {
        printf("FAIL %s: GetThreadId(handle)=%lu, worker reported %lu\n",
               TEST_NAME, (unsigned long)handle_id, (unsigned long)w.self_id);
        return 1;
    }

    FreeLibrary(k32);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
