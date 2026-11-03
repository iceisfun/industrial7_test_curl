/*
 * Test: 12_threads_concurrent_load
 *
 * Purpose: Concurrent LoadLibrary/GetProcAddress/FreeLibrary from several
 *   threads. Each thread repeatedly loads kernel32 (pinned) and version.dll
 *   (refcounted), resolves exports, calls them and frees its references. All
 *   threads must observe the same HMODULE for the same DLL, and the reference
 *   counts must balance so the module is still usable after all threads join.
 *
 * APIs: CreateThread, WaitForMultipleObjects, GetExitCodeThread, CloseHandle,
 *   LoadLibraryExW (LOAD_LIBRARY_SEARCH_SYSTEM32), LoadLibraryW, GetModuleHandleW,
 *   GetProcAddress, FreeLibrary, InterlockedIncrement, GetLastError
 *
 * Success:
 *   - NUM_THREADS threads each finish with exit code 0.
 *   - Every LoadLibrary of version.dll in every thread returns the handle that
 *     the main thread obtained first; every kernel32 handle equals
 *     GetModuleHandleW(L"kernel32.dll").
 *   - No failed call is observed (shared counter stays 0).
 *   - After joining, version.dll resolves and runs, and kernel32 still resolves.
 *
 * Source reference: none in curl (curl never calls LoadLibrary). This checks the
 *   loader-concurrency contract a multi-threaded dynamic-loading design would need.
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

#define NAME "threads_concurrent_load"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

#define NUM_THREADS 8
#define ITERATIONS 200

typedef DWORD (WINAPI *get_ver_size_fn)(LPCWSTR, LPDWORD);

static HMODULE g_ver_handle;
static HMODULE g_k32_handle;
static volatile LONG g_failures;
static const char *volatile g_first_what;
static volatile DWORD g_first_err;

static void record_failure(const char *what, DWORD err)
{
    if (InterlockedIncrement(&g_failures) == 1) {
        g_first_what = what;
        g_first_err = err;
    }
}

static DWORD WINAPI worker(LPVOID arg)
{
    int i;
    (void)arg;

    for (i = 0; i < ITERATIONS; i++) {
        HMODULE k, v;
        FARPROC p;
        get_ver_size_fn size_fn;
        DWORD sz;

        k = LoadLibraryW(L"kernel32.dll");
        if (!k) {
            record_failure("LoadLibraryW(kernel32.dll)", GetLastError());
            continue;
        }
        if (k != g_k32_handle)
            record_failure("kernel32 handle mismatch", 0);

        v = LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!v) {
            record_failure("LoadLibraryExW(version.dll)", GetLastError());
            FreeLibrary(k);
            continue;
        }
        if (v != g_ver_handle)
            record_failure("version.dll handle mismatch", 0);

        p = GetProcAddress(v, "GetFileVersionInfoSizeW");
        if (!p) {
            record_failure("GetProcAddress(GetFileVersionInfoSizeW)", GetLastError());
        } else {
            size_fn = (get_ver_size_fn)(void *)p;
            SetLastError(0);
            sz = size_fn(L"tc_no_such_file_12.dll", NULL);
            if (sz != 0 || GetLastError() == 0)
                record_failure("GetFileVersionInfoSizeW missing-file contract", GetLastError());
        }

        if (!FreeLibrary(v))
            record_failure("FreeLibrary(version.dll)", GetLastError());
        if (!FreeLibrary(k))
            record_failure("FreeLibrary(kernel32.dll)", GetLastError());
    }
    return 0;
}

#define WORKERS NUM_THREADS

int main(void)
{
    HANDLE threads[WORKERS];
    DWORD exit_code;
    FARPROC p;
    FILETIME ft;
    int i;
    DWORD waited;

    g_ver_handle = LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!g_ver_handle)
        FAILF("main LoadLibraryExW(version.dll) err=%lu", (unsigned long)GetLastError());
    g_k32_handle = GetModuleHandleW(L"kernel32.dll");
    if (!g_k32_handle)
        FAILF("main GetModuleHandleW(kernel32.dll) err=%lu", (unsigned long)GetLastError());

    for (i = 0; i < WORKERS; i++) {
        threads[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (!threads[i]) {
            while (i-- > 0) {
                WaitForSingleObject(threads[i], INFINITE);
                CloseHandle(threads[i]);
            }
            FAILF("CreateThread[%d] err=%lu", i, (unsigned long)GetLastError());
        }
    }

    waited = WaitForMultipleObjects(WORKERS, threads, TRUE, 50000);
    if (waited == WAIT_TIMEOUT)
        FAILF("worker threads timed out");
    if (waited == WAIT_FAILED)
        FAILF("WaitForMultipleObjects err=%lu", (unsigned long)GetLastError());

    for (i = 0; i < WORKERS; i++) {
        if (!GetExitCodeThread(threads[i], &exit_code))
            FAILF("GetExitCodeThread[%d] err=%lu", i, (unsigned long)GetLastError());
        if (exit_code != 0)
            FAILF("thread %d exit code %lu", i, (unsigned long)exit_code);
        CloseHandle(threads[i]);
    }

    if (g_failures != 0)
        FAILF("%ld call(s) failed or returned unexpected handles across threads; first: %s err=%lu",
              (long)g_failures, g_first_what, (unsigned long)g_first_err);

    /* Refcounts must balance: both modules remain usable. */
    p = GetProcAddress(g_ver_handle, "GetFileVersionInfoSizeW");
    if (!p)
        FAILF("version.dll unusable after threads joined err=%lu", (unsigned long)GetLastError());
    if (GetModuleHandleW(L"kernel32.dll") != g_k32_handle)
        FAILF("kernel32 handle changed after threads joined");

    GetSystemTimeAsFileTime(&ft);
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0)
        FAILF("GetSystemTimeAsFileTime returned zero");

    if (!FreeLibrary(g_ver_handle))
        FAILF("FreeLibrary(main version.dll ref) err=%lu", (unsigned long)GetLastError());

    printf("PASS " NAME "\n");
    return 0;
}
