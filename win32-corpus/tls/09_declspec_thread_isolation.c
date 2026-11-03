/*
 * Test: 09_declspec_thread_isolation
 * Area: tls
 * Purpose: __declspec(thread) variables (MSVC spelling) are per-thread copies.
 *          Each new thread gets a fresh copy initialised from the static
 *          initializer, not the creator's current value, and writes by one
 *          thread are invisible to others. On a toolchain that does not
 *          implement the attribute the test SKIPs (see the guard below).
 * APIs: __declspec(thread) (compiler/loader TLS), CreateThread,
 *       WaitForSingleObject, GetExitCodeThread, CloseHandle
 * curl relevance: none. curl does not use __declspec(thread) (no hits in lib/
 *          or src/). The C11 and GNU spellings are covered by test 10.
 * Success: a worker's first read of the variable equals the static initializer
 *          (42) even though main had changed it to 7; the worker's writes do
 *          not appear in main; main still reads 7 after the worker exits.
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

#define TEST_NAME "09_declspec_thread_isolation"

/* GCC (mingw-w64 gcc included, in any dialect, -fms-extensions does not
   change it) does not implement __declspec(thread): it warns "'thread'
   attribute directive ignored [-Wattributes]" and the variables become
   ordinary shared globals. That is a missing toolchain feature, so the test
   is compiled only where the attribute is implemented and otherwise reports
   SKIP. The warning is not suppressed. Clang is not in this toolchain, so its
   behaviour is not checked here and it takes the non-GCC path. */
#if defined(__GNUC__) && !defined(__clang__)
#define TEST_HAS_DECLSPEC_THREAD 0
#else
#define TEST_HAS_DECLSPEC_THREAD 1
#endif

#if TEST_HAS_DECLSPEC_THREAD

static __declspec(thread) int tls_counter = 42;
static __declspec(thread) unsigned int tls_flags = 0xF0u;

typedef struct {
    int first_counter;
    unsigned int first_flags;
    int final_counter;
} worker_t;

static DWORD WINAPI worker_main(LPVOID arg)
{
    worker_t *w = (worker_t *)arg;
    w->first_counter = tls_counter;
    w->first_flags = tls_flags;

    tls_counter = 100;
    tls_flags = 0x0Fu;
    w->final_counter = tls_counter;
    return 0;
}

int main(void)
{
    HANDLE th;
    DWORD code = 99;
    worker_t w;

    w.first_counter = -1;
    w.first_flags = 0;
    w.final_counter = -1;

    /* Change the main thread's copy away from its initializer first. */
    tls_counter = 7;
    tls_flags = 0x33u;

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
    CloseHandle(th);

    if(code != 0) {
        printf("FAIL %s: worker exit code %lu\n", TEST_NAME, (unsigned long)code);
        return 1;
    }
    if(w.first_counter != 42) {
        printf("FAIL %s: worker saw counter=%d on entry, expected initializer 42 "
               "(variable is not thread-local)\n", TEST_NAME, w.first_counter);
        return 1;
    }
    if(w.first_flags != 0xF0u) {
        printf("FAIL %s: worker saw flags=0x%x on entry, expected 0xf0\n",
               TEST_NAME, w.first_flags);
        return 1;
    }
    if(w.final_counter != 100) {
        printf("FAIL %s: worker lost its own write (counter=%d)\n", TEST_NAME,
               w.final_counter);
        return 1;
    }
    if(tls_counter != 7) {
        printf("FAIL %s: worker write leaked into main (counter=%d)\n", TEST_NAME,
               tls_counter);
        return 1;
    }
    if(tls_flags != 0x33u) {
        printf("FAIL %s: worker write leaked into main flags (0x%x)\n", TEST_NAME,
               tls_flags);
        return 1;
    }

    printf("PASS %s\n", TEST_NAME);
    return 0;
}

#else

int main(void)
{
    printf("SKIP %s: toolchain does not implement __declspec(thread) "
           "(GCC drops the attribute)\n", TEST_NAME);
    return 77;
}

#endif
