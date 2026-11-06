/*
 * Test: 10_c11_thread_local_and_gnu_thread
 * Area: tls
 * Purpose: The C11 keyword _Thread_local and the GCC/Clang spelling __thread
 *          both give per-thread storage with a constant initializer. Each
 *          spelling is checked separately, including a function-scope static
 *          with _Thread_local, a struct, and a pointer. Values must be
 *          isolated between the main thread and a worker.
 * APIs: _Thread_local (C11), __thread (GCC extension), CreateThread,
 *       WaitForSingleObject, GetExitCodeThread, CloseHandle
 * curl relevance: none found. curl uses neither _Thread_local nor __thread
 *          (no hits in lib/ or src/). The test checks that the mingw toolchain
 *          emits real per-thread storage for both spellings.
 * Success: each thread's first read of each variable equals its initializer;
 *          writes in the worker do not appear in main; the function-scope
 *          _Thread_local counter increments independently per thread.
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

#define TEST_NAME "10_c11_thread_local_and_gnu_thread"

static _Thread_local int c11_value = 5;
static __thread int gnu_value = 9;

struct tl_state {
    int a;
    long b;
};
static _Thread_local struct tl_state state = { 1, 2L };
static _Thread_local void *ptr_slot = NULL;

static int bump_static_counter(void)
{
    static _Thread_local int count = 0;
    return ++count;
}

typedef struct {
    int c11_first;
    int gnu_first;
    int state_a_first;
    int ptr_first_null;
    int bump_first;
    int bump_second;
} worker_t;

static DWORD WINAPI worker_main(LPVOID arg)
{
    worker_t *w = (worker_t *)arg;
    static int dummy_target = 0;

    w->c11_first = c11_value;
    w->gnu_first = gnu_value;
    w->state_a_first = state.a;
    w->ptr_first_null = (ptr_slot == NULL);
    w->bump_first = bump_static_counter();
    w->bump_second = bump_static_counter();

    c11_value = 50;
    gnu_value = 90;
    state.a = 10;
    ptr_slot = &dummy_target;
    return 0;
}

int main(void)
{
    HANDLE th;
    DWORD code = 99;
    worker_t w;
    int main_bump;

    /* Main thread: change its copies, then the worker must still start fresh. */
    c11_value = 6;
    gnu_value = 8;
    state.a = 3;
    ptr_slot = (void *)&w;
    main_bump = bump_static_counter();

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

    if(w.c11_first != 5) {
        printf("FAIL %s: _Thread_local started at %d in worker, expected 5\n",
               TEST_NAME, w.c11_first);
        return 1;
    }
    if(w.gnu_first != 9) {
        printf("FAIL %s: __thread started at %d in worker, expected 9\n",
               TEST_NAME, w.gnu_first);
        return 1;
    }
    if(w.state_a_first != 1) {
        printf("FAIL %s: struct _Thread_local started at %d, expected 1\n",
               TEST_NAME, w.state_a_first);
        return 1;
    }
    if(!w.ptr_first_null) {
        printf("FAIL %s: pointer _Thread_local was not NULL in new thread\n",
               TEST_NAME);
        return 1;
    }
    if(w.bump_first != 1 || w.bump_second != 2) {
        printf("FAIL %s: function-scope _Thread_local counter was %d,%d; expected 1,2\n",
               TEST_NAME, w.bump_first, w.bump_second);
        return 1;
    }

    /* Main's copies must be exactly what main wrote. */
    if(c11_value != 6 || gnu_value != 8 || state.a != 3) {
        printf("FAIL %s: worker writes leaked into main (c11=%d gnu=%d a=%d)\n",
               TEST_NAME, c11_value, gnu_value, state.a);
        return 1;
    }
    if(ptr_slot != (void *)&w) {
        printf("FAIL %s: main pointer slot was overwritten\n", TEST_NAME);
        return 1;
    }
    if(main_bump != 1 || bump_static_counter() != 2) {
        printf("FAIL %s: main function-scope _Thread_local counter wrong\n",
               TEST_NAME);
        return 1;
    }

    printf("PASS %s\n", TEST_NAME);
    return 0;
}
