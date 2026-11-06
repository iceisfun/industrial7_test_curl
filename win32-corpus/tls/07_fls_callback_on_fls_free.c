/*
 * Test: 07_fls_callback_on_fls_free
 * Area: tls
 * Purpose: FlsFree releases an FLS index. For a slot allocated with a
 *          destructor, FlsFree runs the destructor on the calling thread for
 *          the value it holds. A slot allocated with no destructor must free
 *          silently. Freeing an already-freed index must fail.
 * APIs: FlsAlloc, FlsSetValue, FlsGetValue, FlsFree, GetLastError
 * curl relevance: curl_global_cleanup() (lib/easy.c:289) is the process
 *          teardown entry point, but curl uses no FLS (no FlsAlloc hits in lib/
 *          or src/). The test covers FlsFree's destructor and double-free
 *          contract for code that does use FLS.
 * Success: FlsFree on the destructor slot returns TRUE and the destructor ran
 *          exactly once with the stored value; a second FlsFree on that index
 *          returns FALSE; a slot with no destructor frees with TRUE and no
 *          callback is involved.
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

#define TEST_NAME "07_fls_callback_on_fls_free"

static volatile LONG g_calls = 0;
static volatile uintptr_t g_last_value = 0;

static void WINAPI fls_dtor(void *value)
{
    g_last_value = (uintptr_t)value;
    InterlockedIncrement(&g_calls);
}

static int fail_msg(const char *msg)
{
    DWORD err = GetLastError();
    printf("FAIL %s: %s (GetLastError=%lu)\n", TEST_NAME, msg, (unsigned long)err);
    return 1;
}

int main(void)
{
    DWORD with_dtor, no_dtor;
    void *v;

    with_dtor = FlsAlloc(fls_dtor);
    if(with_dtor == FLS_OUT_OF_INDEXES)
        return fail_msg("FlsAlloc(callback) failed");

    no_dtor = FlsAlloc(NULL);
    if(no_dtor == FLS_OUT_OF_INDEXES)
        return fail_msg("FlsAlloc(NULL) failed");

    if(!FlsSetValue(with_dtor, (void *)(uintptr_t)0x7777))
        return fail_msg("FlsSetValue(with_dtor) failed");
    if(!FlsSetValue(no_dtor, (void *)(uintptr_t)0x8888))
        return fail_msg("FlsSetValue(no_dtor) failed");

    v = FlsGetValue(with_dtor);
    if((uintptr_t)v != 0x7777)
        return fail_msg("FlsGetValue(with_dtor) did not return stored value");

    /* Destructor slot: FlsFree must invoke the callback once with 0x7777. */
    if(g_calls != 0)
        return fail_msg("callback ran before FlsFree");
    if(!FlsFree(with_dtor))
        return fail_msg("FlsFree(with_dtor) failed");
    if(g_calls != 1)
        return fail_msg("callback did not run exactly once on FlsFree");
    if(g_last_value != 0x7777)
        return fail_msg("callback did not receive the stored value");

    /* Slot without a destructor: free must succeed and call nothing. */
    if(!FlsFree(no_dtor))
        return fail_msg("FlsFree(no_dtor) failed");
    if(g_calls != 1)
        return fail_msg("a callback ran for a slot that had none");

    /* Freeing an already-freed index must fail. */
    if(FlsFree(with_dtor))
        return fail_msg("second FlsFree of the same index succeeded");
    if(g_calls != 1)
        return fail_msg("second FlsFree ran the destructor again");

    printf("PASS %s\n", TEST_NAME);
    return 0;
}
