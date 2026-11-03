/*
 * Test: 03_tls_invalid_index_errors
 * Area: tls
 * Purpose: Error paths of the TLS API. Using TLS_OUT_OF_INDEXES, or an index
 *          that was already freed, must fail (not crash, not silently
 *          succeed). A second TlsFree of the same index must fail.
 * APIs: TlsAlloc, TlsFree, TlsGetValue, TlsSetValue, GetLastError,
 *       SetLastError
 * curl relevance: curl_global_cleanup() (lib/easy.c:289) is the process
 *          teardown entry point, but curl allocates no TLS indexes (no TlsAlloc
 *          hits in lib/ or src/). Code that frees a TLS index must be able to
 *          detect that the index is already gone; this checks that the API
 *          reports it.
 * Success: TlsSetValue/TlsFree on TLS_OUT_OF_INDEXES return FALSE; TlsGetValue
 *          on TLS_OUT_OF_INDEXES returns NULL with a non-zero GetLastError;
 *          after TlsFree(idx), a second TlsFree of idx returns FALSE.
 *          (TlsSetValue on a freed index is undocumented and not asserted.)
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

#define TEST_NAME "03_tls_invalid_index_errors"

static int fail_msg(const char *msg)
{
    DWORD err = GetLastError();
    printf("FAIL %s: %s (GetLastError=%lu)\n", TEST_NAME, msg, (unsigned long)err);
    return 1;
}

int main(void)
{
    DWORD idx;
    void *v;

    /* 1. Operations on TLS_OUT_OF_INDEXES must fail. */
    SetLastError(ERROR_SUCCESS);
    if(TlsSetValue(TLS_OUT_OF_INDEXES, (void *)0x1))
        return fail_msg("TlsSetValue(TLS_OUT_OF_INDEXES) unexpectedly succeeded");

    SetLastError(ERROR_SUCCESS);
    v = TlsGetValue(TLS_OUT_OF_INDEXES);
    if(v != NULL)
        return fail_msg("TlsGetValue(TLS_OUT_OF_INDEXES) returned non-NULL");
    if(GetLastError() == ERROR_SUCCESS)
        return fail_msg("TlsGetValue(TLS_OUT_OF_INDEXES) did not set a last error");

    if(TlsFree(TLS_OUT_OF_INDEXES))
        return fail_msg("TlsFree(TLS_OUT_OF_INDEXES) unexpectedly succeeded");

    /* 2. Free a valid index, then the same index must no longer be usable. */
    idx = TlsAlloc();
    if(idx == TLS_OUT_OF_INDEXES)
        return fail_msg("TlsAlloc failed");
    if(!TlsSetValue(idx, (void *)0x2))
        return fail_msg("TlsSetValue on a valid index failed");
    if(!TlsFree(idx))
        return fail_msg("first TlsFree of a valid index failed");

    if(TlsFree(idx))
        return fail_msg("second TlsFree of the same index succeeded");
    /* Note: TlsSetValue on a freed index is not specified by the docs, so it
       is deliberately not asserted here. */

    printf("PASS %s\n", TEST_NAME);
    return 0;
}
