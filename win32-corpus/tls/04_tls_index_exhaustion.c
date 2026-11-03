/*
 * Test: 04_tls_index_exhaustion
 * Area: tls
 * Purpose: Allocate as many TLS indexes as the process will give (up to a
 *          cap), write a distinct value into each, read every value back,
 *          then free all of them and confirm the slots can be re-allocated.
 *          Checks that the per-thread slot table is not aliased or corrupted
 *          when many indexes are in use.
 * APIs: TlsAlloc, TlsSetValue, TlsGetValue, TlsFree, GetLastError
 * curl relevance: curl allocates no TLS indexes itself (no TlsAlloc hits in
 *          lib/ or src/), but a process can load other libraries that do. The
 *          documented floor is TLS_MINIMUM_AVAILABLE (64) per process, so the
 *          test checks that at least that many can be allocated.
 * Success: at least TLS_MINIMUM_AVAILABLE indexes are allocated; all indexes
 *          are distinct; every stored value reads back exactly; all frees
 *          succeed; one re-allocation after freeing succeeds.
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

#define TEST_NAME "04_tls_index_exhaustion"
#define MAX_TRY 1200

static int fail_msg(const char *msg)
{
    DWORD err = GetLastError();
    printf("FAIL %s: %s (GetLastError=%lu)\n", TEST_NAME, msg, (unsigned long)err);
    return 1;
}

int main(void)
{
    DWORD *idx;
    size_t count = 0, nfreed = 0, i, j;
    int rc = 0;

    idx = (DWORD *)calloc(MAX_TRY, sizeof(DWORD));
    if(!idx) {
        printf("FAIL %s: calloc failed\n", TEST_NAME);
        return 1;
    }

    /* Allocate until the process runs out, or we hit the cap. */
    for(i = 0; i < MAX_TRY; i++) {
        DWORD v = TlsAlloc();
        if(v == TLS_OUT_OF_INDEXES)
            break;
        idx[count++] = v;
    }

    if(count < TLS_MINIMUM_AVAILABLE) {
        rc = fail_msg("fewer TLS indexes than TLS_MINIMUM_AVAILABLE were allocated");
        goto done;
    }

    /* All indexes must be distinct. */
    for(i = 0; i < count; i++) {
        for(j = i + 1; j < count; j++) {
            if(idx[i] == idx[j]) {
                rc = fail_msg("TlsAlloc returned the same index twice");
                goto done;
            }
        }
    }

    /* Store a distinct value per index, then verify every one. */
    for(i = 0; i < count; i++) {
        if(!TlsSetValue(idx[i], (void *)(uintptr_t)(0x10000 + i * 16))) {
            rc = fail_msg("TlsSetValue failed during fill");
            goto done;
        }
    }
    for(i = 0; i < count; i++) {
        uintptr_t got = (uintptr_t)TlsGetValue(idx[i]);
        if(got != (uintptr_t)(0x10000 + i * 16)) {
            rc = fail_msg("stored value in one index was corrupted by another");
            goto done;
        }
    }

    /* Free everything; each free must succeed exactly once. */
    for(i = 0; i < count; i++) {
        if(!TlsFree(idx[i])) {
            rc = fail_msg("TlsFree failed for an allocated index");
            goto done;
        }
        nfreed++;
    }

    /* Slots must be reusable after being freed. */
    {
        DWORD again = TlsAlloc();
        if(again == TLS_OUT_OF_INDEXES) {
            rc = fail_msg("TlsAlloc failed after all indexes were freed");
            goto done;
        }
        if(!TlsFree(again)) {
            rc = fail_msg("TlsFree of the re-allocated index failed");
            goto done;
        }
    }

done:
    /* Free only the indexes still live: those at or after nfreed. On success
       nfreed == count, so nothing is freed twice on any path. */
    for(i = nfreed; i < count; i++)
        TlsFree(idx[i]);
    free(idx);

    if(rc == 0)
        printf("PASS %s\n", TEST_NAME);
    return rc;
}
