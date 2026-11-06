/*
 * Test: 01_tlsalloc_roundtrip
 * Area: tls
 * Purpose: Basic TLS slot lifecycle on the main thread. TlsAlloc returns a
 *          usable index, a fresh slot reads back NULL with no error, stored
 *          pointer values round-trip exactly, and TlsFree succeeds.
 * APIs: TlsAlloc, TlsGetValue, TlsSetValue, TlsFree, GetLastError
 * curl relevance: curl does not call TlsAlloc itself (no hits in lib/ or src/),
 *          but the TLS primitive is what the per-thread state of linked
 *          components (TLS backends, runtime helpers) sits on. This is the
 *          minimal contract those components rely on.
 * Success: index != TLS_OUT_OF_INDEXES; initial value is NULL with
 *          GetLastError()==0; each stored pointer reads back identical;
 *          NULL can be stored and read back with GetLastError()==0; TlsFree
 *          returns TRUE.
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

#define TEST_NAME "01_tlsalloc_roundtrip"

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
    int marker = 0x5a5a;
    DWORD_PTR sentinel = (DWORD_PTR)0xDEADBEEF12345678ull;

    idx = TlsAlloc();
    if(idx == TLS_OUT_OF_INDEXES)
        return fail_msg("TlsAlloc returned TLS_OUT_OF_INDEXES");

    /* A freshly allocated slot must read as NULL in the allocating thread,
       and a NULL result is only a real NULL when GetLastError is 0. */
    SetLastError(ERROR_SUCCESS);
    v = TlsGetValue(idx);
    if(v != NULL)
        return fail_msg("fresh TLS slot is not NULL");
    if(GetLastError() != ERROR_SUCCESS)
        return fail_msg("TlsGetValue on fresh slot set a non-zero last error");

    /* Store a pointer and read it back unchanged. */
    if(!TlsSetValue(idx, &marker))
        return fail_msg("TlsSetValue(&marker) failed");
    v = TlsGetValue(idx);
    if(v != (void *)&marker)
        return fail_msg("TlsGetValue did not return the pointer just stored");
    if(*(int *)v != 0x5a5a)
        return fail_msg("pointed-to data changed through TLS round-trip");

    /* Store an arbitrary integer-valued pointer, wider than 32 bits on x64. */
    if(!TlsSetValue(idx, (void *)sentinel))
        return fail_msg("TlsSetValue(sentinel) failed");
    if((DWORD_PTR)TlsGetValue(idx) != sentinel)
        return fail_msg("64-bit sentinel value did not round-trip");

    /* Storing NULL must succeed and read back as NULL with no error. */
    if(!TlsSetValue(idx, NULL))
        return fail_msg("TlsSetValue(NULL) failed");
    SetLastError(ERROR_SUCCESS);
    if(TlsGetValue(idx) != NULL)
        return fail_msg("value not NULL after storing NULL");
    if(GetLastError() != ERROR_SUCCESS)
        return fail_msg("NULL read after store set a non-zero last error");

    if(!TlsFree(idx))
        return fail_msg("TlsFree of a valid index failed");

    printf("PASS %s\n", TEST_NAME);
    return 0;
}
