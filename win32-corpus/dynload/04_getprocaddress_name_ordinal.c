/*
 * Test: 04_getprocaddress_name_ordinal
 *
 * Purpose: GetProcAddress resolves a ws2_32 export both by name and by ordinal
 *   (MAKEINTRESOURCE), and both resolve to the same code address. The resolved
 *   WSAStartup/WSACleanup pointers are then called to prove they are live
 *   functions. GetProcAddress name matching is case-sensitive.
 *
 * APIs: LoadLibraryW, GetProcAddress (name and ordinal), FreeLibrary,
 *   WSAStartup, WSACleanup (called through resolved pointers)
 *
 * Success:
 *   - GetProcAddress(ws2, "WSAStartup") != NULL.
 *   - GetProcAddress(ws2, MAKEINTRESOURCEA(115)) == the name-resolved pointer
 *     (ordinal 115 is WSAStartup in ws2_32.dll).
 *   - GetProcAddress(ws2, MAKEINTRESOURCEA(116)) == the "WSACleanup" pointer.
 *   - Calling the WSAStartup pointer with 0x0202 returns 0, and the WSACleanup
 *     pointer returns 0.
 *   - GetProcAddress(ws2, "wsastartup") == NULL with ERROR_PROC_NOT_FOUND (127).
 *
 * Source reference: none direct; curl links Winsock statically, so this covers
 *   the dynamic ordinal path that a loader-based Winsock init would use.
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
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#define NAME "getprocaddress_name_ordinal"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

typedef int (WINAPI *wsastartup_fn)(WORD, LPWSADATA);
typedef int (WINAPI *wsacleanup_fn)(void);

int main(void)
{
    HMODULE ws2;
    FARPROC by_name_start, by_ord_start, by_name_clean, by_ord_clean, bad;
    WSADATA wsa;
    int rc;

    ws2 = LoadLibraryW(L"ws2_32.dll");
    if (!ws2)
        FAILF("LoadLibraryW(ws2_32.dll) err=%lu", (unsigned long)GetLastError());

    by_name_start = GetProcAddress(ws2, "WSAStartup");
    if (!by_name_start)
        FAILF("GetProcAddress(WSAStartup) err=%lu", (unsigned long)GetLastError());

    by_ord_start = GetProcAddress(ws2, MAKEINTRESOURCEA(115));
    if (!by_ord_start)
        FAILF("GetProcAddress(ordinal 115) err=%lu", (unsigned long)GetLastError());
    if (by_ord_start != by_name_start)
        FAILF("ordinal 115 (%p) != WSAStartup by name (%p)",
              (void *)by_ord_start, (void *)by_name_start);

    by_name_clean = GetProcAddress(ws2, "WSACleanup");
    by_ord_clean = GetProcAddress(ws2, MAKEINTRESOURCEA(116));
    if (!by_name_clean || !by_ord_clean)
        FAILF("GetProcAddress WSACleanup name/ordinal err=%lu", (unsigned long)GetLastError());
    if (by_ord_clean != by_name_clean)
        FAILF("ordinal 116 (%p) != WSACleanup by name (%p)",
              (void *)by_ord_clean, (void *)by_name_clean);

    /* Case-sensitive name lookup must not match. */
    SetLastError(0);
    bad = GetProcAddress(ws2, "wsastartup");
    if (bad != NULL)
        FAILF("lower-case 'wsastartup' resolved; GetProcAddress should be case-sensitive");
    if (GetLastError() != ERROR_PROC_NOT_FOUND)
        FAILF("lower-case lookup: expected ERROR_PROC_NOT_FOUND(127) got %lu",
              (unsigned long)GetLastError());

    /* Call through the ordinal-resolved pointers. */
    rc = ((wsastartup_fn)(void *)by_ord_start)(MAKEWORD(2, 2), &wsa);
    if (rc != 0)
        FAILF("WSAStartup via ordinal returned %d (WSAGetLastError=%d)", rc, WSAGetLastError());

    rc = ((wsacleanup_fn)(void *)by_ord_clean)();
    if (rc != 0)
        FAILF("WSACleanup via ordinal returned %d (WSAGetLastError=%d)", rc, WSAGetLastError());

    if (!FreeLibrary(ws2))
        FAILF("FreeLibrary(ws2_32) err=%lu", (unsigned long)GetLastError());

    printf("PASS " NAME "\n");
    return 0;
}
