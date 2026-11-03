/*
 * Test: 01_startup_cleanup
 * Purpose: WSAStartup/WSACleanup lifecycle as curl's global init performs it.
 * APIs: WSAStartup, WSACleanup, WSAGetLastError, MAKEWORD, LOBYTE, HIBYTE.
 * Success:
 *   - WSAStartup(MAKEWORD(2,2), NULL) before any startup fails with WSAEFAULT (10014).
 *   - WSAStartup(MAKEWORD(2,2), &wsa) returns 0 and wVersion is 2.2.
 *   - WSACleanup returns 0.
 *   - A second WSACleanup returns SOCKET_ERROR with WSANOTINITIALISED (10093).
 *   - WSAStartup can be issued again after cleanup and cleaned up again.
 * Source: lib/easy.c:167 (WSAStartup(MAKEWORD(2, 2), &wsa)),
 *         lib/easy.c:221 and lib/easy.c:311 (WSACleanup).
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
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "startup_cleanup"

static int fail_wsa(const char *what)
{
    printf("FAIL %s: %s failed, WSAGetLastError=%d GetLastError=%lu\n",
           TEST_NAME, what, WSAGetLastError(), (unsigned long)GetLastError());
    return 1;
}

static int run(void)
{
    WSADATA wsa;
    int rc;

    /* Null WSADATA pointer must be rejected with WSAEFAULT before any startup. */
    rc = WSAStartup(MAKEWORD(2, 2), NULL);
    if (rc != WSAEFAULT) {
        printf("FAIL %s: WSAStartup(NULL) returned %d, expected WSAEFAULT (10014)\n",
               TEST_NAME, rc);
        if (rc == 0)
            WSACleanup();
        return 1;
    }

    memset(&wsa, 0, sizeof(wsa));
    rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        printf("FAIL %s: WSAStartup returned %d\n", TEST_NAME, rc);
        return 1;
    }
    if (LOBYTE(wsa.wVersion) != 2 || HIBYTE(wsa.wVersion) != 2) {
        printf("FAIL %s: wVersion is %u.%u, expected 2.2\n", TEST_NAME,
               (unsigned)LOBYTE(wsa.wVersion), (unsigned)HIBYTE(wsa.wVersion));
        WSACleanup();
        return 1;
    }

    if (WSACleanup() != 0)
        return fail_wsa("first WSACleanup");

    rc = WSACleanup();
    if (rc != SOCKET_ERROR) {
        printf("FAIL %s: second WSACleanup returned %d, expected SOCKET_ERROR\n",
               TEST_NAME, rc);
        return 1;
    }
    if (WSAGetLastError() != WSANOTINITIALISED) {
        printf("FAIL %s: second WSACleanup error %d, expected WSANOTINITIALISED (10093)\n",
               TEST_NAME, WSAGetLastError());
        return 1;
    }

    memset(&wsa, 0, sizeof(wsa));
    rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        printf("FAIL %s: re-init WSAStartup returned %d\n", TEST_NAME, rc);
        return 1;
    }
    if (WSACleanup() != 0)
        return fail_wsa("re-init WSACleanup");

    printf("PASS %s\n", TEST_NAME);
    return 0;
}

int main(void)
{
    int rc = run();
    fflush(stdout);
    return rc;
}
