/*
 * Test: 08_select_fdset
 * Purpose: select() on fd_set as curl's fallback readiness path uses it.
 *          Covers zero-timeout polls, read/write readiness on connected sockets,
 *          and the Winsock rule that all three fd_sets empty is an error.
 * APIs: select, FD_ZERO, FD_SET, FD_ISSET, socket, bind, listen, connect,
 *       accept, send, recv, closesocket, WSAGetLastError.
 * Success:
 *   - zero-timeout select on an idle listener returns 0 and FD_ISSET is false.
 *   - select on the listener after a pending connect returns 1 and FD_ISSET is true.
 *   - connected socket is writable (select returns 1 on write set).
 *   - zero-timeout read select on an idle connected socket returns 0.
 *   - after the client sends 6 bytes, read select returns 1 and recv yields 6 bytes.
 *   - select with all three fd_sets empty fails with WSAEINVAL (10022).
 * Source: lib/select.c:61-73 (Winsock select() cannot handle zero events; curl
 *         guards the empty fd_set case before calling it).
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

#define TEST_NAME "select_fdset"

static int fail_wsa(const char *what)
{
    printf("FAIL %s: %s failed, WSAGetLastError=%d GetLastError=%lu\n",
           TEST_NAME, what, WSAGetLastError(), (unsigned long)GetLastError());
    return 1;
}

static SOCKET make_listener(unsigned short *out_port)
{
    struct sockaddr_in sa;
    int len = (int)sizeof(sa);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (s == INVALID_SOCKET)
        return INVALID_SOCKET;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(s, (struct sockaddr *)&sa, (int)sizeof(sa)) == SOCKET_ERROR ||
        listen(s, 8) == SOCKET_ERROR ||
        getsockname(s, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    *out_port = ntohs(sa.sin_port);
    return s;
}

static int body(void)
{
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, conn = INVALID_SOCKET;
    unsigned short port = 0;
    struct sockaddr_in sa;
    fd_set rset, wset, empty;
    struct timeval tv;
    char buf[8];
    int rc, got = 0;
    int ret = 1;

    listener = make_listener(&port);
    if (listener == INVALID_SOCKET) {
        fail_wsa("listener setup");
        goto out;
    }

    /* Idle listener: zero-timeout poll must report nothing ready. */
    FD_ZERO(&rset);
    FD_SET(listener, &rset);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    rc = select(0, &rset, NULL, NULL, &tv);
    if (rc != 0 || FD_ISSET(listener, &rset)) {
        printf("FAIL %s: idle listener select returned %d (expected 0)\n", TEST_NAME, rc);
        goto out;
    }

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        fail_wsa("client socket");
        goto out;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (connect(client, (struct sockaddr *)&sa, (int)sizeof(sa)) == SOCKET_ERROR) {
        fail_wsa("connect");
        goto out;
    }

    /* Pending connection: listener readable. */
    FD_ZERO(&rset);
    FD_SET(listener, &rset);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    rc = select(0, &rset, NULL, NULL, &tv);
    if (rc == SOCKET_ERROR) {
        fail_wsa("select on listener with pending connection");
        goto out;
    }
    if (rc != 1 || !FD_ISSET(listener, &rset)) {
        printf("FAIL %s: pending connection select returned %d, listener ready=%d\n",
               TEST_NAME, rc, FD_ISSET(listener, &rset) ? 1 : 0);
        goto out;
    }

    conn = accept(listener, NULL, NULL);
    if (conn == INVALID_SOCKET) {
        fail_wsa("accept");
        goto out;
    }

    /* Freshly connected socket is writable. */
    FD_ZERO(&wset);
    FD_SET(conn, &wset);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    rc = select(0, NULL, &wset, NULL, &tv);
    if (rc != 1 || !FD_ISSET(conn, &wset)) {
        printf("FAIL %s: connected socket not writable (select=%d)\n", TEST_NAME, rc);
        goto out;
    }

    /* No data yet: zero-timeout read select must report nothing. */
    FD_ZERO(&rset);
    FD_SET(conn, &rset);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    rc = select(0, &rset, NULL, NULL, &tv);
    if (rc != 0 || FD_ISSET(conn, &rset)) {
        printf("FAIL %s: idle connected socket readable (select=%d)\n", TEST_NAME, rc);
        goto out;
    }

    if (send(client, "sel666", 6, 0) != 6) {
        fail_wsa("client send 6 bytes");
        goto out;
    }
    FD_ZERO(&rset);
    FD_SET(conn, &rset);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    rc = select(0, &rset, NULL, NULL, &tv);
    if (rc != 1 || !FD_ISSET(conn, &rset)) {
        printf("FAIL %s: connected socket not readable after send (select=%d)\n", TEST_NAME, rc);
        goto out;
    }
    rc = recv(conn, buf, sizeof(buf), 0);
    if (rc != 6) {
        fail_wsa("recv after select reported readable");
        goto out;
    }
    got = rc;
    if (memcmp(buf, "sel666", 6) != 0 || got != 6) {
        printf("FAIL %s: payload mismatch after select\n", TEST_NAME);
        goto out;
    }

    /* Winsock rejects a select with all three sets empty. */
    FD_ZERO(&empty);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    rc = select(0, &empty, &empty, &empty, &tv);
    if (rc != SOCKET_ERROR || WSAGetLastError() != WSAEINVAL) {
        printf("FAIL %s: select with empty fd_sets returned %d err=%d, expected SOCKET_ERROR/WSAEINVAL (10022)\n",
               TEST_NAME, rc, WSAGetLastError());
        goto out;
    }

    printf("PASS %s\n", TEST_NAME);
    ret = 0;

out:
    if (conn != INVALID_SOCKET)
        closesocket(conn);
    if (client != INVALID_SOCKET)
        closesocket(client);
    if (listener != INVALID_SOCKET)
        closesocket(listener);
    return ret;
}

int main(void)
{
    WSADATA wsa;
    int rc;

    memset(&wsa, 0, sizeof(wsa));
    rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        printf("FAIL %s: WSAStartup returned %d\n", TEST_NAME, rc);
        return 1;
    }
    rc = body();
    WSACleanup();
    fflush(stdout);
    return rc;
}
