/*
 * Test: 07_fionbio_wouldblock
 * Purpose: Nonblocking I/O semantics. A nonblocking accept or recv with nothing
 *          pending must fail with WSAEWOULDBLOCK, not with a hard error, and
 *          curl's "try again later" logic depends on that code.
 * APIs: ioctlsocket(FIONBIO), accept, recv, send, connect, select,
 *       WSAGetLastError, closesocket.
 * Success:
 *   - ioctlsocket(FIONBIO, 1) returns 0 on the listener and on the client.
 *   - accept with no pending connection returns INVALID_SOCKET with WSAEWOULDBLOCK (10035).
 *   - recv with no data returns SOCKET_ERROR with WSAEWOULDBLOCK.
 *   - after the connection is accepted, recv of the 5-byte payload returns 5 bytes.
 *   - a further recv returns WSAEWOULDBLOCK again.
 *   - ioctlsocket(FIONBIO) on a closed socket fails with WSAENOTSOCK (10038).
 * Source: lib/cf-socket.c:999 (SOCK_EAGAIN/SOCKEINPROGRESS treated as pending),
 *         lib/cf-socket.c:1684 and lib/cf-socket.c:1740 (SOCK_EAGAIN checks in
 *         the send and receive paths that this test models).
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

#define TEST_NAME "fionbio_wouldblock"

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
    SOCKET dead;
    unsigned short port = 0;
    struct sockaddr_in sa;
    fd_set set;
    struct timeval tv;
    u_long mode;
    char buf[8];
    int i, got = 0, rc, sel;
    int ret = 1;

    listener = make_listener(&port);
    if (listener == INVALID_SOCKET) {
        fail_wsa("listener setup");
        goto out;
    }

    mode = 1;
    if (ioctlsocket(listener, FIONBIO, &mode) != 0) {
        fail_wsa("ioctlsocket(listener, FIONBIO, 1)");
        goto out;
    }

    /* Nothing pending: accept must report WSAEWOULDBLOCK. */
    conn = accept(listener, NULL, NULL);
    if (conn != INVALID_SOCKET) {
        printf("FAIL %s: accept with no pending connection returned a socket\n", TEST_NAME);
        goto out;
    }
    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        printf("FAIL %s: accept error=%d, expected WSAEWOULDBLOCK (10035)\n",
               TEST_NAME, WSAGetLastError());
        goto out;
    }

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        fail_wsa("client socket");
        goto out;
    }
    mode = 1;
    if (ioctlsocket(client, FIONBIO, &mode) != 0) {
        fail_wsa("ioctlsocket(client, FIONBIO, 1)");
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    rc = connect(client, (struct sockaddr *)&sa, (int)sizeof(sa));
    if (rc == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS) {
            printf("FAIL %s: nonblocking connect error %d\n", TEST_NAME, e);
            goto out;
        }
    }

    /* Poll the listener until the handshake completes and accept succeeds. */
    for (i = 0; i < 50 && conn == INVALID_SOCKET; i++) {
        FD_ZERO(&set);
        FD_SET(listener, &set);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        sel = select(0, &set, NULL, NULL, &tv);
        if (sel == SOCKET_ERROR) {
            fail_wsa("select on listener");
            goto out;
        }
        if (sel == 0)
            continue;
        conn = accept(listener, NULL, NULL);
        if (conn == INVALID_SOCKET && WSAGetLastError() != WSAEWOULDBLOCK) {
            fail_wsa("accept after readable");
            goto out;
        }
    }
    if (conn == INVALID_SOCKET) {
        printf("FAIL %s: nonblocking accept never succeeded\n", TEST_NAME);
        goto out;
    }

    mode = 1;
    if (ioctlsocket(conn, FIONBIO, &mode) != 0) {
        fail_wsa("ioctlsocket(conn, FIONBIO, 1)");
        goto out;
    }

    /* No data yet on the accepted socket: recv must report WSAEWOULDBLOCK. */
    if (recv(conn, buf, sizeof(buf), 0) != SOCKET_ERROR || WSAGetLastError() != WSAEWOULDBLOCK) {
        printf("FAIL %s: recv with no data did not return WSAEWOULDBLOCK (err=%d)\n",
               TEST_NAME, WSAGetLastError());
        goto out;
    }

    /* Wait for the client to be writable, then send 5 bytes. */
    FD_ZERO(&set);
    FD_SET(client, &set);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (select(0, NULL, &set, NULL, &tv) != 1 || !FD_ISSET(client, &set)) {
        printf("FAIL %s: client not writable after connect\n", TEST_NAME);
        goto out;
    }
    if (send(client, "hello", 5, 0) != 5) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            fail_wsa("client send 5 bytes");
            goto out;
        }
        printf("FAIL %s: client send would block on empty socket\n", TEST_NAME);
        goto out;
    }

    FD_ZERO(&set);
    FD_SET(conn, &set);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (select(0, &set, NULL, NULL, &tv) != 1 || !FD_ISSET(conn, &set)) {
        printf("FAIL %s: accepted socket not readable after send\n", TEST_NAME);
        goto out;
    }
    while (got < 5) {
        int r = recv(conn, buf + got, 5 - got, 0);
        if (r == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                FD_ZERO(&set);
                FD_SET(conn, &set);
                tv.tv_sec = 5;
                tv.tv_usec = 0;
                if (select(0, &set, NULL, NULL, &tv) != 1) {
                    printf("FAIL %s: timed out waiting for payload\n", TEST_NAME);
                    goto out;
                }
                continue;
            }
            fail_wsa("recv payload");
            goto out;
        }
        if (r == 0) {
            printf("FAIL %s: unexpected EOF after %d bytes\n", TEST_NAME, got);
            goto out;
        }
        got += r;
    }
    if (memcmp(buf, "hello", 5) != 0) {
        printf("FAIL %s: payload mismatch\n", TEST_NAME);
        goto out;
    }

    /* Drained: recv must again report WSAEWOULDBLOCK, not EOF. */
    if (recv(conn, buf, sizeof(buf), 0) != SOCKET_ERROR || WSAGetLastError() != WSAEWOULDBLOCK) {
        printf("FAIL %s: drained recv did not return WSAEWOULDBLOCK (err=%d)\n",
               TEST_NAME, WSAGetLastError());
        goto out;
    }

    /* ioctlsocket on a closed socket must fail with WSAENOTSOCK. */
    dead = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (dead == INVALID_SOCKET) {
        fail_wsa("socket for closed-handle test");
        goto out;
    }
    closesocket(dead);
    mode = 1;
    if (ioctlsocket(dead, FIONBIO, &mode) != SOCKET_ERROR || WSAGetLastError() != WSAENOTSOCK) {
        printf("FAIL %s: ioctlsocket on closed socket error=%d, expected WSAENOTSOCK (10038)\n",
               TEST_NAME, WSAGetLastError());
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
