/*
 * Test: 03_nonblocking_connect_success
 * Purpose: Nonblocking connect to a loopback listener, the way curl's
 *          connection filter drives it: FIONBIO on, connect, accept
 *          WSAEWOULDBLOCK/WSAEINPROGRESS as "in progress", wait for
 *          writability, check SO_ERROR == 0, then restore blocking mode.
 * APIs: socket, ioctlsocket(FIONBIO), connect, select, getsockopt(SO_ERROR),
 *       getpeername, accept, send, recv, WSAGetLastError.
 * Success:
 *   - ioctlsocket(FIONBIO, 1) returns 0.
 *   - connect returns 0 or SOCKET_ERROR with WSAEWOULDBLOCK or WSAEINPROGRESS
 *     (any other error is a failure).
 *   - select reports the socket writable within 5 seconds.
 *   - getsockopt(SO_ERROR) returns 0.
 *   - a second connect on the connected socket fails with WSAEISCONN (10056).
 *   - ioctlsocket(FIONBIO, 0) restores blocking mode and a 4-byte send/recv works.
 * Source: lib/cf-socket.c:999 (EINPROGRESS/EAGAIN treated as connect pending),
 *         lib/cf-socket.c:968 (getsockopt SO_ERROR after connect completes),
 *         lib/connect.c:385 (wait for connect completion via poll).
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

#define TEST_NAME "nonblocking_connect_success"

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
    fd_set wset, eset, rset;
    struct timeval tv;
    u_long mode;
    int err = 0, errlen = (int)sizeof(err);
    int rc, sel, len;
    int in_progress = 0;
    char buf[8];
    int ret = 1;

    listener = make_listener(&port);
    if (listener == INVALID_SOCKET) {
        fail_wsa("listener setup");
        goto out;
    }

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        fail_wsa("client socket");
        goto out;
    }

    mode = 1;
    if (ioctlsocket(client, FIONBIO, &mode) != 0) {
        fail_wsa("ioctlsocket(FIONBIO, 1)");
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
            printf("FAIL %s: nonblocking connect error %d, expected WSAEWOULDBLOCK (10035) or WSAEINPROGRESS (10036)\n",
                   TEST_NAME, e);
            goto out;
        }
        in_progress = 1;
    }

    FD_ZERO(&wset);
    FD_ZERO(&eset);
    FD_SET(client, &wset);
    FD_SET(client, &eset);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    sel = select(0, NULL, &wset, &eset, &tv);   /* first arg ignored by Winsock */
    if (sel == SOCKET_ERROR) {
        fail_wsa("select on connecting socket");
        goto out;
    }
    if (sel == 0) {
        printf("FAIL %s: connect did not complete within 5 seconds (in_progress=%d)\n",
               TEST_NAME, in_progress);
        goto out;
    }
    if (!FD_ISSET(client, &wset)) {
        printf("FAIL %s: connecting socket not reported writable\n", TEST_NAME);
        goto out;
    }

    if (getsockopt(client, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen) == SOCKET_ERROR) {
        fail_wsa("getsockopt(SO_ERROR)");
        goto out;
    }
    if (err != 0) {
        printf("FAIL %s: SO_ERROR=%d after connect, expected 0\n", TEST_NAME, err);
        goto out;
    }

    /* Connect on an already connected socket must report WSAEISCONN. */
    rc = connect(client, (struct sockaddr *)&sa, (int)sizeof(sa));
    if (rc != SOCKET_ERROR || WSAGetLastError() != WSAEISCONN) {
        printf("FAIL %s: second connect returned %d err=%d, expected WSAEISCONN (10056)\n",
               TEST_NAME, rc, WSAGetLastError());
        goto out;
    }

    FD_ZERO(&rset);
    FD_SET(listener, &rset);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (select(0, &rset, NULL, NULL, &tv) != 1 || !FD_ISSET(listener, &rset)) {
        printf("FAIL %s: listener not readable with pending connection\n", TEST_NAME);
        goto out;
    }
    conn = accept(listener, NULL, NULL);
    if (conn == INVALID_SOCKET) {
        fail_wsa("accept");
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getpeername(client, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("getpeername after nonblocking connect");
        goto out;
    }
    if (ntohs(sa.sin_port) != port) {
        printf("FAIL %s: getpeername port=%u, expected %u\n", TEST_NAME,
               (unsigned)ntohs(sa.sin_port), (unsigned)port);
        goto out;
    }

    mode = 0;
    if (ioctlsocket(client, FIONBIO, &mode) != 0) {
        fail_wsa("ioctlsocket(FIONBIO, 0)");
        goto out;
    }
    if (send(client, "ping", 4, 0) != 4) {
        fail_wsa("send after restoring blocking mode");
        goto out;
    }
    memset(buf, 0, sizeof(buf));
    {
        int got = 0;
        while (got < 4) {
            int r = recv(conn, buf + got, 4 - got, 0);
            if (r <= 0) {
                fail_wsa("server recv");
                goto out;
            }
            got += r;
        }
    }
    if (memcmp(buf, "ping", 4) != 0) {
        printf("FAIL %s: payload mismatch after connect\n", TEST_NAME);
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
