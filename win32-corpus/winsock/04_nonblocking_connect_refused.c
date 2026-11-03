/*
 * Test: 04_nonblocking_connect_refused
 * Purpose: Nonblocking connect to a loopback port with no listener. curl must
 *          see the refusal through SO_ERROR after the socket becomes ready,
 *          not as a success. This is the failure path that curl turns into
 *          CURLE_COULDNT_CONNECT.
 * APIs: socket, ioctlsocket(FIONBIO), connect, select (write + except sets),
 *       getsockopt(SO_ERROR), WSAGetLastError.
 * Success:
 *   - A port is obtained by binding and then closing a listener, so nothing listens.
 *   - connect either fails immediately with WSAECONNREFUSED (10061), or returns
 *     WSAEWOULDBLOCK / WSAEINPROGRESS.
 *   - In the latter case select reports the socket writable or in the
 *     exception set within 5 seconds.
 *   - getsockopt(SO_ERROR) returns WSAECONNREFUSED (10061).
 * Source: lib/cf-socket.c:999 (in-progress is not an error),
 *         lib/cf-socket.c:968 (SO_ERROR retrieved to find the real connect result),
 *         lib/connect.c:385 (poll until connect completes).
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

#define TEST_NAME "nonblocking_connect_refused"

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
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET;
    unsigned short port = 0;
    struct sockaddr_in sa;
    fd_set wset, eset;
    struct timeval tv;
    u_long mode;
    int err = 0, errlen = (int)sizeof(err);
    int rc, sel;
    int ret = 1;

    /* Obtain a loopback port that nothing listens on. */
    listener = make_listener(&port);
    if (listener == INVALID_SOCKET) {
        fail_wsa("listener setup for closed port");
        goto out;
    }
    closesocket(listener);
    listener = INVALID_SOCKET;

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
        if (e == WSAECONNREFUSED) {
            /* Refusal reported synchronously; that is a valid outcome. */
            printf("PASS %s\n", TEST_NAME);
            ret = 0;
            goto out;
        }
        if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS) {
            printf("FAIL %s: connect error %d, expected WSAECONNREFUSED, WSAEWOULDBLOCK or WSAEINPROGRESS\n",
                   TEST_NAME, e);
            goto out;
        }
    }
    else {
        printf("FAIL %s: nonblocking connect to closed port returned success\n", TEST_NAME);
        goto out;
    }

    FD_ZERO(&wset);
    FD_ZERO(&eset);
    FD_SET(client, &wset);
    FD_SET(client, &eset);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    sel = select(0, NULL, &wset, &eset, &tv);
    if (sel == SOCKET_ERROR) {
        fail_wsa("select on refused connect");
        goto out;
    }
    if (sel == 0) {
        printf("FAIL %s: refused connect not reported ready within 5 seconds\n", TEST_NAME);
        goto out;
    }

    if (getsockopt(client, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen) == SOCKET_ERROR) {
        fail_wsa("getsockopt(SO_ERROR)");
        goto out;
    }
    if (err != WSAECONNREFUSED) {
        printf("FAIL %s: SO_ERROR=%d, expected WSAECONNREFUSED (10061)\n", TEST_NAME, err);
        goto out;
    }

    printf("PASS %s\n", TEST_NAME);
    ret = 0;

out:
    if (listener != INVALID_SOCKET)
        closesocket(listener);
    if (client != INVALID_SOCKET)
        closesocket(client);
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
