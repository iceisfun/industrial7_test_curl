/*
 * Test: 02_tcp_loopback_echo
 * Purpose: Baseline TCP round trip on 127.0.0.1 as curl's connect path uses it:
 *          socket, bind to an ephemeral port, listen, connect, accept,
 *          getsockname/getpeername on both ends, and exact-count send/recv.
 * APIs: socket, bind, listen, connect, accept, send, recv, getsockname,
 *       getpeername, htons, ntohs, closesocket, WSAStartup, WSACleanup,
 *       WSAGetLastError.
 * Success:
 *   - connect to the listener returns 0.
 *   - client getpeername reports 127.0.0.1 and the listener's port.
 *   - accepted socket getpeername reports the client's getsockname port,
 *     and its getsockname reports the listener's port.
 *   - a 9-byte payload sent client->server and echoed back arrives intact.
 * Source: lib/cf-socket.c:999 (socket_connect_result, the connect() outcome
 *         handling this test models) and lib/cf-socket.c:968 (SO_ERROR check).
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

#define TEST_NAME "tcp_loopback_echo"

static int fail_wsa(const char *what)
{
    printf("FAIL %s: %s failed, WSAGetLastError=%d GetLastError=%lu\n",
           TEST_NAME, what, WSAGetLastError(), (unsigned long)GetLastError());
    return 1;
}

/* Creates a blocking IPv4 listener on 127.0.0.1 with an ephemeral port. */
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

static int recv_exact(SOCKET s, char *buf, int want)
{
    int got = 0;
    while (got < want) {
        int r = recv(s, buf + got, want - got, 0);
        if (r <= 0)
            return -1;   /* 0 = unexpected EOF, SOCKET_ERROR = failure */
        got += r;
    }
    return got;
}

static int body(void)
{
    static const char msg[] = "curl-echo";  /* 9 bytes */
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, conn = INVALID_SOCKET;
    unsigned short port = 0, client_port = 0;
    struct sockaddr_in sa;
    int len;
    char buf[16];
    int rc = 1;

    listener = make_listener(&port);
    if (listener == INVALID_SOCKET) {
        fail_wsa("listener setup (socket/bind/listen/getsockname)");
        goto out;
    }
    if (port == 0) {
        printf("FAIL %s: ephemeral port is 0 after bind\n", TEST_NAME);
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
        fail_wsa("connect to 127.0.0.1 listener");
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getsockname(client, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("client getsockname");
        goto out;
    }
    client_port = ntohs(sa.sin_port);
    if (client_port == 0 || sa.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        printf("FAIL %s: client local address unexpected (port=%u)\n",
               TEST_NAME, (unsigned)client_port);
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getpeername(client, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("client getpeername");
        goto out;
    }
    if (ntohs(sa.sin_port) != port || sa.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        printf("FAIL %s: client getpeername port=%u, expected %u\n",
               TEST_NAME, (unsigned)ntohs(sa.sin_port), (unsigned)port);
        goto out;
    }

    conn = accept(listener, NULL, NULL);
    if (conn == INVALID_SOCKET) {
        fail_wsa("accept");
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getpeername(conn, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("accepted getpeername");
        goto out;
    }
    if (ntohs(sa.sin_port) != client_port) {
        printf("FAIL %s: accepted peer port=%u, client local port=%u\n",
               TEST_NAME, (unsigned)ntohs(sa.sin_port), (unsigned)client_port);
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getsockname(conn, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("accepted getsockname");
        goto out;
    }
    if (ntohs(sa.sin_port) != port) {
        printf("FAIL %s: accepted local port=%u, listener port=%u\n",
               TEST_NAME, (unsigned)ntohs(sa.sin_port), (unsigned)port);
        goto out;
    }

    if (send(client, msg, 9, 0) != 9) {
        fail_wsa("client send 9 bytes");
        goto out;
    }
    if (recv_exact(conn, buf, 9) != 9) {
        fail_wsa("server recv 9 bytes");
        goto out;
    }
    if (memcmp(buf, msg, 9) != 0) {
        printf("FAIL %s: server received corrupted payload\n", TEST_NAME);
        goto out;
    }
    if (send(conn, buf, 9, 0) != 9) {
        fail_wsa("server echo send 9 bytes");
        goto out;
    }
    memset(buf, 0, sizeof(buf));
    if (recv_exact(client, buf, 9) != 9) {
        fail_wsa("client recv echo 9 bytes");
        goto out;
    }
    if (memcmp(buf, msg, 9) != 0) {
        printf("FAIL %s: echoed payload mismatch\n", TEST_NAME);
        goto out;
    }

    printf("PASS %s\n", TEST_NAME);
    rc = 0;

out:
    if (conn != INVALID_SOCKET)
        closesocket(conn);
    if (client != INVALID_SOCKET)
        closesocket(client);
    if (listener != INVALID_SOCKET)
        closesocket(listener);
    return rc;
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
