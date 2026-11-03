/*
 * Test: 10_shutdown_closesocket
 * Purpose: Half-close and teardown semantics. curl shuts sockets down before
 *          closing them and relies on the peer seeing EOF, on the other
 *          direction still working after SD_SEND, and on closed handles failing.
 * APIs: shutdown (SD_SEND, SD_BOTH), send, recv, closesocket, socket, connect,
 *       accept, WSAGetLastError.
 * Success:
 *   - shutdown(client, SD_SEND) returns 0.
 *   - server recv after the 4-byte payload returns exactly 4 bytes, then 0 (EOF).
 *   - server->client data still flows after the client's SD_SEND (3 bytes).
 *   - client send after SD_SEND fails with WSAESHUTDOWN (10058).
 *   - shutdown on an unconnected socket fails with WSAENOTCONN (10057).
 *   - closesocket returns 0 for live sockets; send on the closed handle fails
 *     with WSAENOTSOCK (10038).
 * Source: lib/cf-socket.c:1100 (cf_socket_shutdown, the teardown entry point
 *         that curl runs before closing), lib/cf-socket.c:545 (the
 *         closesocket call on the socket). The test drives Winsock directly
 *         and does not call into curl; shutdown semantics come from the
 *         Winsock shutdown() contract.
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

#define TEST_NAME "shutdown_closesocket"

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
    SOCKET unconnected = INVALID_SOCKET;
    unsigned short port = 0;
    struct sockaddr_in sa;
    char buf[8];
    int got, r;
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
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (connect(client, (struct sockaddr *)&sa, (int)sizeof(sa)) == SOCKET_ERROR) {
        fail_wsa("connect");
        goto out;
    }
    conn = accept(listener, NULL, NULL);
    if (conn == INVALID_SOCKET) {
        fail_wsa("accept");
        goto out;
    }

    if (send(client, "four", 4, 0) != 4) {
        fail_wsa("client send 4 bytes");
        goto out;
    }
    if (shutdown(client, SD_SEND) != 0) {
        fail_wsa("shutdown(client, SD_SEND)");
        goto out;
    }

    got = 0;
    while (got < 4) {
        r = recv(conn, buf + got, 4 - got, 0);
        if (r <= 0) {
            fail_wsa("server recv of pre-shutdown payload");
            goto out;
        }
        got += r;
    }
    if (memcmp(buf, "four", 4) != 0) {
        printf("FAIL %s: payload mismatch before EOF\n", TEST_NAME);
        goto out;
    }

    r = recv(conn, buf, sizeof(buf), 0);
    if (r != 0) {
        printf("FAIL %s: server recv after client SD_SEND returned %d, expected 0 (EOF)\n",
               TEST_NAME, r);
        goto out;
    }

    /* Half-close: reverse direction still works. */
    if (send(conn, "bye", 3, 0) != 3) {
        fail_wsa("server send after client half-close");
        goto out;
    }
    got = 0;
    while (got < 3) {
        r = recv(client, buf + got, 3 - got, 0);
        if (r <= 0) {
            fail_wsa("client recv after its own SD_SEND");
            goto out;
        }
        got += r;
    }
    if (memcmp(buf, "bye", 3) != 0) {
        printf("FAIL %s: reverse-direction payload mismatch\n", TEST_NAME);
        goto out;
    }

    /* Sending after SD_SEND must fail with WSAESHUTDOWN. */
    if (send(client, "x", 1, 0) != SOCKET_ERROR || WSAGetLastError() != WSAESHUTDOWN) {
        printf("FAIL %s: send after SD_SEND error=%d, expected WSAESHUTDOWN (10058)\n",
               TEST_NAME, WSAGetLastError());
        goto out;
    }

    if (shutdown(client, SD_BOTH) != 0) {
        fail_wsa("shutdown(client, SD_BOTH) after SD_SEND");
        goto out;
    }

    /* Shutdown on a socket that was never connected. */
    unconnected = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (unconnected == INVALID_SOCKET) {
        fail_wsa("unconnected socket");
        goto out;
    }
    if (shutdown(unconnected, SD_BOTH) != SOCKET_ERROR || WSAGetLastError() != WSAENOTCONN) {
        printf("FAIL %s: shutdown on unconnected socket error=%d, expected WSAENOTCONN (10057)\n",
               TEST_NAME, WSAGetLastError());
        goto out;
    }
    if (closesocket(unconnected) != 0) {
        fail_wsa("closesocket(unconnected)");
        goto out;
    }
    unconnected = INVALID_SOCKET;

    if (closesocket(client) != 0) {
        fail_wsa("closesocket(client)");
        client = INVALID_SOCKET;
        goto out;
    }
    client = INVALID_SOCKET;

    /* Using a closed handle must fail with WSAENOTSOCK. */
    {
        SOCKET dead = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (dead == INVALID_SOCKET) {
            fail_wsa("socket for closed-handle check");
            goto out;
        }
        closesocket(dead);
        if (send(dead, "z", 1, 0) != SOCKET_ERROR || WSAGetLastError() != WSAENOTSOCK) {
            printf("FAIL %s: send on closed handle error=%d, expected WSAENOTSOCK (10038)\n",
                   TEST_NAME, WSAGetLastError());
            goto out;
        }
    }

    printf("PASS %s\n", TEST_NAME);
    ret = 0;

out:
    if (unconnected != INVALID_SOCKET)
        closesocket(unconnected);
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
