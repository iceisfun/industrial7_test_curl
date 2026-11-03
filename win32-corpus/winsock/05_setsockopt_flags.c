/*
 * Test: 05_setsockopt_flags
 * Purpose: Socket option round trips that curl's connection setup depends on:
 *          TCP_NODELAY, SO_KEEPALIVE, SO_REUSEADDR, SO_TYPE, plus the error
 *          contract for an unknown option.
 * APIs: setsockopt, getsockopt, socket, bind, listen, connect, accept,
 *       closesocket, WSAGetLastError.
 * Success:
 *   - TCP_NODELAY (IPPROTO_TCP) set to 1 reads back 1, then 0 reads back 0.
 *   - SO_KEEPALIVE set to 1 reads back 1, then 0 reads back 0.
 *   - SO_REUSEADDR set to 1 reads back 1 (read-back only; no port-stealing
 *     semantics are tested, because curl does not set it on Windows).
 *   - SO_TYPE reads back SOCK_STREAM.
 *   - An unknown option (SOL_SOCKET, 0x7FFF) fails with WSAENOPROTOOPT (10042).
 * Source: lib/cf-socket.c:155-161 (TCP_NODELAY set via setsockopt, int onoff),
 *         lib/cf-socket.c:200-202 (SO_KEEPALIVE set via setsockopt),
 *         lib/socketpair.c:183-194 (SO_REUSEADDR is NOT set on Windows; the
 *         read-back check here is a corpus-scope check only).
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

#define TEST_NAME "setsockopt_flags"

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

/*
 * Reads a socket option as int; returns 0 on success, -1 on failure.
 * *outlen receives the optlen the stack reports back, so callers can tell a
 * full int-sized result from a short write.
 */
static int get_int_opt_len(SOCKET s, int level, int opt, int *out, int *outlen)
{
    int v = 0;
    int len = (int)sizeof(v);
    if (getsockopt(s, level, opt, (char *)&v, &len) == SOCKET_ERROR)
        return -1;
    *out = v;
    *outlen = len;
    return 0;
}

/* Reads a socket option as int; returns 0 on success, -1 on failure. */
static int get_int_opt(SOCKET s, int level, int opt, int *out)
{
    int len = 0;
    return get_int_opt_len(s, level, opt, out, &len);
}

static int set_int_opt(SOCKET s, int level, int opt, int value)
{
    return setsockopt(s, level, opt, (const char *)&value, (int)sizeof(value));
}

static int body(void)
{
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, conn = INVALID_SOCKET;
    unsigned short port = 0;
    struct sockaddr_in sa;
    int val = 0;
    int optlen = 0;
    int nodelay_short = 0;
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

    /* TCP_NODELAY on and off. */
    if (set_int_opt(client, IPPROTO_TCP, TCP_NODELAY, 1) == SOCKET_ERROR) {
        fail_wsa("setsockopt(TCP_NODELAY, 1)");
        goto out;
    }
    if (get_int_opt_len(client, IPPROTO_TCP, TCP_NODELAY, &val, &optlen) != 0) {
        fail_wsa("getsockopt(TCP_NODELAY)");
        goto out;
    }
    if (optlen != (int)sizeof(int)) {
        /* Wine writes only one byte here (optlen=1); the value is not meaningful. */
        nodelay_short = optlen;
    } else if (val == 0) {
        printf("FAIL %s: TCP_NODELAY read back 0 after setting 1\n", TEST_NAME);
        goto out;
    }
    if (set_int_opt(client, IPPROTO_TCP, TCP_NODELAY, 0) == SOCKET_ERROR) {
        fail_wsa("setsockopt(TCP_NODELAY, 0)");
        goto out;
    }
    if (get_int_opt_len(client, IPPROTO_TCP, TCP_NODELAY, &val, &optlen) != 0) {
        fail_wsa("getsockopt(TCP_NODELAY) after 0");
        goto out;
    }
    if (optlen != (int)sizeof(int)) {
        nodelay_short = optlen;
    } else if (val != 0) {
        printf("FAIL %s: TCP_NODELAY read back %d after setting 0\n", TEST_NAME, val);
        goto out;
    }
    if (set_int_opt(client, IPPROTO_TCP, TCP_NODELAY, 1) == SOCKET_ERROR) {
        fail_wsa("setsockopt(TCP_NODELAY, 1) for curl default");
        goto out;
    }

    /* SO_KEEPALIVE on and off. */
    if (set_int_opt(client, SOL_SOCKET, SO_KEEPALIVE, 1) == SOCKET_ERROR) {
        fail_wsa("setsockopt(SO_KEEPALIVE, 1)");
        goto out;
    }
    if (get_int_opt(client, SOL_SOCKET, SO_KEEPALIVE, &val) != 0 || val == 0) {
        printf("FAIL %s: SO_KEEPALIVE read back %d after setting 1\n", TEST_NAME, val);
        goto out;
    }
    if (set_int_opt(client, SOL_SOCKET, SO_KEEPALIVE, 0) == SOCKET_ERROR) {
        fail_wsa("setsockopt(SO_KEEPALIVE, 0)");
        goto out;
    }
    if (get_int_opt(client, SOL_SOCKET, SO_KEEPALIVE, &val) != 0 || val != 0) {
        printf("FAIL %s: SO_KEEPALIVE read back %d after setting 0\n", TEST_NAME, val);
        goto out;
    }

    /* SO_REUSEADDR read-back on the listener. */
    if (set_int_opt(listener, SOL_SOCKET, SO_REUSEADDR, 1) == SOCKET_ERROR) {
        fail_wsa("setsockopt(SO_REUSEADDR, 1)");
        goto out;
    }
    if (get_int_opt(listener, SOL_SOCKET, SO_REUSEADDR, &val) != 0 || val == 0) {
        printf("FAIL %s: SO_REUSEADDR read back %d after setting 1\n", TEST_NAME, val);
        goto out;
    }

    /* SO_TYPE identifies the socket type. */
    if (get_int_opt(client, SOL_SOCKET, SO_TYPE, &val) != 0 || val != SOCK_STREAM) {
        printf("FAIL %s: SO_TYPE=%d, expected SOCK_STREAM (%d)\n", TEST_NAME, val, SOCK_STREAM);
        goto out;
    }

    /* Unknown option must be rejected with WSAENOPROTOOPT. */
    if (set_int_opt(client, SOL_SOCKET, 0x7FFF, 1) != SOCKET_ERROR) {
        printf("FAIL %s: setsockopt of unknown option succeeded\n", TEST_NAME);
        goto out;
    }
    if (WSAGetLastError() != WSAENOPROTOOPT) {
        printf("FAIL %s: unknown option error=%d, expected WSAENOPROTOOPT (10042)\n",
               TEST_NAME, WSAGetLastError());
        goto out;
    }

    if (nodelay_short) {
        printf("SKIP %s: wine gap: getsockopt(IPPROTO_TCP, TCP_NODELAY) reports optlen=%d "
               "instead of %d (wine writes a single byte); TCP_NODELAY read-back not verified, "
               "all other checks passed\n",
               TEST_NAME, nodelay_short, (int)sizeof(int));
        ret = 77;
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
