/*
 * Test: 05_setsockopt_flags
 * Purpose: Socket option round trips that curl's connection setup depends on:
 *          TCP_NODELAY, SO_KEEPALIVE, SO_REUSEADDR, SO_TYPE, plus the error
 *          contract for an unknown option.
 * APIs: setsockopt, getsockopt, socket, bind, listen, connect, accept,
 *       closesocket, WSAGetLastError.
 * Success:
 *   - TCP_NODELAY (IPPROTO_TCP) set to 1 reads back 1, then 0 reads back 0,
 *     5 reads back 1. getsockopt returns optlen=1 and writes ONE byte (probed
 *     on Win10 22H2; this is real Windows behaviour, not a wine gap). optlen 0
 *     fails with WSAEFAULT.
 *   - SO_KEEPALIVE: the same BOOLEAN contract (optlen 1).
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

/* Reads a BOOLEAN option: Windows reports optlen 1 and writes only the low byte. */
static int get_bool_opt(SOCKET s, int level, int opt, int expect, const char *what)
{
    int v = -1;
    int len = (int)sizeof(v);
    if (getsockopt(s, level, opt, (char *)&v, &len) == SOCKET_ERROR) {
        printf("FAIL %s: %s: getsockopt error %d\n", TEST_NAME, what, WSAGetLastError());
        return 1;
    }
    if (len != 1 || (v & 0xff) != expect || ((unsigned)v >> 8) != 0xffffffu) {
        printf("FAIL %s: %s: optlen=%d value=0x%08x, expected optlen 1 and low byte %d with the rest of the "
               "buffer untouched\n", TEST_NAME, what, len, (unsigned)v, expect);
        return 1;
    }
    return 0;
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

    /* TCP_NODELAY and SO_KEEPALIVE are BOOLEAN options on Windows: getsockopt
       reports optlen=1 and writes one byte (probed on Win10 22H2, with a 4 byte
       and a 1 byte buffer; a 0 byte buffer fails with WSAEFAULT). The set side
       accepts any non-zero int and normalises it to 1. */
    if (set_int_opt(client, IPPROTO_TCP, TCP_NODELAY, 1) == SOCKET_ERROR) {
        fail_wsa("setsockopt(TCP_NODELAY, 1)");
        goto out;
    }
    if (get_bool_opt(client, IPPROTO_TCP, TCP_NODELAY, 1, "TCP_NODELAY after 1"))
        goto out;
    if (set_int_opt(client, IPPROTO_TCP, TCP_NODELAY, 0) == SOCKET_ERROR) {
        fail_wsa("setsockopt(TCP_NODELAY, 0)");
        goto out;
    }
    if (get_bool_opt(client, IPPROTO_TCP, TCP_NODELAY, 0, "TCP_NODELAY after 0"))
        goto out;
    if (set_int_opt(client, IPPROTO_TCP, TCP_NODELAY, 5) == SOCKET_ERROR) {
        fail_wsa("setsockopt(TCP_NODELAY, 5)");
        goto out;
    }
    if (get_bool_opt(client, IPPROTO_TCP, TCP_NODELAY, 1, "TCP_NODELAY after 5 (normalised)"))
        goto out;
    {
        /* curl passes an int; a zero length is rejected, a 1 byte char works. */
        char one = 1;
        if (setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, 1) == SOCKET_ERROR) {
            fail_wsa("setsockopt(TCP_NODELAY, char 1)");
            goto out;
        }
        if (setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, 0) != SOCKET_ERROR ||
            WSAGetLastError() != WSAEFAULT) {
            printf("FAIL %s: setsockopt(TCP_NODELAY, optlen 0) error=%d, expected WSAEFAULT (10014)\n",
                   TEST_NAME, WSAGetLastError());
            goto out;
        }
        val = 0;
        optlen = 0;
        if (getsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *)&val, &optlen) != SOCKET_ERROR ||
            WSAGetLastError() != WSAEFAULT) {
            printf("FAIL %s: getsockopt(TCP_NODELAY, optlen 0) error=%d, expected WSAEFAULT (10014)\n",
                   TEST_NAME, WSAGetLastError());
            goto out;
        }
    }

    /* SO_KEEPALIVE on and off (also a BOOLEAN: optlen 1). */
    if (set_int_opt(client, SOL_SOCKET, SO_KEEPALIVE, 1) == SOCKET_ERROR) {
        fail_wsa("setsockopt(SO_KEEPALIVE, 1)");
        goto out;
    }
    if (get_bool_opt(client, SOL_SOCKET, SO_KEEPALIVE, 1, "SO_KEEPALIVE after 1"))
        goto out;
    if (set_int_opt(client, SOL_SOCKET, SO_KEEPALIVE, 0) == SOCKET_ERROR) {
        fail_wsa("setsockopt(SO_KEEPALIVE, 0)");
        goto out;
    }
    if (get_bool_opt(client, SOL_SOCKET, SO_KEEPALIVE, 0, "SO_KEEPALIVE after 0"))
        goto out;

    /* SO_REUSEADDR read-back on the listener. */
    if (set_int_opt(listener, SOL_SOCKET, SO_REUSEADDR, 1) == SOCKET_ERROR) {
        fail_wsa("setsockopt(SO_REUSEADDR, 1)");
        goto out;
    }
    if (get_int_opt_len(listener, SOL_SOCKET, SO_REUSEADDR, &val, &optlen) != 0 || val != 1 ||
        optlen != (int)sizeof(int)) {
        printf("FAIL %s: SO_REUSEADDR read back %d optlen=%d after setting 1, expected 1 / 4\n",
               TEST_NAME, val, optlen);
        goto out;
    }

    /* SO_TYPE identifies the socket type. */
    if (get_int_opt_len(client, SOL_SOCKET, SO_TYPE, &val, &optlen) != 0 || val != SOCK_STREAM ||
        optlen != (int)sizeof(int)) {
        printf("FAIL %s: SO_TYPE=%d optlen=%d, expected SOCK_STREAM (%d) / 4\n", TEST_NAME, val, optlen,
               SOCK_STREAM);
        goto out;
    }
    /* A 1 byte buffer is too small for an int option: WSAEFAULT. */
    {
        char tiny = 0;
        optlen = 1;
        if (getsockopt(client, SOL_SOCKET, SO_TYPE, &tiny, &optlen) != SOCKET_ERROR ||
            WSAGetLastError() != WSAEFAULT) {
            printf("FAIL %s: getsockopt(SO_TYPE, optlen 1) error=%d, expected WSAEFAULT (10014)\n", TEST_NAME,
                   WSAGetLastError());
            goto out;
        }
    }
    /* SO_BROADCAST is not supported on a TCP socket: WSAENOPROTOOPT. */
    if (set_int_opt(client, SOL_SOCKET, SO_BROADCAST, 1) != SOCKET_ERROR ||
        WSAGetLastError() != WSAENOPROTOOPT) {
        printf("FAIL %s: SO_BROADCAST on TCP error=%d, expected WSAENOPROTOOPT (10042)\n", TEST_NAME,
               WSAGetLastError());
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
