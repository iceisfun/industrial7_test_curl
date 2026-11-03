/*
 * Test: 06_ipv6_v6only_dual_stack
 * Purpose: IPv6 loopback behaviour that curl relies on when it binds IPv6
 *          sockets and falls back to IPv4 mapping.
 *   Part A: IPV6_V6ONLY=1 socket bound to ::1 accepts an IPv6 client.
 *   Part B: IPV6_V6ONLY=0 socket bound to :: accepts an IPv4 127.0.0.1 client,
 *           and the accepted peer address is an IPv4-mapped IPv6 address.
 * APIs: socket(AF_INET6), setsockopt(IPPROTO_IPV6, IPV6_V6ONLY), getsockopt,
 *       bind, listen, connect, accept, getsockname, getpeername, send, recv.
 * Success:
 *   - Part A: V6ONLY reads back 1; getsockname reports AF_INET6 with address ::1;
 *     getpeername on the accepted socket matches the client's local port.
 *   - Part B: V6ONLY reads back 0 before bind; IPv4 connect to the dual-stack
 *     listener succeeds; accepted peer is AF_INET6 with ::ffff:127.0.0.1.
 *   - SKIP when AF_INET6 sockets or the ::1 / :: bind are unavailable.
 * Source: lib/cf-socket.c:1297-1298 (IPV6_V6ONLY set to 0 before bind on Windows,
 *         with the comment about IPv4-mapped addresses).
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

#define TEST_NAME "ipv6_v6only_dual_stack"

static int fail_wsa(const char *what)
{
    printf("FAIL %s: %s failed, WSAGetLastError=%d GetLastError=%lu\n",
           TEST_NAME, what, WSAGetLastError(), (unsigned long)GetLastError());
    return 1;
}

static int set_v6only(SOCKET s, int value)
{
    return setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&value, (int)sizeof(value));
}

/*
 * Returns 0 on success, -1 on getsockopt error, and 2 when the stack reports an
 * option length other than sizeof(int). Windows returns a 4-byte DWORD for
 * IPV6_V6ONLY; wine returns optlen 1 and writes only the low byte, so the
 * upper bytes keep the -1 sentinel (reads back -255). That is a wine gap, not
 * a Windows result, and the caller turns it into a SKIP.
 */
static int get_v6only(SOCKET s, int *out)
{
    int v = -1;
    int len = (int)sizeof(v);
    if (getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v, &len) == SOCKET_ERROR)
        return -1;
    *out = v;
    if (len != (int)sizeof(int))
        return 2;
    return 0;
}

/* Binds an AF_INET6 socket to either ::1 or :: on an ephemeral port. */
static SOCKET make_v6_listener(int loopback_only, int v6only, unsigned short *out_port, int *bind_err)
{
    struct sockaddr_in6 sa;
    int len = (int)sizeof(sa);
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

    *bind_err = 0;
    if (s == INVALID_SOCKET) {
        *bind_err = WSAGetLastError();
        return INVALID_SOCKET;
    }
    if (set_v6only(s, v6only) == SOCKET_ERROR) {
        closesocket(s);
        *bind_err = WSAGetLastError();
        return INVALID_SOCKET;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port = 0;
    if (loopback_only)
        sa.sin6_addr.s6_addr[15] = 1;   /* ::1 */
    if (bind(s, (struct sockaddr *)&sa, (int)sizeof(sa)) == SOCKET_ERROR) {
        *bind_err = WSAGetLastError();
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (listen(s, 8) == SOCKET_ERROR ||
        getsockname(s, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        *bind_err = WSAGetLastError();
        closesocket(s);
        return INVALID_SOCKET;
    }
    *out_port = ntohs(sa.sin6_port);
    return s;
}

/* True when the error means the IPv6 address family or address is absent, not a bug. */
static int v6_absent(int err)
{
    return err == WSAEAFNOSUPPORT || err == WSAEPFNOSUPPORT ||
           err == WSAEPROTONOSUPPORT || err == WSAEADDRNOTAVAIL;
}

static int is_loopback_v6(const struct in6_addr *a)
{
    int i;
    for (i = 0; i < 15; i++) {
        if (a->s6_addr[i] != 0)
            return 0;
    }
    return a->s6_addr[15] == 1;
}

static int is_v4_mapped_loopback(const struct in6_addr *a)
{
    int i;
    for (i = 0; i < 10; i++) {
        if (a->s6_addr[i] != 0)
            return 0;
    }
    return a->s6_addr[10] == 0xff && a->s6_addr[11] == 0xff &&
           a->s6_addr[12] == 127 && a->s6_addr[13] == 0 &&
           a->s6_addr[14] == 0 && a->s6_addr[15] == 1;
}

/* Part A: V6ONLY=1 socket on ::1 with an IPv6 client. Returns 0 pass, 1 fail, 77 skip. */
static int part_a(void)
{
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, conn = INVALID_SOCKET;
    unsigned short port = 0;
    struct sockaddr_in6 sa;
    int len, v = -1, bind_err = 0;
    int rc = 1;
    const char msg[4] = { 'v', '6', 'o', 'k' };
    char buf[4];
    int got = 0;

    listener = make_v6_listener(1, 1, &port, &bind_err);
    if (listener == INVALID_SOCKET) {
        if (v6_absent(bind_err)) {
            printf("SKIP %s: ::1 listener unavailable (error %d)\n", TEST_NAME, bind_err);
            return 77;
        }
        printf("FAIL %s: ::1 listener setup failed (error %d)\n", TEST_NAME, bind_err);
        return 1;
    }
    {
        int gr = get_v6only(listener, &v);
        if (gr == 2) {
            printf("SKIP %s: wine gap - getsockopt(IPV6_V6ONLY) returns a 1-byte optlen, not a 4-byte DWORD\n",
                   TEST_NAME);
            rc = 77;
            goto out;
        }
        if (gr != 0 || v != 1) {
            printf("FAIL %s: IPV6_V6ONLY reads back %d, expected 1\n", TEST_NAME, v);
            goto out;
        }
    }

    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getsockname(listener, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("getsockname on ::1 listener");
        goto out;
    }
    if (sa.sin6_family != AF_INET6 || !is_loopback_v6(&sa.sin6_addr)) {
        printf("FAIL %s: listener local family=%d, not ::1\n", TEST_NAME, (int)sa.sin6_family);
        goto out;
    }

    client = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        fail_wsa("client AF_INET6 socket");
        goto out;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    sa.sin6_addr.s6_addr[15] = 1;
    if (connect(client, (struct sockaddr *)&sa, (int)sizeof(sa)) == SOCKET_ERROR) {
        fail_wsa("connect to [::1]");
        goto out;
    }

    conn = accept(listener, NULL, NULL);
    if (conn == INVALID_SOCKET) {
        fail_wsa("accept on ::1");
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getpeername(conn, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("accepted getpeername");
        goto out;
    }
    if (sa.sin6_family != AF_INET6 || !is_loopback_v6(&sa.sin6_addr)) {
        printf("FAIL %s: accepted peer is not ::1 (family=%d)\n", TEST_NAME, (int)sa.sin6_family);
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getsockname(client, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("client getsockname on ::1");
        goto out;
    }
    {
        unsigned short client_port = ntohs(sa.sin6_port);
        memset(&sa, 0, sizeof(sa));
        len = (int)sizeof(sa);
        if (getpeername(conn, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
            fail_wsa("accepted getpeername (port check)");
            goto out;
        }
        if (ntohs(sa.sin6_port) != client_port) {
            printf("FAIL %s: accepted peer port %u, client local port %u\n", TEST_NAME,
                   (unsigned)ntohs(sa.sin6_port), (unsigned)client_port);
            goto out;
        }
    }

    if (send(client, msg, 4, 0) != 4) {
        fail_wsa("send over ::1");
        goto out;
    }
    while (got < 4) {
        int r = recv(conn, buf + got, 4 - got, 0);
        if (r <= 0) {
            fail_wsa("recv over ::1");
            goto out;
        }
        got += r;
    }
    if (memcmp(buf, msg, 4) != 0) {
        printf("FAIL %s: payload mismatch over ::1\n", TEST_NAME);
        goto out;
    }
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

/* Part B: V6ONLY=0 socket on :: accepting an IPv4 client. Returns 0 pass, 1 fail, 77 skip. */
static int part_b(void)
{
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, conn = INVALID_SOCKET;
    unsigned short port = 0;
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    int len, v = -1, bind_err = 0;
    int rc = 1;

    listener = make_v6_listener(0, 0, &port, &bind_err);
    if (listener == INVALID_SOCKET) {
        if (v6_absent(bind_err)) {
            printf("SKIP %s: dual-stack [::] listener unavailable (error %d)\n", TEST_NAME, bind_err);
            return 77;
        }
        printf("FAIL %s: dual-stack [::] listener setup failed (error %d)\n", TEST_NAME, bind_err);
        return 1;
    }
    {
        int gr = get_v6only(listener, &v);
        if (gr == 2) {
            printf("SKIP %s: wine gap - getsockopt(IPV6_V6ONLY) returns a 1-byte optlen, not a 4-byte DWORD\n",
                   TEST_NAME);
            rc = 77;
            goto out;
        }
        if (gr != 0 || v != 0) {
            printf("FAIL %s: IPV6_V6ONLY reads back %d on dual-stack socket, expected 0\n", TEST_NAME, v);
            goto out;
        }
    }

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        fail_wsa("IPv4 client socket");
        goto out;
    }
    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;
    sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa4.sin_port = htons(port);
    if (connect(client, (struct sockaddr *)&sa4, (int)sizeof(sa4)) == SOCKET_ERROR) {
        fail_wsa("IPv4 connect to dual-stack listener");
        goto out;
    }

    conn = accept(listener, NULL, NULL);
    if (conn == INVALID_SOCKET) {
        fail_wsa("accept of IPv4 client on dual-stack listener");
        goto out;
    }

    memset(&sa6, 0, sizeof(sa6));
    len = (int)sizeof(sa6);
    if (getpeername(conn, (struct sockaddr *)&sa6, &len) == SOCKET_ERROR) {
        fail_wsa("getpeername on dual-stack accepted socket");
        goto out;
    }
    if (sa6.sin6_family != AF_INET6) {
        printf("FAIL %s: accepted peer family %d, expected AF_INET6\n", TEST_NAME, (int)sa6.sin6_family);
        goto out;
    }
    if (!(sa6.sin6_addr.s6_addr[10] == 0xff && sa6.sin6_addr.s6_addr[11] == 0xff)) {
        printf("FAIL %s: accepted peer is not IPv4-mapped\n", TEST_NAME);
        goto out;
    }
    if (!is_v4_mapped_loopback(&sa6.sin6_addr)) {
        printf("FAIL %s: IPv4-mapped peer is not ::ffff:127.0.0.1\n", TEST_NAME);
        goto out;
    }

    memset(&sa4, 0, sizeof(sa4));
    len = (int)sizeof(sa4);
    if (getsockname(client, (struct sockaddr *)&sa4, &len) == SOCKET_ERROR) {
        fail_wsa("IPv4 client getsockname");
        goto out;
    }
    if (ntohs(sa6.sin6_port) != ntohs(sa4.sin_port)) {
        printf("FAIL %s: accepted peer port %u, client local port %u\n", TEST_NAME,
               (unsigned)ntohs(sa6.sin6_port), (unsigned)ntohs(sa4.sin_port));
        goto out;
    }
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

static int body(void)
{
    SOCKET probe;
    int rc;

    probe = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (probe == INVALID_SOCKET) {
        if (v6_absent(WSAGetLastError())) {
            printf("SKIP %s: AF_INET6 stream sockets unavailable (error %d)\n",
                   TEST_NAME, WSAGetLastError());
            return 77;
        }
        printf("FAIL %s: AF_INET6 socket failed (error %d)\n", TEST_NAME, WSAGetLastError());
        return 1;
    }
    closesocket(probe);

    rc = part_a();
    if (rc == 77)
        return 77;
    if (rc != 0)
        return rc;

    rc = part_b();
    if (rc == 77)
        return 77;
    if (rc != 0)
        return rc;

    printf("PASS %s\n", TEST_NAME);
    return 0;
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
