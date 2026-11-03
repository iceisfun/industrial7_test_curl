/*
 * Test: 12_wsasocketw_duplicate
 * Purpose: WSASocketW with WSA_FLAG_OVERLAPPED, and WSADuplicateSocketW
 *          followed by WSASocketW(FROM_PROTOCOL_INFO) in the same process.
 *          Checks that both handles refer to one underlying socket and that the
 *          socket survives closing the original handle while the duplicate is open.
 * APIs: WSASocketW, WSADuplicateSocketW, WSAPROTOCOL_INFOW, FROM_PROTOCOL_INFO,
 *       GetCurrentProcessId, bind, listen, getsockname, accept, connect,
 *       getsockopt(SO_TYPE), closesocket, WSAGetLastError.
 * Success:
 *   - WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED)
 *     returns a valid socket whose SO_TYPE is SOCK_STREAM.
 *   - WSADuplicateSocketW returns 0 and WSASocketW(FROM_PROTOCOL_INFO) returns a
 *     valid socket with the same local port.
 *   - a connection made after the original handle is closed is accepted on the
 *     duplicate, and its payload round-trips.
 *   - SKIP when WSASocketW or WSADuplicateSocketW is unsupported (WSAEOPNOTSUPP
 *     or WSAEPROTOTYPE). Other errors, including WSAEINVAL, are FAIL.
 * Source: lib/openldap.c:652 (WSADuplicateSocket(conn->sock[FIRSTSOCKET],
 *         GetCurrentProcessId(), ...) used to hand a socket to another context).
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

#define TEST_NAME "wsasocketw_duplicate"

static int fail_wsa(const char *what)
{
    printf("FAIL %s: %s failed, WSAGetLastError=%d GetLastError=%lu\n",
           TEST_NAME, what, WSAGetLastError(), (unsigned long)GetLastError());
    return 1;
}

/* Only "feature absent" errors skip; WSAEINVAL is a real failure for these valid arguments. */
static int is_unsupported(int err)
{
    return err == WSAEOPNOTSUPP || err == WSAEPROTOTYPE;
}

static int connect_and_echo(unsigned short port, SOCKET acceptor, const char *tag)
{
    SOCKET client, conn;
    struct sockaddr_in sa;
    char buf[8];
    int got = 0;
    int ret = 1;

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        printf("FAIL %s: %s client socket error %d\n", TEST_NAME, tag, WSAGetLastError());
        return 1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (connect(client, (struct sockaddr *)&sa, (int)sizeof(sa)) == SOCKET_ERROR) {
        printf("FAIL %s: %s connect error %d\n", TEST_NAME, tag, WSAGetLastError());
        closesocket(client);
        return 1;
    }
    conn = accept(acceptor, NULL, NULL);
    if (conn == INVALID_SOCKET) {
        printf("FAIL %s: %s accept on duplicate error %d\n", TEST_NAME, tag, WSAGetLastError());
        closesocket(client);
        return 1;
    }
    if (send(client, "dup", 3, 0) != 3) {
        printf("FAIL %s: %s client send error %d\n", TEST_NAME, tag, WSAGetLastError());
        goto out;
    }
    while (got < 3) {
        int r = recv(conn, buf + got, 3 - got, 0);
        if (r <= 0) {
            printf("FAIL %s: %s server recv error %d\n", TEST_NAME, tag, WSAGetLastError());
            goto out;
        }
        got += r;
    }
    if (memcmp(buf, "dup", 3) != 0) {
        printf("FAIL %s: %s payload mismatch\n", TEST_NAME, tag);
        goto out;
    }
    ret = 0;

out:
    closesocket(conn);
    closesocket(client);
    return ret;
}

static int body(void)
{
    SOCKET s = INVALID_SOCKET, dup = INVALID_SOCKET;
    WSAPROTOCOL_INFOW info;
    struct sockaddr_in sa;
    int len, type = 0, tlen = (int)sizeof(type);
    unsigned short port_s = 0, port_dup = 0;
    int ret = 1;

    s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        int e = WSAGetLastError();
        if (is_unsupported(e)) {
            printf("SKIP %s: WSASocketW unsupported (error %d)\n", TEST_NAME, e);
            return 77;
        }
        printf("FAIL %s: WSASocketW error %d\n", TEST_NAME, e);
        return 1;
    }
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &tlen) == SOCKET_ERROR ||
        type != SOCK_STREAM) {
        printf("FAIL %s: SO_TYPE=%d after WSASocketW, expected SOCK_STREAM\n", TEST_NAME, type);
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(s, (struct sockaddr *)&sa, (int)sizeof(sa)) == SOCKET_ERROR) {
        fail_wsa("bind WSASocketW socket");
        goto out;
    }
    if (listen(s, 8) == SOCKET_ERROR) {
        fail_wsa("listen WSASocketW socket");
        goto out;
    }
    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getsockname(s, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("getsockname on original");
        goto out;
    }
    port_s = ntohs(sa.sin_port);

    memset(&info, 0, sizeof(info));
    if (WSADuplicateSocketW(s, GetCurrentProcessId(), &info) != 0) {
        int e = WSAGetLastError();
        if (is_unsupported(e)) {
            printf("SKIP %s: WSADuplicateSocketW unsupported (error %d)\n", TEST_NAME, e);
            ret = 77;
            goto out;
        }
        printf("FAIL %s: WSADuplicateSocketW error %d\n", TEST_NAME, e);
        goto out;
    }

    dup = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
                     &info, 0, WSA_FLAG_OVERLAPPED);
    if (dup == INVALID_SOCKET) {
        int e = WSAGetLastError();
        if (is_unsupported(e)) {
            printf("SKIP %s: WSASocketW(FROM_PROTOCOL_INFO) unsupported (error %d)\n", TEST_NAME, e);
            ret = 77;
            goto out;
        }
        printf("FAIL %s: WSASocketW(FROM_PROTOCOL_INFO) error %d\n", TEST_NAME, e);
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getsockname(dup, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("getsockname on duplicate");
        goto out;
    }
    port_dup = ntohs(sa.sin_port);
    if (port_dup != port_s || port_s == 0) {
        printf("FAIL %s: duplicate port %u, original port %u\n", TEST_NAME,
               (unsigned)port_dup, (unsigned)port_s);
        goto out;
    }

    /* Original handle goes away; the underlying socket must survive via the duplicate. */
    if (closesocket(s) != 0) {
        fail_wsa("closesocket(original)");
        s = INVALID_SOCKET;
        goto out;
    }
    s = INVALID_SOCKET;

    if (connect_and_echo(port_dup, dup, "post-close") != 0)
        goto out;

    printf("PASS %s\n", TEST_NAME);
    ret = 0;

out:
    if (dup != INVALID_SOCKET)
        closesocket(dup);
    if (s != INVALID_SOCKET)
        closesocket(s);
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
