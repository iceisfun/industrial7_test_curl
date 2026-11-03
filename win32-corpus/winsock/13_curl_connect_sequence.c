/*
 * Test: 13_curl_connect_sequence
 * Purpose: End-to-end curl-style socket lifecycle for one HTTP/1.0 exchange on
 *          loopback, in the order lib/cf-socket.c performs it:
 *            socket -> FIONBIO on -> TCP_NODELAY -> SO_KEEPALIVE ->
 *            SIO_KEEPALIVE_VALS -> connect (EINPROGRESS) -> select writable ->
 *            SO_ERROR == 0 -> getsockname/getpeername -> nonblocking send ->
 *            nonblocking recv until EOF -> closesocket.
 *          The server runs on a separate thread (accept, read request, reply).
 * APIs: WSAStartup, socket, ioctlsocket(FIONBIO), setsockopt(TCP_NODELAY,
 *       SO_KEEPALIVE), WSAIoctl(SIO_KEEPALIVE_VALS), connect, select,
 *       getsockopt(SO_ERROR), getsockname, getpeername, send, recv,
 *       accept, bind, listen, CreateThread, WaitForSingleObject, CloseHandle,
 *       closesocket, WSAGetLastError.
 * Success:
 *   - connect is either immediate or pending (WSAEWOULDBLOCK/WSAEINPROGRESS),
 *     and the socket is writable within 5 s with SO_ERROR == 0.
 *   - getpeername reports the listener port; getsockname reports 127.0.0.1.
 *   - the client receives "HTTP/1.0 200 OK" and the body "hello" before EOF.
 *   - the server thread finishes with status 0 within 5 s.
 *   - SKIP only when SIO_KEEPALIVE_VALS is unsupported (WSAEOPNOTSUPP).
 * Source: lib/cf-socket.c:155-161 (TCP_NODELAY), lib/cf-socket.c:200-202
 *         (SO_KEEPALIVE), lib/cf-socket.c:265 (WSAIoctl SIO_KEEPALIVE_VALS),
 *         lib/cf-socket.c:968 (SO_ERROR after connect), lib/cf-socket.c:999
 *         (in-progress connect is not an error), lib/connect.c:385 (wait via
 *         poll for connect completion).
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
#include <mstcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "curl_connect_sequence"

#ifndef SIO_KEEPALIVE_VALS
#define SIO_KEEPALIVE_VALS _WSAIOW(IOC_VENDOR, 4)
#endif

#define RESPONSE "HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"

struct server_ctx {
    SOCKET listener;
    int result;
};

static int fail_wsa(const char *what)
{
    printf("FAIL %s: %s failed, WSAGetLastError=%d GetLastError=%lu\n",
           TEST_NAME, what, WSAGetLastError(), (unsigned long)GetLastError());
    return 1;
}

static DWORD WINAPI server_thread(LPVOID param)
{
    struct server_ctx *ctx = (struct server_ctx *)param;
    SOCKET conn;
    char req[256];
    int len = 0, sent = 0, total = (int)strlen(RESPONSE);

    ctx->result = -1;
    conn = accept(ctx->listener, NULL, NULL);
    if (conn == INVALID_SOCKET)
        return 1;

    memset(req, 0, sizeof(req));
    while (len < (int)sizeof(req) - 1 && strstr(req, "\r\n\r\n") == NULL) {
        int r = recv(conn, req + len, (int)sizeof(req) - 1 - len, 0);
        if (r <= 0)
            break;
        len += r;
    }
    if (strstr(req, "GET / HTTP/1.0\r\n") == NULL) {
        ctx->result = -2;
        closesocket(conn);
        return 0;
    }

    while (sent < total) {
        int r = send(conn, RESPONSE + sent, total - sent, 0);
        if (r == SOCKET_ERROR) {
            ctx->result = -3;
            closesocket(conn);
            return 0;
        }
        sent += r;
    }
    closesocket(conn);
    ctx->result = 0;
    return 0;
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

/* Waits for the socket to be ready in the requested direction; returns select() result. */
static int wait_ready(SOCKET s, int want_write, int seconds)
{
    fd_set set, eset;
    struct timeval tv;

    FD_ZERO(&set);
    FD_ZERO(&eset);
    FD_SET(s, &set);
    if (want_write)
        FD_SET(s, &eset);
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    if (want_write)
        return select(0, NULL, &set, &eset, &tv);
    return select(0, &set, NULL, NULL, &tv);
}

static int body(void)
{
    struct server_ctx ctx;
    HANDLE thread = NULL;
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET;
    unsigned short port = 0, local_port = 0;
    struct sockaddr_in sa;
    u_long mode;
    DWORD bytes = 0;
    struct tcp_keepalive ka;
    int on = 1, err = 0, errlen = (int)sizeof(err), len, sel;
    int in_progress = 0;
    const char *req = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    size_t reqlen = strlen(req), sent = 0;
    char resp[512];
    size_t got = 0;
    int ret = 1;
    DWORD wait;

    listener = make_listener(&port);
    if (listener == INVALID_SOCKET) {
        fail_wsa("listener setup");
        return 1;
    }
    ctx.listener = listener;
    ctx.result = -99;
    thread = CreateThread(NULL, 0, server_thread, &ctx, 0, NULL);
    if (thread == NULL) {
        fail_wsa("CreateThread");
        closesocket(listener);
        return 1;
    }

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        fail_wsa("client socket");
        goto out;
    }

    /* Curl_nonblock() */
    mode = 1;
    if (ioctlsocket(client, FIONBIO, &mode) != 0) {
        fail_wsa("FIONBIO on");
        goto out;
    }
    /* set_tcp_nodelay() */
    if (setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, (int)sizeof(on)) == SOCKET_ERROR) {
        fail_wsa("TCP_NODELAY");
        goto out;
    }
    /* set_keepalive() */
    if (setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, (int)sizeof(on)) == SOCKET_ERROR) {
        fail_wsa("SO_KEEPALIVE");
        goto out;
    }
    memset(&ka, 0, sizeof(ka));
    ka.onoff = 1;
    ka.keepalivetime = 60000;
    ka.keepaliveinterval = 1000;
    if (WSAIoctl(client, SIO_KEEPALIVE_VALS, &ka, (DWORD)sizeof(ka),
                 NULL, 0, &bytes, NULL, NULL) != 0) {
        if (WSAGetLastError() == WSAEOPNOTSUPP) {
            printf("SKIP %s: SIO_KEEPALIVE_VALS not supported (WSAEOPNOTSUPP)\n", TEST_NAME);
            ret = 77;
            goto out;
        }
        fail_wsa("WSAIoctl(SIO_KEEPALIVE_VALS)");
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (connect(client, (struct sockaddr *)&sa, (int)sizeof(sa)) == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS) {
            printf("FAIL %s: connect error %d\n", TEST_NAME, e);
            goto out;
        }
        in_progress = 1;
    }

    sel = wait_ready(client, 1, 5);
    if (sel == SOCKET_ERROR) {
        fail_wsa("select waiting for connect");
        goto out;
    }
    if (sel == 0) {
        printf("FAIL %s: connect did not complete in 5 s (in_progress=%d)\n", TEST_NAME, in_progress);
        goto out;
    }

    if (getsockopt(client, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen) == SOCKET_ERROR) {
        fail_wsa("getsockopt(SO_ERROR)");
        goto out;
    }
    if (err != 0) {
        printf("FAIL %s: SO_ERROR=%d after connect\n", TEST_NAME, err);
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getsockname(client, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("getsockname");
        goto out;
    }
    local_port = ntohs(sa.sin_port);
    if (local_port == 0 || sa.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        printf("FAIL %s: local address not 127.0.0.1:nonzero\n", TEST_NAME);
        goto out;
    }

    memset(&sa, 0, sizeof(sa));
    len = (int)sizeof(sa);
    if (getpeername(client, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        fail_wsa("getpeername");
        goto out;
    }
    if (ntohs(sa.sin_port) != port) {
        printf("FAIL %s: peer port %u, expected %u\n", TEST_NAME,
               (unsigned)ntohs(sa.sin_port), (unsigned)port);
        goto out;
    }

    /* Nonblocking send of the request. */
    while (sent < reqlen) {
        int r = send(client, req + sent, (int)(reqlen - sent), 0);
        if (r == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                fail_wsa("send request");
                goto out;
            }
            if (wait_ready(client, 1, 5) <= 0) {
                printf("FAIL %s: socket not writable while sending request\n", TEST_NAME);
                goto out;
            }
            continue;
        }
        sent += (size_t)r;
    }

    /* Nonblocking receive until the server closes. */
    for (;;) {
        int r;
        if (got >= sizeof(resp) - 1) {
            printf("FAIL %s: response larger than buffer\n", TEST_NAME);
            goto out;
        }
        r = recv(client, resp + got, (int)(sizeof(resp) - 1 - got), 0);
        if (r == 0)
            break;
        if (r == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                fail_wsa("recv response");
                goto out;
            }
            if (wait_ready(client, 0, 5) <= 0) {
                printf("FAIL %s: response not readable within 5 s\n", TEST_NAME);
                goto out;
            }
            continue;
        }
        got += (size_t)r;
    }
    resp[got] = '\0';

    if (strncmp(resp, "HTTP/1.0 200 OK\r\n", 17) != 0) {
        printf("FAIL %s: unexpected status line\n", TEST_NAME);
        goto out;
    }
    if (strcmp(resp + got - 5, "hello") != 0 || strstr(resp, "\r\n\r\nhello") == NULL) {
        printf("FAIL %s: response body is not \"hello\"\n", TEST_NAME);
        goto out;
    }

    wait = WaitForSingleObject(thread, 5000);
    if (wait != WAIT_OBJECT_0) {
        printf("FAIL %s: server thread did not finish (wait=%lu)\n", TEST_NAME, (unsigned long)wait);
        goto out;
    }
    if (ctx.result != 0) {
        printf("FAIL %s: server thread result %d\n", TEST_NAME, ctx.result);
        goto out;
    }

    printf("PASS %s\n", TEST_NAME);
    ret = 0;

out:
    if (client != INVALID_SOCKET)
        closesocket(client);
    if (listener != INVALID_SOCKET)
        closesocket(listener);
    if (thread != NULL) {
        /* Closing the listener unblocks accept() if the server never got a connection. */
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
    }
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
