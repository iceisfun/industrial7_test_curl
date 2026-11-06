/*
 * Test: 09_wsapoll
 * Purpose: WSAPoll readiness reporting as an alternative to select() for the
 *          curl poll path (lib/select.c uses poll() when available). WSAPoll is
 *          resolved at runtime with LoadLibrary/GetProcAddress so that a missing
 *          export on a Windows older than Vista yields SKIP instead of a link error.
 * APIs: LoadLibraryA, GetProcAddress, FreeLibrary, WSAPoll (via pointer),
 *       socket, bind, listen, connect, accept, send, recv, closesocket.
 * Success:
 *   - WSAPoll on an idle listener with timeout 0 returns 0 with revents 0.
 *   - after a pending connect, POLLRDNORM is set on the listener (return 1).
 *   - a connected socket reports POLLWRNORM with timeout 0.
 *   - an idle connected socket reports no POLLRDNORM with timeout 0.
 *   - after 4 bytes are sent, POLLRDNORM is reported and recv returns 4 bytes.
 *   - after the peer closes (FIN), WSAPoll returns 1 with revents exactly
 *     POLLHUP (0x2): Windows does not add POLLRDNORM (probed 20 times, std and
 *     adm); recv then returns 0 (EOF).
 * Source: lib/select.c:97-99 (Curl_poll chooses poll() when HAVE_POLL is defined),
 *         lib/connect.c:385 (Curl_poll used while connect is pending).
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

#define TEST_NAME "wsapoll"

typedef int (WSAAPI *pfn_WSAPoll_t)(WSAPOLLFD *fdArray, ULONG fds, INT timeout);

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

/* Polls one socket for one event; returns WSAPoll result or SOCKET_ERROR. */
static int poll_one(pfn_WSAPoll_t fn, SOCKET s, SHORT events, INT timeout_ms, SHORT *revents)
{
    WSAPOLLFD pfd;
    int rc;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = s;
    pfd.events = events;
    rc = fn(&pfd, 1, timeout_ms);
    *revents = pfd.revents;
    return rc;
}

static int body(pfn_WSAPoll_t fn)
{
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, conn = INVALID_SOCKET;
    unsigned short port = 0;
    struct sockaddr_in sa;
    SHORT rev = 0;
    char buf[8];
    int rc, got = 0;
    int ret = 1;

    listener = make_listener(&port);
    if (listener == INVALID_SOCKET) {
        fail_wsa("listener setup");
        goto out;
    }

    rc = poll_one(fn, listener, POLLRDNORM, 0, &rev);
    if (rc != 0 || rev != 0) {
        printf("FAIL %s: idle listener poll returned %d revents=0x%x\n",
               TEST_NAME, rc, (unsigned)rev);
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

    rc = poll_one(fn, listener, POLLRDNORM, 2000, &rev);
    if (rc == SOCKET_ERROR) {
        fail_wsa("WSAPoll on listener with pending connection");
        goto out;
    }
    if (rc != 1 || (rev & POLLRDNORM) == 0) {
        printf("FAIL %s: pending connection poll returned %d revents=0x%x\n",
               TEST_NAME, rc, (unsigned)rev);
        goto out;
    }

    conn = accept(listener, NULL, NULL);
    if (conn == INVALID_SOCKET) {
        fail_wsa("accept");
        goto out;
    }

    rc = poll_one(fn, conn, POLLWRNORM, 2000, &rev);
    if (rc != 1 || (rev & POLLWRNORM) == 0) {
        printf("FAIL %s: connected socket not writable via WSAPoll (rc=%d revents=0x%x)\n",
               TEST_NAME, rc, (unsigned)rev);
        goto out;
    }

    rc = poll_one(fn, conn, POLLRDNORM, 0, &rev);
    if (rc != 0 || (rev & POLLRDNORM) != 0) {
        printf("FAIL %s: idle connected socket reports readable (rc=%d revents=0x%x)\n",
               TEST_NAME, rc, (unsigned)rev);
        goto out;
    }

    if (send(client, "poll", 4, 0) != 4) {
        fail_wsa("client send 4 bytes");
        goto out;
    }
    rc = poll_one(fn, conn, POLLRDNORM, 2000, &rev);
    if (rc != 1 || (rev & POLLRDNORM) == 0) {
        printf("FAIL %s: data not reported readable (rc=%d revents=0x%x)\n",
               TEST_NAME, rc, (unsigned)rev);
        goto out;
    }
    while (got < 4) {
        int r = recv(conn, buf + got, 4 - got, 0);
        if (r <= 0) {
            fail_wsa("recv after WSAPoll readable");
            goto out;
        }
        got += r;
    }
    if (memcmp(buf, "poll", 4) != 0) {
        printf("FAIL %s: payload mismatch\n", TEST_NAME);
        goto out;
    }

    /* Peer closes: readable with EOF, recv returns 0. */
    closesocket(client);
    client = INVALID_SOCKET;
    rc = poll_one(fn, conn, POLLRDNORM, 2000, &rev);
    if (rc != 1 || rev != POLLHUP) {
        printf("FAIL %s: peer close: rc=%d revents=0x%x, expected 1 / POLLHUP (0x2) alone (Win10 22H2, 20 runs)\n",
               TEST_NAME, rc, (unsigned)rev);
        goto out;
    }
    if (recv(conn, buf, sizeof(buf), 0) != 0) {
        printf("FAIL %s: recv after peer close did not return 0\n", TEST_NAME);
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
    HMODULE ws2;
    FARPROC proc;
    pfn_WSAPoll_t fn;
    int rc;

    memset(&wsa, 0, sizeof(wsa));
    rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        printf("FAIL %s: WSAStartup returned %d\n", TEST_NAME, rc);
        return 1;
    }

    ws2 = LoadLibraryA("ws2_32.dll");
    if (ws2 == NULL) {
        printf("SKIP %s: LoadLibrary(ws2_32.dll) failed (error %lu)\n",
               TEST_NAME, (unsigned long)GetLastError());
        WSACleanup();
        fflush(stdout);
        return 77;
    }
    proc = GetProcAddress(ws2, "WSAPoll");
    if (proc == NULL) {
        printf("SKIP %s: WSAPoll not exported by ws2_32 (error %lu)\n",
               TEST_NAME, (unsigned long)GetLastError());
        FreeLibrary(ws2);
        WSACleanup();
        fflush(stdout);
        return 77;
    }
    fn = (pfn_WSAPoll_t)(void (*)(void))proc;

    rc = body(fn);
    FreeLibrary(ws2);
    WSACleanup();
    fflush(stdout);
    return rc;
}
