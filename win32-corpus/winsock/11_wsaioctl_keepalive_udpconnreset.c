/*
 * Test: 11_wsaioctl_keepalive_udpconnreset
 * Purpose: WSAIoctl control codes. SIO_KEEPALIVE_VALS sets TCP keepalive
 *          timing on a connected socket, and SIO_UDP_CONNRESET toggles whether
 *          a UDP socket reports ICMP port-unreachable as WSAECONNRESET.
 * APIs: WSAIoctl, getsockopt(SO_KEEPALIVE), socket, bind, listen, connect,
 *       accept, closesocket, WSAGetLastError.
 * Success:
 *   - WSAIoctl(SIO_KEEPALIVE_VALS, {onoff=1, time=30000, interval=1000}) returns 0.
 *   - getsockopt(SO_KEEPALIVE) reads back 1 afterwards.
 *   - WSAIoctl(SIO_UDP_CONNRESET) with FALSE and then TRUE on a UDP socket returns 0.
 *   - Effect with FALSE: a datagram sent to a closed loopback UDP port draws an
 *     ICMP port-unreachable, and no error is reported (select times out).
 *   - Effect with TRUE: the same datagram makes the next recvfrom fail with
 *     WSAECONNRESET (10054).
 *   - getsockopt(SO_KEEPALIVE) reads are made with a freshly sized optlen each time.
 *   - Win10 22H2 accepts both codes (real Windows PASS, probed in std and adm);
 *     a WSAEOPNOTSUPP (10045) reply to either code is still a SKIP for
 *     stacks without the control codes.
 *   - A missing WSAECONNRESET with TRUE is a FAIL (the old wine SKIP path is
 *     removed: wine did not deliver the loopback ICMP, Windows does).
 * Source: lib/cf-socket.c:248-270 (SIO_KEEPALIVE_VALS via WSAIoctl with
 *         struct tcp_keepalive, failure logged and tolerated).
 *         SIO_UDP_CONNRESET is not referenced anywhere in lib/ in this tree;
 *         it is included because the corpus scope requires it.
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

#define TEST_NAME "wsaioctl_keepalive_udpconnreset"

#ifndef SIO_KEEPALIVE_VALS
#define SIO_KEEPALIVE_VALS _WSAIOW(IOC_VENDOR, 4)
#endif
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

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

/* Returns the port of a loopback UDP socket that was bound and then closed,
   so a datagram sent to it draws an ICMP port-unreachable. */
static int closed_udp_port(unsigned short *out_port)
{
    struct sockaddr_in sa;
    int len = (int)sizeof(sa);
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (s == INVALID_SOCKET)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(s, (struct sockaddr *)&sa, (int)sizeof(sa)) == SOCKET_ERROR ||
        getsockname(s, (struct sockaddr *)&sa, &len) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }
    *out_port = ntohs(sa.sin_port);
    closesocket(s);
    return 0;
}

/* Sends one datagram from u to a closed loopback port, waits 500 ms for the
   ICMP to arrive, then does a nonblocking recvfrom. Returns 0 when nothing is
   reported (WSAEWOULDBLOCK), 1 when recvfrom reports an error (err_out receives
   WSAGetLastError), -1 on a setup failure or unexpected data. */
static int udp_icmp_probe(SOCKET u, unsigned short target, int *err_out)
{
    struct sockaddr_in sa;
    u_long mode;
    char buf[8];
    int r, err;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(target);
    if (sendto(u, "x", 1, 0, (struct sockaddr *)&sa, (int)sizeof(sa)) != 1)
        return -1;

    Sleep(500);

    mode = 1;
    if (ioctlsocket(u, FIONBIO, &mode) != 0)
        return -1;
    r = recvfrom(u, buf, sizeof(buf), 0, NULL, NULL);
    err = WSAGetLastError();
    mode = 0;
    if (ioctlsocket(u, FIONBIO, &mode) != 0)
        return -1;

    if (r == SOCKET_ERROR) {
        if (err == WSAEWOULDBLOCK)
            return 0;
        *err_out = err;
        return 1;
    }
    return -1;   /* nothing was sent to us, so any data is unexpected */
}

static int body(void)
{
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, conn = INVALID_SOCKET;
    SOCKET udp = INVALID_SOCKET;
    unsigned short port = 0, closed_port = 0;
    struct sockaddr_in sa;
    struct tcp_keepalive ka;
    DWORD bytes = 0xFFFFFFFFu;
    DWORD flag;
    int val = 0, vlen;
    int probe_err = 0, probe;
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

    /* TCP keepalive timing via SIO_KEEPALIVE_VALS. */
    memset(&ka, 0, sizeof(ka));
    ka.onoff = 1;
    ka.keepalivetime = 30000;
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
    vlen = (int)sizeof(val);
    if (getsockopt(client, SOL_SOCKET, SO_KEEPALIVE, (char *)&val, &vlen) == SOCKET_ERROR) {
        fail_wsa("getsockopt(SO_KEEPALIVE) after SIO_KEEPALIVE_VALS");
        goto out;
    }
    if (val == 0) {
        printf("FAIL %s: SO_KEEPALIVE reads 0 after SIO_KEEPALIVE_VALS onoff=1\n", TEST_NAME);
        goto out;
    }

    /* Turning keepalive off through the same ioctl. */
    ka.onoff = 0;
    if (WSAIoctl(client, SIO_KEEPALIVE_VALS, &ka, (DWORD)sizeof(ka),
                 NULL, 0, &bytes, NULL, NULL) != 0) {
        fail_wsa("WSAIoctl(SIO_KEEPALIVE_VALS, onoff=0)");
        goto out;
    }
    vlen = (int)sizeof(val);
    if (getsockopt(client, SOL_SOCKET, SO_KEEPALIVE, (char *)&val, &vlen) == SOCKET_ERROR ||
        val != 0) {
        printf("FAIL %s: SO_KEEPALIVE=%d after SIO_KEEPALIVE_VALS onoff=0, expected 0\n",
               TEST_NAME, val);
        goto out;
    }

    /* UDP connection reset reporting. */
    udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) {
        fail_wsa("UDP socket");
        goto out;
    }
    if (closed_udp_port(&closed_port) != 0) {
        fail_wsa("reserving a closed UDP loopback port");
        goto out;
    }

    /* FALSE: the ICMP port-unreachable must be ignored, so nothing is reported. */
    flag = 0;
    if (WSAIoctl(udp, SIO_UDP_CONNRESET, &flag, (DWORD)sizeof(flag),
                 NULL, 0, &bytes, NULL, NULL) != 0) {
        if (WSAGetLastError() == WSAEOPNOTSUPP) {
            printf("SKIP %s: SIO_UDP_CONNRESET not supported (WSAEOPNOTSUPP)\n", TEST_NAME);
            ret = 77;
            goto out;
        }
        fail_wsa("WSAIoctl(SIO_UDP_CONNRESET, FALSE)");
        goto out;
    }
    probe = udp_icmp_probe(udp, closed_port, &probe_err);
    if (probe != 0) {
        printf("FAIL %s: with SIO_UDP_CONNRESET FALSE, probe returned %d (err=%d), expected no report\n",
               TEST_NAME, probe, probe_err);
        goto out;
    }

    /* TRUE: the same ICMP must surface as WSAECONNRESET on recvfrom. */
    flag = 1;
    if (WSAIoctl(udp, SIO_UDP_CONNRESET, &flag, (DWORD)sizeof(flag),
                 NULL, 0, &bytes, NULL, NULL) != 0) {
        fail_wsa("WSAIoctl(SIO_UDP_CONNRESET, TRUE)");
        goto out;
    }
    probe = udp_icmp_probe(udp, closed_port, &probe_err);
    if (probe != 1 || probe_err != WSAECONNRESET) {
        printf("FAIL %s: with SIO_UDP_CONNRESET TRUE, probe=%d err=%d, expected WSAECONNRESET (10054)\n",
               TEST_NAME, probe, probe_err);
        goto out;
    }

    printf("PASS %s\n", TEST_NAME);
    ret = 0;

out:
    if (udp != INVALID_SOCKET)
        closesocket(udp);
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
