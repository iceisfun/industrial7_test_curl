/*
 * Test: 21_wsasendmsg_wsarecvmsg_pktinfo
 * Purpose: the extension functions WSASendMsg / WSARecvMsg (fetched with
 *          SIO_GET_EXTENSION_FUNCTION_POINTER, as QUIC code paths in curl's
 *          ngtcp2/quiche backends do) over UDP loopback, with IP_PKTINFO
 *          ancillary data and the truncation flag.
 * APIs: WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER), WSARecvMsg, WSASendMsg, IP_PKTINFO.
 * Success: both pointers resolve; a datagram sent with WSASendMsg arrives via
 *          WSARecvMsg with the right source and an IP_PKTINFO control record
 *          for 127.0.0.1; an undersized data buffer sets MSG_PARTIAL and
 *          reports WSAEMSGSIZE (10040) with dwFlags 0x300 and the first 4 bytes copied.
 * Source: lib/vquic/ (UDP send/recv with GSO/ECN on other platforms; Windows uses these).
 */
#define TEST_NAME "21_wsasendmsg_wsarecvmsg_pktinfo"
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
#include <mswsock.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define INFO(...) do { printf("INFO "); printf(__VA_ARGS__); printf("\n"); } while (0)
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); g_fail = 1; goto out; } while (0)
static __attribute__((unused)) int g_fail;
static __attribute__((unused)) SOCKET lis_loop(int backlog, unsigned short *port) {
  struct sockaddr_in a;
  int l = sizeof(a);
  SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == INVALID_SOCKET) return s;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(s, (struct sockaddr *)&a, sizeof(a)) || listen(s, backlog) || getsockname(s, (struct sockaddr *)&a, &l)) {
    closesocket(s);
    return INVALID_SOCKET;
  }
  *port = ntohs(a.sin_port);
  return s;
}
static __attribute__((unused)) struct sockaddr_in loop_addr(unsigned short port) {
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  return a;
}
#ifndef IP_PKTINFO
#define IP_PKTINFO 19
#endif

int main(void) {
  WSADATA wd;
  SOCKET rs = INVALID_SOCKET, ss = INVALID_SOCKET;
  GUID grecv = WSAID_WSARECVMSG, gsend = WSAID_WSASENDMSG;
  LPFN_WSARECVMSG pRecvMsg = NULL;
  LPFN_WSASENDMSG pSendMsg = NULL;
  struct sockaddr_in a, from, sfrom;
  int l = sizeof(a), r, e, on = 1;
  DWORD got = 0, nsent = 0, nrecv = 0;
  char data[] = "quic-datagram-0123456789";
  char rbuf[64];
  union { WSACMSGHDR h; char b[WSA_CMSG_SPACE(sizeof(IN_PKTINFO))]; } ctl;
  WSABUF wb, cb;
  WSAMSG msg;
  WSACMSGHDR *ch;
  int found = 0, i;

  if (WSAStartup(MAKEWORD(2, 2), &wd)) { printf("FAIL %s: WSAStartup\n", TEST_NAME); return 1; }
  rs = socket(AF_INET, SOCK_DGRAM, 0);
  ss = socket(AF_INET, SOCK_DGRAM, 0);
  a = loop_addr(0);
  if (bind(rs, (struct sockaddr *)&a, sizeof(a)) || getsockname(rs, (struct sockaddr *)&a, &l)) FAILF("bind");
  if (bind(ss, (struct sockaddr *)&(struct sockaddr_in){ .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) }, sizeof(a))) FAILF("bind sender");
  l = sizeof(sfrom); getsockname(ss, (struct sockaddr *)&sfrom, &l);

  r = WSAIoctl(rs, SIO_GET_EXTENSION_FUNCTION_POINTER, &grecv, sizeof(grecv), &pRecvMsg, sizeof(pRecvMsg), &got, NULL, NULL);
  if (r || !pRecvMsg || got != sizeof(pRecvMsg)) FAILF("WSARecvMsg pointer r=%d err=%d got=%lu", r, WSAGetLastError(), (unsigned long)got);
  r = WSAIoctl(ss, SIO_GET_EXTENSION_FUNCTION_POINTER, &gsend, sizeof(gsend), &pSendMsg, sizeof(pSendMsg), &got, NULL, NULL);
  if (r || !pSendMsg) FAILF("WSASendMsg pointer r=%d err=%d", r, WSAGetLastError());
  if (setsockopt(rs, IPPROTO_IP, IP_PKTINFO, (char *)&on, sizeof(on))) FAILF("IP_PKTINFO %d", WSAGetLastError());

  for (i = 0; i < 20; i++) {
    memset(&msg, 0, sizeof(msg));
    wb.buf = data; wb.len = sizeof(data);
    msg.name = (LPSOCKADDR)&a; msg.namelen = sizeof(a);
    msg.lpBuffers = &wb; msg.dwBufferCount = 1;
    nsent = 0;
    r = pSendMsg(ss, &msg, 0, &nsent, NULL, NULL);
    if (r) FAILF("WSASendMsg iteration %d err=%d", i, WSAGetLastError());
    if (nsent != sizeof(data)) FAILF("sent %lu", (unsigned long)nsent);

    memset(rbuf, 0, sizeof(rbuf)); memset(&ctl, 0, sizeof(ctl)); memset(&from, 0, sizeof(from));
    memset(&msg, 0, sizeof(msg));
    wb.buf = rbuf; wb.len = sizeof(rbuf);
    cb.buf = (char *)&ctl; cb.len = sizeof(ctl);
    msg.name = (LPSOCKADDR)&from; msg.namelen = sizeof(from);
    msg.lpBuffers = &wb; msg.dwBufferCount = 1;
    msg.Control = cb;
    nrecv = 0;
    r = pRecvMsg(rs, &msg, &nrecv, NULL, NULL);
    if (r) FAILF("WSARecvMsg iteration %d err=%d", i, WSAGetLastError());
    if (nrecv != sizeof(data) || memcmp(rbuf, data, sizeof(data))) FAILF("payload nrecv=%lu", (unsigned long)nrecv);
    if (from.sin_port != sfrom.sin_port || from.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) FAILF("source address");
    if (i == 0)
      INFO("flags=0x%lx namelen=%d control.len=%lu", (unsigned long)msg.dwFlags, msg.namelen, (unsigned long)msg.Control.len);
    found = 0;
    for (ch = WSA_CMSG_FIRSTHDR(&msg); ch; ch = WSA_CMSG_NXTHDR(&msg, ch)) {
      if (ch->cmsg_level == IPPROTO_IP && ch->cmsg_type == IP_PKTINFO) {
        IN_PKTINFO *pi = (IN_PKTINFO *)WSA_CMSG_DATA(ch);
        found = 1;
        if (i == 0) INFO("pktinfo addr=%08lx ifindex=%lu cmsg_len=%lu", (unsigned long)ntohl(pi->ipi_addr.s_addr), (unsigned long)pi->ipi_ifindex, (unsigned long)ch->cmsg_len);
        if (pi->ipi_addr.s_addr != htonl(INADDR_LOOPBACK)) FAILF("pktinfo destination address");
      }
    }
    if (!found) FAILF("no IP_PKTINFO record");
    if (msg.dwFlags != 0 || msg.Control.len != 24) FAILF("flags 0x%lx control len %lu, expected 0 / 24", (unsigned long)msg.dwFlags, (unsigned long)msg.Control.len);
  }

  /* truncation */
  nsent = 0;
  memset(&msg, 0, sizeof(msg));
  wb.buf = data; wb.len = sizeof(data);
  msg.name = (LPSOCKADDR)&a; msg.namelen = sizeof(a);
  msg.lpBuffers = &wb; msg.dwBufferCount = 1;
  pSendMsg(ss, &msg, 0, &nsent, NULL, NULL);
  memset(&msg, 0, sizeof(msg));
  wb.buf = rbuf; wb.len = 4;
  msg.lpBuffers = &wb; msg.dwBufferCount = 1;
  nrecv = 0;
  r = pRecvMsg(rs, &msg, &nrecv, NULL, NULL);
  e = WSAGetLastError();
  INFO("truncated: r=%d err=%d nrecv=%lu flags=0x%lx", r, e, (unsigned long)nrecv, (unsigned long)msg.dwFlags);
  if (r != SOCKET_ERROR || e != WSAEMSGSIZE || nrecv != 4 || memcmp(rbuf, "quic", 4)) FAILF("truncated receive r=%d err=%d nrecv=%lu, expected SOCKET_ERROR / 10040 / 4", r, e, (unsigned long)nrecv);
  if (msg.dwFlags != 0x300) FAILF("truncated receive flags 0x%lx, expected 0x300 (MSG_TRUNC|MSG_CTRUNC)", (unsigned long)msg.dwFlags);
  printf("PASS %s\n", TEST_NAME);
out:
  if (rs != INVALID_SOCKET) closesocket(rs);
  if (ss != INVALID_SOCKET) closesocket(ss);
  WSACleanup();
  return g_fail;
}
