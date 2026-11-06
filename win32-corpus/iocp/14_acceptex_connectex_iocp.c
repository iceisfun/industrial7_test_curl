/*
 * 14_acceptex_connectex_iocp
 *
 * Purpose: AcceptEx and ConnectEx through an I/O completion port, the way a
 *   native overlapped network stack (and any future curl IOCP socket filter)
 *   drives connection setup, including the failure path of ConnectEx.
 * APIs: WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER: AcceptEx, ConnectEx,
 *   GetAcceptExSockaddrs), CreateIoCompletionPort, GetQueuedCompletionStatus,
 *   setsockopt(SO_UPDATE_ACCEPT_CONTEXT, SO_UPDATE_CONNECT_CONTEXT),
 *   getpeername, WSAGetOverlappedResult.
 * Success (probed on Win10 22H2, std and adm identical):
 *   - the three extension functions resolve; AcceptEx on an idle listener and
 *     ConnectEx (bound socket) both return FALSE with WSA_IO_PENDING (997);
 *   - both complete through the port with success, 0 bytes, OVERLAPPED.Internal
 *     = STATUS_SUCCESS; the order of the two packets varies between runs;
 *   - before SO_UPDATE_CONNECT_CONTEXT / SO_UPDATE_ACCEPT_CONTEXT, getpeername
 *     on the sockets fails WSAENOTCONN (10057); after it, getpeername works
 *     and reports the listener port / the connecting peer;
 *   - GetAcceptExSockaddrs returns two AF_INET addresses of 16 bytes;
 *   - ConnectEx to a closed port: returns pending, then the port yields a
 *     failed packet with GetLastError ERROR_CONNECTION_REFUSED (1225),
 *     OVERLAPPED.Internal STATUS_CONNECTION_REFUSED (0xC0000236) and
 *     WSAGetOverlappedResult fails with WSAECONNREFUSED (10061); this takes
 *     about 2 s on Windows (2047 ms measured), accepted within 1..6 s.
 * Source: none (curl uses select/WSAEventSelect, not AcceptEx/ConnectEx);
 *   included because the corpus covers the IOCP socket contract.
 */
#define TEST_NAME "14_acceptex_connectex_iocp"
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
#include <stdlib.h>
#include <string.h>

#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); exit(1); } while (0)

static __attribute__((unused)) struct sockaddr_in loop_addr(unsigned short port) {
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(port);
  return sa;
}

static __attribute__((unused)) SOCKET ov_socket(void) {
  return WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
}

static __attribute__((unused)) SOCKET ov_listener(unsigned short *port) {
  struct sockaddr_in sa = loop_addr(0);
  int len = (int)sizeof(sa);
  SOCKET s = ov_socket();
  if (s == INVALID_SOCKET || bind(s, (struct sockaddr *)&sa, (int)sizeof(sa)) != 0 || listen(s, 8) != 0 ||
      getsockname(s, (struct sockaddr *)&sa, &len) != 0)
    FAILF("overlapped listener setup (error %d)", WSAGetLastError());
  *port = ntohs(sa.sin_port);
  return s;
}

/* Connected overlapped pair; the client is associated with the port under ckey. */
static __attribute__((unused)) void ov_pair(SOCKET lis, unsigned short port, HANDLE iocp, ULONG_PTR ckey, SOCKET *cli, SOCKET *srv) {
  struct sockaddr_in sa = loop_addr(port);
  *cli = ov_socket();
  if (*cli == INVALID_SOCKET || connect(*cli, (struct sockaddr *)&sa, (int)sizeof(sa)) != 0) FAILF("pair connect (error %d)", WSAGetLastError());
  *srv = accept(lis, NULL, NULL);
  if (*srv == INVALID_SOCKET) FAILF("pair accept (error %d)", WSAGetLastError());
  if (iocp && CreateIoCompletionPort((HANDLE)*cli, iocp, ckey, 0) != iocp) FAILF("associate client (gle %lu)", (unsigned long)GetLastError());
}

typedef struct {
  BOOL ok;
  DWORD gle, bytes;
  ULONG_PTR key;
  OVERLAPPED *ov;
} pkt_t;

/* Dequeue one packet; the OVERLAPPED pointer is NULL on a timeout. */
static __attribute__((unused)) pkt_t get_pkt(HANDLE port, DWORD ms) {
  pkt_t p;
  p.bytes = 0xAAAA;
  p.key = 0xAAAA;
  p.ov = NULL;
  SetLastError(0);
  p.ok = GetQueuedCompletionStatus(port, &p.bytes, &p.key, &p.ov, ms);
  p.gle = GetLastError();
  return p;
}

#define EXPECT_PKT(p, want_ok, want_gle, want_bytes, want_ov, want_key, want_status, what) do { \
    if ((p).ov != (want_ov)) FAILF("%s: wrong or missing OVERLAPPED (got %p, want %p, ok=%d gle=%lu)", (what), (void *)(p).ov, (void *)(want_ov), (int)(p).ok, (unsigned long)(p).gle); \
    if ((p).ok != (want_ok) || (p).gle != (DWORD)(want_gle) || (p).bytes != (DWORD)(want_bytes) || (p).key != (ULONG_PTR)(want_key)) \
      FAILF("%s: ok=%d gle=%lu bytes=%lu key=0x%llx, expected %d / %lu / %lu / 0x%llx", (what), (int)(p).ok, (unsigned long)(p).gle, (unsigned long)(p).bytes, (unsigned long long)(p).key, (int)(want_ok), (unsigned long)(want_gle), (unsigned long)(want_bytes), (unsigned long long)(want_key)); \
    if ((ULONG)(p).ov->Internal != (ULONG)(want_status)) \
      FAILF("%s: OVERLAPPED.Internal (NTSTATUS) 0x%08lx, expected 0x%08lx", (what), (unsigned long)(ULONG)(p).ov->Internal, (unsigned long)(ULONG)(want_status)); \
  } while (0)


int main(void) {
  WSADATA wsa;
  GUID ga = WSAID_ACCEPTEX, gc = WSAID_CONNECTEX, gg = WSAID_GETACCEPTEXSOCKADDRS;
  LPFN_ACCEPTEX AcceptExFn = NULL;
  LPFN_CONNECTEX ConnectExFn = NULL;
  LPFN_GETACCEPTEXSOCKADDRS GetAddrs = NULL;
  DWORD ret = 0, got = 0, tr = 0, fl = 0;
  SOCKET lis, as, c, dead, c2;
  unsigned short port, dport;
  HANDLE port2;
  char abuf[2 * (sizeof(struct sockaddr_in) + 16) + 16];
  OVERLAPPED ova, ovc, ovc2;
  struct sockaddr_in z, to, pn, *rs = NULL, *ls = NULL;
  struct sockaddr *lsa = NULL, *rsa = NULL;
  int l, lsl = 0, rsl = 0;
  pkt_t p;
  DWORD t0, el;

  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) FAILF("WSAStartup");
  lis = ov_listener(&port);
  if (WSAIoctl(lis, SIO_GET_EXTENSION_FUNCTION_POINTER, &ga, sizeof(ga), &AcceptExFn, sizeof(AcceptExFn), &ret, NULL, NULL) != 0 ||
      WSAIoctl(lis, SIO_GET_EXTENSION_FUNCTION_POINTER, &gc, sizeof(gc), &ConnectExFn, sizeof(ConnectExFn), &ret, NULL, NULL) != 0 ||
      WSAIoctl(lis, SIO_GET_EXTENSION_FUNCTION_POINTER, &gg, sizeof(gg), &GetAddrs, sizeof(GetAddrs), &ret, NULL, NULL) != 0 ||
      !AcceptExFn || !ConnectExFn || !GetAddrs)
    FAILF("resolving AcceptEx/ConnectEx/GetAcceptExSockaddrs (error %d)", WSAGetLastError());

  port2 = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  if (!port2 || CreateIoCompletionPort((HANDLE)lis, port2, 0xA, 0) != port2) FAILF("port setup");
  as = ov_socket();
  memset(&ova, 0, sizeof(ova));
  if (AcceptExFn(lis, as, abuf, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, &got, &ova) ||
      WSAGetLastError() != WSA_IO_PENDING)
    FAILF("AcceptEx on an idle listener did not return pending (error %d)", WSAGetLastError());
  p = get_pkt(port2, 100);
  if (p.ov != NULL || p.gle != WAIT_TIMEOUT) FAILF("a packet arrived before any client connected");

  c = ov_socket();
  z = loop_addr(0);
  if (bind(c, (struct sockaddr *)&z, (int)sizeof(z)) != 0) FAILF("bind client");
  if (CreateIoCompletionPort((HANDLE)c, port2, 0xC, 0) != port2) FAILF("associate client");
  memset(&ovc, 0, sizeof(ovc));
  to = loop_addr(port);
  if (ConnectExFn(c, (struct sockaddr *)&to, (int)sizeof(to), NULL, 0, &got, &ovc) || WSAGetLastError() != WSA_IO_PENDING)
    FAILF("ConnectEx did not return pending (error %d)", WSAGetLastError());
  /* The two completions arrive in either order (both orders were seen across runs). */
  p = get_pkt(port2, 2000);
  if (p.ov == &ovc) {
    EXPECT_PKT(p, TRUE, 0, 0, &ovc, 0xC, 0, "ConnectEx completion");
    p = get_pkt(port2, 2000);
    EXPECT_PKT(p, TRUE, 0, 0, &ova, 0xA, 0, "AcceptEx completion");
  } else {
    EXPECT_PKT(p, TRUE, 0, 0, &ova, 0xA, 0, "AcceptEx completion");
    p = get_pkt(port2, 2000);
    EXPECT_PKT(p, TRUE, 0, 0, &ovc, 0xC, 0, "ConnectEx completion");
  }

  l = (int)sizeof(pn);
  if (getpeername(c, (struct sockaddr *)&pn, &l) != SOCKET_ERROR || WSAGetLastError() != WSAENOTCONN) FAILF("getpeername before SO_UPDATE_CONNECT_CONTEXT");
  if (setsockopt(c, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) FAILF("SO_UPDATE_CONNECT_CONTEXT error %d", WSAGetLastError());
  l = (int)sizeof(pn);
  if (getpeername(c, (struct sockaddr *)&pn, &l) != 0 || ntohs(pn.sin_port) != port) FAILF("getpeername after SO_UPDATE_CONNECT_CONTEXT");
  l = (int)sizeof(pn);
  if (getpeername(as, (struct sockaddr *)&pn, &l) != SOCKET_ERROR || WSAGetLastError() != WSAENOTCONN) FAILF("getpeername on the accepted socket before SO_UPDATE_ACCEPT_CONTEXT");
  if (setsockopt(as, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char *)&lis, (int)sizeof(lis)) != 0) FAILF("SO_UPDATE_ACCEPT_CONTEXT error %d", WSAGetLastError());
  l = (int)sizeof(pn);
  if (getpeername(as, (struct sockaddr *)&pn, &l) != 0) FAILF("getpeername after SO_UPDATE_ACCEPT_CONTEXT");
  GetAddrs(abuf, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, &lsa, &lsl, &rsa, &rsl);
  ls = (struct sockaddr_in *)lsa;
  rs = (struct sockaddr_in *)rsa;
  if (lsl != 16 || rsl != 16 || ls->sin_family != AF_INET || rs->sin_family != AF_INET || ntohs(ls->sin_port) != port)
    FAILF("GetAcceptExSockaddrs lengths %d/%d or addresses wrong", lsl, rsl);

  /* ConnectEx to a closed port */
  dead = ov_listener(&dport);
  closesocket(dead);
  c2 = ov_socket();
  if (bind(c2, (struct sockaddr *)&z, (int)sizeof(z)) != 0 || CreateIoCompletionPort((HANDLE)c2, port2, 0xD, 0) != port2) FAILF("c2 setup");
  memset(&ovc2, 0, sizeof(ovc2));
  to = loop_addr(dport);
  t0 = GetTickCount();
  if (ConnectExFn(c2, (struct sockaddr *)&to, (int)sizeof(to), NULL, 0, &got, &ovc2) || WSAGetLastError() != WSA_IO_PENDING)
    FAILF("ConnectEx to a closed port did not return pending (error %d)", WSAGetLastError());
  p = get_pkt(port2, 8000);
  el = GetTickCount() - t0;
  EXPECT_PKT(p, FALSE, ERROR_CONNECTION_REFUSED, 0, &ovc2, 0xD, 0xC0000236u, "refused ConnectEx completion");
  if (el < 1000 || el > 6000) FAILF("refused ConnectEx completed after %lu ms, expected 1000..6000", (unsigned long)el);
  if (WSAGetOverlappedResult(c2, &ovc2, &tr, FALSE, &fl) || WSAGetLastError() != WSAECONNREFUSED) FAILF("WSAGetOverlappedResult after the refusal: error %d, expected 10061", WSAGetLastError());

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
