/*
 * 15_socket_pending_io_termination
 *
 * Purpose: the completion packet an IOCP-driven socket gets when a pending
 *   WSARecv ends in each of the ways a connection can end: orderly close by
 *   the peer, reset by the peer, local closesocket, CancelIoEx. An overlapped
 *   engine maps these (GetQueuedCompletionStatus result plus WSAGetOverlappedResult)
 *   to curl's recv results (0 = closed, error = failure), so the exact codes matter.
 * APIs: WSARecv (overlapped), CreateIoCompletionPort, GetQueuedCompletionStatus,
 *   WSAGetOverlappedResult, CancelIoEx, closesocket, setsockopt(SO_LINGER).
 * Success (probed on Win10 22H2, std and adm identical; each case 20 times):
 *   - WSARecv with no data returns SOCKET_ERROR / WSA_IO_PENDING (997);
 *   - peer shutdown(SD_SEND): packet ok=TRUE, 0 bytes, Internal STATUS_SUCCESS (EOF);
 *   - peer RST (SO_LINGER {1,0} then close): ok=FALSE, GetLastError
 *     ERROR_NETNAME_DELETED (64), Internal STATUS_CONNECTION_RESET (0xC000020D),
 *     WSAGetOverlappedResult fails WSAECONNRESET (10054);
 *   - local closesocket with the receive pending: ok=FALSE, GetLastError
 *     ERROR_CONNECTION_ABORTED (1236), Internal STATUS_CONNECTION_ABORTED
 *     (0xC0000241) -- not ERROR_OPERATION_ABORTED;
 *   - CancelIoEx(socket, &ov) returns TRUE and the packet is ok=FALSE,
 *     ERROR_OPERATION_ABORTED (995), Internal STATUS_CANCELLED (0xC0000120);
 *     a second CancelIoEx, and CancelIoEx(socket, NULL) with nothing pending,
 *     fail with ERROR_NOT_FOUND (1168); CancelIoEx(socket, NULL) with one
 *     pending receive cancels it (995).
 * Source: none (generic Winsock overlapped contract).
 */
#define TEST_NAME "15_socket_pending_io_termination"
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


enum { K_FIN, K_RST, K_CLOSE, K_CANCEL, K_CANCEL_ALL };

static void one(int kind, int iter) {
  SOCKET lis, cli, srv;
  unsigned short port;
  HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  char buf[16];
  WSABUF wb;
  OVERLAPPED ov;
  DWORD n = 0, f = 0, tr = 0, fl = 0;
  pkt_t p;
  char what[64];
  struct linger lg;

  lis = ov_listener(&port);
  ov_pair(lis, port, iocp, 0x30 + kind, &cli, &srv);
  wb.len = sizeof(buf);
  wb.buf = buf;
  memset(&ov, 0, sizeof(ov));
  snprintf(what, sizeof(what), "case %d iteration %d", kind, iter);
  if (WSARecv(cli, &wb, 1, &n, &f, &ov, NULL) != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING)
    FAILF("%s: WSARecv did not return pending (error %d)", what, WSAGetLastError());
  switch (kind) {
  case K_FIN:
    shutdown(srv, SD_SEND);
    p = get_pkt(iocp, 3000);
    EXPECT_PKT(p, TRUE, 0, 0, &ov, 0x30 + K_FIN, 0, what);
    break;
  case K_RST:
    lg.l_onoff = 1;
    lg.l_linger = 0;
    setsockopt(srv, SOL_SOCKET, SO_LINGER, (const char *)&lg, (int)sizeof(lg));
    closesocket(srv);
    srv = INVALID_SOCKET;
    p = get_pkt(iocp, 3000);
    EXPECT_PKT(p, FALSE, ERROR_NETNAME_DELETED, 0, &ov, 0x30 + K_RST, 0xC000020Du, what);
    if (WSAGetOverlappedResult(cli, &ov, &tr, FALSE, &fl) || WSAGetLastError() != WSAECONNRESET)
      FAILF("%s: WSAGetOverlappedResult after RST: error %d, expected 10054", what, WSAGetLastError());
    break;
  case K_CLOSE:
    closesocket(cli);
    cli = INVALID_SOCKET;
    p = get_pkt(iocp, 3000);
    EXPECT_PKT(p, FALSE, ERROR_CONNECTION_ABORTED, 0, &ov, 0x30 + K_CLOSE, 0xC0000241u, what);
    break;
  case K_CANCEL:
    if (!CancelIoEx((HANDLE)cli, &ov)) FAILF("%s: CancelIoEx failed (gle %lu)", what, (unsigned long)GetLastError());
    p = get_pkt(iocp, 3000);
    EXPECT_PKT(p, FALSE, ERROR_OPERATION_ABORTED, 0, &ov, 0x30 + K_CANCEL, 0xC0000120u, what);
    if (CancelIoEx((HANDLE)cli, &ov) || GetLastError() != ERROR_NOT_FOUND)
      FAILF("%s: second CancelIoEx gle %lu, expected ERROR_NOT_FOUND (1168)", what, (unsigned long)GetLastError());
    if (CancelIoEx((HANDLE)cli, NULL) || GetLastError() != ERROR_NOT_FOUND)
      FAILF("%s: CancelIoEx(NULL) with nothing pending gle %lu, expected 1168", what, (unsigned long)GetLastError());
    break;
  default:
    if (!CancelIoEx((HANDLE)cli, NULL)) FAILF("%s: CancelIoEx(NULL) with a pending receive failed (gle %lu)", what, (unsigned long)GetLastError());
    p = get_pkt(iocp, 3000);
    EXPECT_PKT(p, FALSE, ERROR_OPERATION_ABORTED, 0, &ov, 0x30 + K_CANCEL_ALL, 0xC0000120u, what);
    break;
  }
  if (cli != INVALID_SOCKET) closesocket(cli);
  if (srv != INVALID_SOCKET) closesocket(srv);
  closesocket(lis);
  CloseHandle(iocp);
}

int main(void) {
  WSADATA wsa;
  int k, i;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) FAILF("WSAStartup");
  for (k = K_FIN; k <= K_CANCEL_ALL; k++)
    for (i = 0; i < 20; i++)
      one(k, i);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
