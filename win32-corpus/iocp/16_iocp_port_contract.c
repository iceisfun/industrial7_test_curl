/*
 * 16_iocp_port_contract
 *
 * Purpose: the completion port API contract an event loop is built on:
 *   timeouts, posted packets, batch dequeue limits, and the errors for
 *   misuse of CreateIoCompletionPort.
 * APIs: CreateIoCompletionPort, PostQueuedCompletionStatus,
 *   GetQueuedCompletionStatus, GetQueuedCompletionStatusEx, CloseHandle.
 * Success (probed on Win10 22H2, std and adm identical):
 *   - GetQueuedCompletionStatus on an empty port: FALSE, GetLastError
 *     WAIT_TIMEOUT (258), lpOverlapped NULL and the other outputs untouched,
 *     for timeouts 50 ms and 0;
 *   - PostQueuedCompletionStatus with a NULL OVERLAPPED comes back as TRUE
 *     with the posted byte count and key and a NULL pointer; an arbitrary
 *     OVERLAPPED pointer comes back unchanged and its fields are not touched
 *     (Internal stays 0x77);
 *   - GetQueuedCompletionStatusEx: empty port with a timeout (alertable or
 *     not): FALSE / 258; with 3 packets queued and room for 2 it returns 2
 *     (keys 1 and 2, in order), the next call returns the remaining 1;
 *     maxEntries 0 and a NULL count pointer are ERROR_INVALID_PARAMETER (87);
 *   - CreateIoCompletionPort: associating a socket works once; the same
 *     handle again, with the same or another port, is ERROR_INVALID_PARAMETER
 *     (87); an event handle is ERROR_INVALID_HANDLE (6); (NULL, NULL) is 6;
 *     INVALID_HANDLE_VALUE with an existing port is 87;
 *   - GetQueuedCompletionStatus on a closed port: FALSE / ERROR_INVALID_HANDLE (6).
 * Source: none (generic Win32 contract).
 */
#define TEST_NAME "16_iocp_port_contract"
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


static void expect_timeout(HANDLE port, DWORD ms, const char *what) {
  pkt_t p = get_pkt(port, ms);
  if (p.ok || p.gle != WAIT_TIMEOUT || p.ov != NULL || p.bytes != 0xAAAA || p.key != 0xAAAA)
    FAILF("%s: ok=%d gle=%lu ov=%p bytes=0x%lx key=0x%llx, expected FALSE / 258 / NULL / untouched", what, (int)p.ok, (unsigned long)p.gle,
          (void *)p.ov, (unsigned long)p.bytes, (unsigned long long)p.key);
}

int main(void) {
  WSADATA wsa;
  HANDLE iocp, other, ev;
  OVERLAPPED fake;
  pkt_t p;
  SOCKET s;
  OVERLAPPED_ENTRY e[4];
  ULONG n = 0;
  HANDLE r;
  DWORD t0;

  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) FAILF("WSAStartup");
  iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  other = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  if (!iocp || !other) FAILF("CreateIoCompletionPort(port)");

  t0 = GetTickCount();
  expect_timeout(iocp, 50, "empty port, 50 ms");
  if (GetTickCount() - t0 < 40) FAILF("a 50 ms wait returned after %lu ms", (unsigned long)(GetTickCount() - t0));
  expect_timeout(iocp, 0, "empty port, 0 ms");

  if (!PostQueuedCompletionStatus(iocp, 7, 0x55, NULL)) FAILF("PostQueuedCompletionStatus(NULL overlapped)");
  p = get_pkt(iocp, 0);
  if (!p.ok || p.bytes != 7 || p.key != 0x55 || p.ov != NULL) FAILF("posted NULL-overlapped packet came back wrong (ok=%d bytes=%lu key=0x%llx ov=%p)", (int)p.ok, (unsigned long)p.bytes, (unsigned long long)p.key, (void *)p.ov);
  memset(&fake, 0, sizeof(fake));
  fake.Internal = 0x77;
  if (!PostQueuedCompletionStatus(iocp, 3, 0x66, &fake)) FAILF("PostQueuedCompletionStatus(overlapped)");
  p = get_pkt(iocp, 0);
  if (!p.ok || p.bytes != 3 || p.key != 0x66 || p.ov != &fake || fake.Internal != 0x77 || fake.InternalHigh != 0)
    FAILF("posted OVERLAPPED packet came back wrong or the OVERLAPPED was modified (Internal=0x%llx)", (unsigned long long)fake.Internal);

  /* batch dequeue */
  if (GetQueuedCompletionStatusEx(iocp, e, 4, &n, 50, FALSE) || GetLastError() != WAIT_TIMEOUT) FAILF("GetQueuedCompletionStatusEx on an empty port: gle %lu, expected 258", (unsigned long)GetLastError());
  if (GetQueuedCompletionStatusEx(iocp, e, 4, &n, 50, TRUE) || GetLastError() != WAIT_TIMEOUT) FAILF("alertable GetQueuedCompletionStatusEx on an empty port: gle %lu, expected 258", (unsigned long)GetLastError());
  PostQueuedCompletionStatus(iocp, 1, 1, NULL);
  PostQueuedCompletionStatus(iocp, 2, 2, NULL);
  PostQueuedCompletionStatus(iocp, 3, 3, NULL);
  if (!GetQueuedCompletionStatusEx(iocp, e, 2, &n, 0, FALSE) || n != 2 || e[0].lpCompletionKey != 1 || e[1].lpCompletionKey != 2)
    FAILF("batch of 2 from 3 queued: n=%lu", (unsigned long)n);
  if (!GetQueuedCompletionStatusEx(iocp, e, 4, &n, 0, FALSE) || n != 1 || e[0].lpCompletionKey != 3 || e[0].dwNumberOfBytesTransferred != 3)
    FAILF("remaining packet: n=%lu", (unsigned long)n);
  if (GetQueuedCompletionStatusEx(iocp, e, 0, &n, 0, FALSE) || GetLastError() != ERROR_INVALID_PARAMETER) FAILF("maxEntries 0: gle %lu, expected 87", (unsigned long)GetLastError());
  if (GetQueuedCompletionStatusEx(iocp, e, 4, NULL, 0, FALSE) || GetLastError() != ERROR_INVALID_PARAMETER) FAILF("NULL count pointer: gle %lu, expected 87", (unsigned long)GetLastError());

  /* association */
  s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
  if (CreateIoCompletionPort((HANDLE)s, iocp, 1, 0) != iocp) FAILF("associating a socket (gle %lu)", (unsigned long)GetLastError());
  SetLastError(0);
  if (CreateIoCompletionPort((HANDLE)s, iocp, 2, 0) != NULL || GetLastError() != ERROR_INVALID_PARAMETER) FAILF("associating the same socket again: gle %lu, expected 87", (unsigned long)GetLastError());
  SetLastError(0);
  if (CreateIoCompletionPort((HANDLE)s, other, 2, 0) != NULL || GetLastError() != ERROR_INVALID_PARAMETER) FAILF("associating the socket with another port: gle %lu, expected 87", (unsigned long)GetLastError());
  ev = CreateEventW(NULL, FALSE, FALSE, NULL);
  SetLastError(0);
  if (CreateIoCompletionPort(ev, iocp, 3, 0) != NULL || GetLastError() != ERROR_INVALID_HANDLE) FAILF("associating an event handle: gle %lu, expected 6", (unsigned long)GetLastError());
  SetLastError(0);
  if (CreateIoCompletionPort(NULL, NULL, 0, 0) != NULL || GetLastError() != ERROR_INVALID_HANDLE) FAILF("CreateIoCompletionPort(NULL, NULL): gle %lu, expected 6", (unsigned long)GetLastError());
  SetLastError(0);
  r = CreateIoCompletionPort(INVALID_HANDLE_VALUE, iocp, 3, 0);
  if (r != NULL || GetLastError() != ERROR_INVALID_PARAMETER) FAILF("INVALID_HANDLE_VALUE with an existing port: gle %lu, expected 87", (unsigned long)GetLastError());

  closesocket(s);
  CloseHandle(iocp);
  p = get_pkt(iocp, 0);
  if (p.ok || p.gle != ERROR_INVALID_HANDLE) FAILF("GetQueuedCompletionStatus on a closed port: ok=%d gle=%lu, expected FALSE / 6", (int)p.ok, (unsigned long)p.gle);
  CloseHandle(other);
  CloseHandle(ev);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
