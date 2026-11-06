/*
 * 17_overlapped_status_fields
 *
 * Purpose: the OVERLAPPED status contract used when polling or waiting on
 *   overlapped file and pipe I/O: Internal (NTSTATUS) and InternalHigh (bytes),
 *   HasOverlappedIoCompleted, GetOverlappedResult / GetOverlappedResultEx
 *   with and without waiting, EOF and broken-pipe completions.
 * APIs: CreateFileW (FILE_FLAG_OVERLAPPED), CreateNamedPipeW, ReadFile,
 *   WriteFile, CreateIoCompletionPort, GetQueuedCompletionStatus,
 *   GetOverlappedResult, GetOverlappedResultEx, HasOverlappedIoCompleted.
 * Success (probed on Win10 22H2, std and adm identical):
 *   - overlapped file write: ERROR_IO_PENDING (997) and a packet with 4 bytes;
 *     the OVERLAPPED reads Internal 0 and InternalHigh 4 afterwards;
 *   - ReadFile at end of file: the packet is ok=FALSE, GetLastError
 *     ERROR_HANDLE_EOF (38), 0 bytes, Internal STATUS_END_OF_FILE (0xC0000011);
 *     a read of 8 bytes at offset 2 of a 4 byte file completes with 2 bytes;
 *   - HasOverlappedIoCompleted is TRUE for a zeroed OVERLAPPED;
 *   - a pending pipe read has Internal STATUS_PENDING (0x103) and
 *     HasOverlappedIoCompleted is FALSE; GetOverlappedResult(bWait FALSE) and
 *     GetOverlappedResultEx with timeout 0 fail ERROR_IO_INCOMPLETE (996);
 *     GetOverlappedResultEx with 300 ms fails WAIT_TIMEOUT (258) after at least
 *     290 ms, also when alertable;
 *   - after the writer sends 3 bytes GetOverlappedResultEx(1000) succeeds with
 *     3 bytes and Internal 0;
 *   - a pending read whose writer closes the pipe completes with
 *     ERROR_BROKEN_PIPE (109) and Internal STATUS_PIPE_BROKEN (0xC000014B).
 * Source: none (generic Win32 contract).
 */
#define TEST_NAME "17_overlapped_status_fields"
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
  WCHAR path[MAX_PATH], pn[64];
  HANDLE f, p, rd, wr;
  OVERLAPPED ov;
  DWORD n = 0, t0;
  pkt_t k;
  char b[8];
  BOOL ok;

  GetTempPathW(MAX_PATH, path);
  wcscat(path, L"i7iocp-status.tmp");
  f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE, NULL);
  if (f == INVALID_HANDLE_VALUE) FAILF("CreateFileW (gle %lu)", (unsigned long)GetLastError());
  p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  if (CreateIoCompletionPort(f, p, 0x20, 0) != p) FAILF("associate file");

  memset(&ov, 0, sizeof(ov));
  if (HasOverlappedIoCompleted(&ov) == FALSE) FAILF("HasOverlappedIoCompleted(zeroed OVERLAPPED) is FALSE");
  ok = WriteFile(f, "abcd", 4, &n, &ov);
  if (ok || GetLastError() != ERROR_IO_PENDING) FAILF("overlapped WriteFile: ok=%d gle=%lu, expected FALSE / 997", (int)ok, (unsigned long)GetLastError());
  k = get_pkt(p, 3000);
  EXPECT_PKT(k, TRUE, 0, 4, &ov, 0x20, 0, "write completion");
  if (ov.InternalHigh != 4) FAILF("InternalHigh after the write is %llu, expected 4", (unsigned long long)ov.InternalHigh);

  memset(&ov, 0, sizeof(ov));
  ov.Offset = 4;
  ok = ReadFile(f, b, sizeof(b), &n, &ov);
  if (ok || GetLastError() != ERROR_IO_PENDING) FAILF("ReadFile at EOF: ok=%d gle=%lu, expected FALSE / 997", (int)ok, (unsigned long)GetLastError());
  k = get_pkt(p, 3000);
  EXPECT_PKT(k, FALSE, ERROR_HANDLE_EOF, 0, &ov, 0x20, 0xC0000011u, "read at EOF completion");

  memset(&ov, 0, sizeof(ov));
  ov.Offset = 2;
  ok = ReadFile(f, b, sizeof(b), &n, &ov);
  if (ok || GetLastError() != ERROR_IO_PENDING) FAILF("partial ReadFile: ok=%d gle=%lu, expected FALSE / 997", (int)ok, (unsigned long)GetLastError());
  k = get_pkt(p, 3000);
  EXPECT_PKT(k, TRUE, 0, 2, &ov, 0x20, 0, "partial read completion");
  if (memcmp(b, "cd", 2) != 0) FAILF("partial read returned the wrong bytes");
  CloseHandle(f);
  CloseHandle(p);

  /* pipe */
  swprintf(pn, 64, L"\\\\.\\pipe\\i7iocp-status-%lu", (unsigned long)GetCurrentProcessId());
  rd = CreateNamedPipeW(pn, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
  wr = CreateFileW(pn, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (rd == INVALID_HANDLE_VALUE || wr == INVALID_HANDLE_VALUE) FAILF("pipe setup (gle %lu)", (unsigned long)GetLastError());
  memset(&ov, 0, sizeof(ov));
  ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
  ok = ReadFile(rd, b, sizeof(b), &n, &ov);
  if (ok || GetLastError() != ERROR_IO_PENDING) FAILF("pending pipe ReadFile: ok=%d gle=%lu", (int)ok, (unsigned long)GetLastError());
  if ((ULONG)ov.Internal != 0x103) FAILF("pending OVERLAPPED.Internal is 0x%llx, expected STATUS_PENDING (0x103)", (unsigned long long)ov.Internal);
  if (HasOverlappedIoCompleted(&ov)) FAILF("HasOverlappedIoCompleted is TRUE for a pending read");
  if (GetOverlappedResult(rd, &ov, &n, FALSE) || GetLastError() != ERROR_IO_INCOMPLETE) FAILF("GetOverlappedResult(FALSE) on a pending read: gle %lu, expected 996", (unsigned long)GetLastError());
  if (GetOverlappedResultEx(rd, &ov, &n, 0, FALSE) || GetLastError() != ERROR_IO_INCOMPLETE) FAILF("GetOverlappedResultEx(0): gle %lu, expected 996", (unsigned long)GetLastError());
  t0 = GetTickCount();
  if (GetOverlappedResultEx(rd, &ov, &n, 300, FALSE) || GetLastError() != WAIT_TIMEOUT) FAILF("GetOverlappedResultEx(300): gle %lu, expected 258", (unsigned long)GetLastError());
  if (GetTickCount() - t0 < 290) FAILF("GetOverlappedResultEx(300) returned after %lu ms", (unsigned long)(GetTickCount() - t0));
  if (GetOverlappedResultEx(rd, &ov, &n, 100, TRUE) || GetLastError() != WAIT_TIMEOUT) FAILF("alertable GetOverlappedResultEx(100): gle %lu, expected 258", (unsigned long)GetLastError());
  WriteFile(wr, "xyz", 3, &n, NULL);
  if (!GetOverlappedResultEx(rd, &ov, &n, 1000, FALSE) || n != 3 || ov.Internal != 0) FAILF("GetOverlappedResultEx after data: n=%lu Internal=0x%llx", (unsigned long)n, (unsigned long long)ov.Internal);
  if (memcmp(b, "xyz", 3) != 0) FAILF("pipe read returned the wrong bytes");

  memset(&ov, 0, sizeof(ov));
  ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
  ok = ReadFile(rd, b, sizeof(b), &n, &ov);
  if (ok || GetLastError() != ERROR_IO_PENDING) FAILF("second pending pipe ReadFile");
  CloseHandle(wr);
  if (GetOverlappedResultEx(rd, &ov, &n, 1000, FALSE) || GetLastError() != ERROR_BROKEN_PIPE || (ULONG)ov.Internal != 0xC000014Bu)
    FAILF("read pending when the writer closed: gle=%lu Internal=0x%llx, expected 109 / 0xC000014B", (unsigned long)GetLastError(), (unsigned long long)ov.Internal);
  CloseHandle(rd);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
