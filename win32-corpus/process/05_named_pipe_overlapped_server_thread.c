/*
 * Test: 05_named_pipe_overlapped_server_thread
 *
 * Purpose: run an overlapped (FILE_FLAG_OVERLAPPED) named pipe server on a
 *   worker thread and drive it from the main thread as a client, for two
 *   consecutive connections on the same instance (DisconnectNamedPipe then
 *   ConnectNamedPipe again). This is the event-driven accept/read/write loop
 *   used by local IPC servers, where the thread waits on an OVERLAPPED event
 *   rather than blocking synchronously on I/O.
 *
 * APIs: CreateNamedPipeW (FILE_FLAG_OVERLAPPED), CreateEventW, ConnectNamedPipe
 *   (overlapped), ReadFile/WriteFile (overlapped), GetOverlappedResult,
 *   WaitForSingleObject on OVERLAPPED.hEvent, FlushFileBuffers,
 *   DisconnectNamedPipe, CreateFileW and WaitNamedPipeW (client, retrying on
 *   ERROR_PIPE_BUSY), CreateThread, GetExitCodeThread.
 *
 * Success means: both rounds complete; the client receives exactly
 *   "ack:req0" and "ack:req1"; the server thread exits 0. An overlapped
 *   operation that is still pending after 10 seconds is a FAIL.
 *
 * Source reference: lib/curl_threads.c:57 (wait on a thread handle with a
 *   WAIT_OBJECT_0 check, then close) for the thread side. No overlapped named
 *   pipe call site exists in lib/, src/ or tests/; the overlapped wait is a
 *   Win32 pattern the corpus needs, not a curl code path.
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

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define NAME "named_pipe_overlapped_server_thread"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

#define ROUNDS 2
#define IO_TIMEOUT_MS 10000

struct server_ctx {
  HANDLE pipe;
};

static void put_u(wchar_t *dst, unsigned long v)
{
  wchar_t tmp[16];
  size_t n = 0, i;
  do {
    tmp[n++] = (wchar_t)(L'0' + (v % 10));
    v /= 10;
  } while(v);
  for(i = 0; i < n; i++)
    dst[i] = tmp[n - 1 - i];
  dst[n] = 0;
}

/*
 * Wait for an overlapped operation that returned ERROR_IO_PENDING (or failed
 * synchronously with it) and fetch its byte count. Returns TRUE on success.
 */
static BOOL complete_io(HANDLE h, OVERLAPPED *ov, DWORD *n)
{
  if(GetLastError() != ERROR_IO_PENDING)
    return FALSE;
  if(WaitForSingleObject(ov->hEvent, IO_TIMEOUT_MS) != WAIT_OBJECT_0)
    return FALSE;
  return GetOverlappedResult(h, ov, n, FALSE);
}

static DWORD WINAPI server_thread(LPVOID arg)
{
  struct server_ctx *ctx = (struct server_ctx *)arg;
  int round;

  for(round = 0; round < ROUNDS; round++) {
    OVERLAPPED ov;
    char req[64];
    char reply[80];
    DWORD got = 0, wrote = 0;
    int len;

    /* Accept. */
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if(!ov.hEvent)
      return 10;
    if(!ConnectNamedPipe(ctx->pipe, &ov)) {
      if(GetLastError() != ERROR_PIPE_CONNECTED &&
         !complete_io(ctx->pipe, &ov, &got)) {
        CloseHandle(ov.hEvent);
        return 11;
      }
    }
    CloseHandle(ov.hEvent);

    /* Read the request. */
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if(!ov.hEvent)
      return 12;
    if(!ReadFile(ctx->pipe, req, sizeof(req) - 1, &got, &ov)) {
      if(!complete_io(ctx->pipe, &ov, &got)) {
        CloseHandle(ov.hEvent);
        return 12;
      }
    }
    CloseHandle(ov.hEvent);
    req[got] = 0;

    /* Write the reply. */
    len = snprintf(reply, sizeof(reply), "ack:%s", req);
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if(!ov.hEvent)
      return 13;
    if(!WriteFile(ctx->pipe, reply, (DWORD)len, &wrote, &ov)) {
      if(!complete_io(ctx->pipe, &ov, &wrote)) {
        CloseHandle(ov.hEvent);
        return 13;
      }
    }
    CloseHandle(ov.hEvent);
    if(wrote != (DWORD)len)
      return 14;

    /* Returns once the client has read the reply. */
    if(!FlushFileBuffers(ctx->pipe))
      return 15;
    if(!DisconnectNamedPipe(ctx->pipe))
      return 16;
  }
  return 0;
}

static int run(void)
{
  wchar_t name[128];
  wchar_t tail[16];
  struct server_ctx ctx;
  HANDLE thread;
  DWORD tcode = 0;
  int round;

  wcscpy(name, L"\\\\.\\pipe\\curl-corpus-proc-05-");
  put_u(tail, GetCurrentProcessId());
  wcscat(name, tail);

  ctx.pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                              PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                              1, 4096, 4096, 0, NULL);
  if(ctx.pipe == INVALID_HANDLE_VALUE) {
    if(GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
      SKIPF("CreateNamedPipeW not implemented");
    FAILF("CreateNamedPipeW(FILE_FLAG_OVERLAPPED)");
  }

  thread = CreateThread(NULL, 0, server_thread, &ctx, 0, NULL);
  if(!thread) {
    CloseHandle(ctx.pipe);
    FAILF("CreateThread");
  }

  for(round = 0; round < ROUNDS; round++) {
    char req[16];
    char reply[64];
    char expect[32];
    HANDLE cli = INVALID_HANDLE_VALUE;
    DWORD got = 0, wrote = 0;
    int tries;

    snprintf(req, sizeof(req), "req%d", round);
    snprintf(expect, sizeof(expect), "ack:%s", req);

    for(tries = 0; tries < 300; tries++) {
      cli = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                        OPEN_EXISTING, 0, NULL);
      if(cli != INVALID_HANDLE_VALUE)
        break;
      if(GetLastError() != ERROR_PIPE_BUSY && GetLastError() != ERROR_FILE_NOT_FOUND) {
        WaitForSingleObject(thread, 0);
        CloseHandle(thread);
        CloseHandle(ctx.pipe);
        FAILF("client CreateFileW round %d", round);
      }
      /* A server thread that already exited can never accept us: stop early. */
      if(WaitForSingleObject(thread, 0) == WAIT_OBJECT_0)
        break;
      WaitNamedPipeW(name, 50);
      Sleep(10);
    }
    if(cli == INVALID_HANDLE_VALUE) {
      DWORD scode = 0;
      if(WaitForSingleObject(thread, 0) == WAIT_OBJECT_0 &&
         GetExitCodeThread(thread, &scode) && scode != 0) {
        CloseHandle(thread);
        CloseHandle(ctx.pipe);
        FAILF("server thread exited early with code %lu in round %d",
              (unsigned long)scode, round);
      }
      CloseHandle(thread);
      CloseHandle(ctx.pipe);
      FAILF("client could not connect in round %d", round);
    }

    if(!WriteFile(cli, req, (DWORD)strlen(req), &wrote, NULL) ||
       wrote != (DWORD)strlen(req)) {
      CloseHandle(cli);
      CloseHandle(thread);
      CloseHandle(ctx.pipe);
      FAILF("client WriteFile round %d", round);
    }
    if(!ReadFile(cli, reply, sizeof(reply) - 1, &got, NULL)) {
      CloseHandle(cli);
      CloseHandle(thread);
      CloseHandle(ctx.pipe);
      FAILF("client ReadFile round %d", round);
    }
    reply[got] = 0;
    CloseHandle(cli);

    if(strcmp(reply, expect) != 0) {
      CloseHandle(thread);
      CloseHandle(ctx.pipe);
      FAILF("round %d reply \"%s\", expected \"%s\"", round, reply, expect);
    }
  }

  if(WaitForSingleObject(thread, IO_TIMEOUT_MS) != WAIT_OBJECT_0) {
    CloseHandle(thread);
    CloseHandle(ctx.pipe);
    FAILF("server thread did not finish");
  }
  if(!GetExitCodeThread(thread, &tcode)) {
    CloseHandle(thread);
    CloseHandle(ctx.pipe);
    FAILF("GetExitCodeThread");
  }
  CloseHandle(thread);
  CloseHandle(ctx.pipe);
  if(tcode != 0)
    FAILF("server thread exit code %lu, expected 0", (unsigned long)tcode);
  return 0;
}

int main(void)
{
  int rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
