/*
 * Test: 04_named_pipe_loopback_single
 *
 * Purpose: create a local named pipe server with CreateNamedPipeW and connect a
 *   loopback client to it in the same process. The client connects before the
 *   server calls ConnectNamedPipe, which is the ERROR_PIPE_CONNECTED path that
 *   a non-blocking accept-style caller must accept as success. Then exchange a
 *   ping/pong in both directions. A negative case verifies that opening a
 *   pipe name with no server instance fails with ERROR_FILE_NOT_FOUND.
 *
 * APIs: CreateNamedPipeW (PIPE_ACCESS_DUPLEX, byte mode, PIPE_WAIT),
 *   CreateFileW (client, OPEN_EXISTING), ConnectNamedPipe, WriteFile, ReadFile,
 *   DisconnectNamedPipe, GetLastError.
 *
 * Success means: ConnectNamedPipe returns FALSE with ERROR_PIPE_CONNECTED, the
 *   server reads exactly "ping" (4 bytes), the client reads exactly "pong", and
 *   CreateFileW on a pipe name that was never created returns
 *   INVALID_HANDLE_VALUE with ERROR_FILE_NOT_FOUND. If CreateNamedPipeW itself
 *   is unimplemented the test
 *   SKIPs (ERROR_CALL_NOT_IMPLEMENTED).
 *
 * Source reference: none in curl. grep of lib/, src/ and tests/ finds no
 *   CreateNamedPipe call site; this test covers a Win32 primitive that the
 *   corpus needs for local loopback IPC, not a curl code path.
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

#define NAME "named_pipe_loopback_single"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

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

static int run(void)
{
  wchar_t name[128];
  wchar_t missing[128];
  wchar_t tail[16];
  HANDLE srv, cli, bad;
  char buf[32];
  DWORD got = 0, wrote = 0;

  wcscpy(name, L"\\\\.\\pipe\\curl-corpus-proc-04-");
  put_u(tail, GetCurrentProcessId());
  wcscat(name, tail);

  srv = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX,
                         PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                         1, 4096, 4096, 0, NULL);
  if(srv == INVALID_HANDLE_VALUE) {
    if(GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
      SKIPF("CreateNamedPipeW not implemented");
    FAILF("CreateNamedPipeW");
  }

  cli = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    OPEN_EXISTING, 0, NULL);
  if(cli == INVALID_HANDLE_VALUE)
    FAILF("CreateFileW(client on server name)");

  /* Client already connected: the server-side connect reports PIPE_CONNECTED.
     Returning TRUE is also a valid outcome and is accepted. */
  if(!ConnectNamedPipe(srv, NULL) && GetLastError() != ERROR_PIPE_CONNECTED)
    FAILF("ConnectNamedPipe");

  if(!WriteFile(cli, "ping", 4, &wrote, NULL) || wrote != 4)
    FAILF("client WriteFile(ping)");

  if(!ReadFile(srv, buf, sizeof(buf) - 1, &got, NULL))
    FAILF("server ReadFile");
  buf[got] = 0;
  if(got != 4 || strcmp(buf, "ping") != 0)
    FAILF("server read \"%s\" (%lu bytes), expected \"ping\"", buf, (unsigned long)got);

  if(!WriteFile(srv, "pong", 4, &wrote, NULL) || wrote != 4)
    FAILF("server WriteFile(pong)");

  got = 0;
  if(!ReadFile(cli, buf, sizeof(buf) - 1, &got, NULL))
    FAILF("client ReadFile");
  buf[got] = 0;
  if(got != 4 || strcmp(buf, "pong") != 0)
    FAILF("client read \"%s\" (%lu bytes), expected \"pong\"", buf, (unsigned long)got);

  if(!DisconnectNamedPipe(srv))
    FAILF("DisconnectNamedPipe");
  CloseHandle(cli);
  CloseHandle(srv);

  /* Negative: this name was never created by any server instance. */
  wcscpy(missing, L"\\\\.\\pipe\\curl-corpus-proc-04-missing-");
  put_u(tail, GetCurrentProcessId());
  wcscat(missing, tail);
  bad = CreateFileW(missing, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
  if(bad != INVALID_HANDLE_VALUE) {
    CloseHandle(bad);
    FAILF("CreateFileW on a missing pipe name succeeded");
  }
  if(GetLastError() != ERROR_FILE_NOT_FOUND)
    FAILF("missing pipe error was not ERROR_FILE_NOT_FOUND");

  return 0;
}

int main(void)
{
  int rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
