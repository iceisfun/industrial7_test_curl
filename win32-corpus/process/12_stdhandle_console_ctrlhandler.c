/*
 * Test: 12_stdhandle_console_ctrlhandler
 *
 * Purpose: check the standard-handle and console APIs that curl's Windows
 *   tool uses to decide whether output is a terminal and to install a
 *   console-control handler. Covers GetStdHandle, SetStdHandle (swap the
 *   STD_ERROR_HANDLE to a pipe and restore it), GetConsoleMode consistency
 *   against _isatty, a pipe handle that must NOT look like a console, and
 *   SetConsoleCtrlHandler install/remove. The control event is never raised,
 *   so no other process on a shared console is affected.
 *
 * APIs: GetStdHandle, SetStdHandle, GetConsoleMode, GetFileType,
 *   SetConsoleCtrlHandler, CreatePipe, CloseHandle, _fileno, _isatty,
 *   _open_osfhandle, _close.
 *
 * Success means: if GetConsoleMode(stdout) succeeds then _isatty(stdout) is
 *   non-zero, and if it fails then _isatty(stdout) is 0 (the two views agree);
 *   GetConsoleMode on a pipe handle fails and GetFileType is FILE_TYPE_PIPE;
 *   _isatty on a CRT fd wrapping that pipe is 0; SetStdHandle(STD_ERROR_HANDLE)
 *   is observable via GetStdHandle and can be restored; SetConsoleCtrlHandler
 *   installs and removes a handler and returns TRUE both times.
 *
 * Source reference: src/tool_doswin.c:639 (GetStdHandle(STD_OUTPUT_HANDLE)
 *   fed into GetConsoleMode), src/tool_doswin.c:661 (SetConsoleCtrlHandler
 *   (signal_handler, TRUE)) and src/tool_doswin.c:669 (removal on failure),
 *   and src/tool_operate.c:1358 (stream_isatty).
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
#include <io.h>
#include <fcntl.h>
#include <stdint.h>

#define NAME "stdhandle_console_ctrlhandler"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

static BOOL WINAPI test_ctrl_handler(DWORD type)
{
  (void)type;
  return FALSE;  /* not handled: let the default handler run */
}

static int run(void)
{
  HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  HANDLE orig_err, rd = NULL, wr = NULL, got;
  DWORD mode = 0;
  BOOL con;
  int tty, fd;

  if(out == NULL || out == INVALID_HANDLE_VALUE)
    SKIPF("no standard output handle in this process");

  /* 1. GetConsoleMode and _isatty must agree on stdout. */
  SetLastError(0);
  con = GetConsoleMode(out, &mode);
  tty = _isatty(_fileno(stdout));
  if(con && !tty)
    FAILF("GetConsoleMode(stdout) succeeded but _isatty(stdout) is 0");
  if(!con && tty)
    FAILF("_isatty(stdout) is non-zero but GetConsoleMode(stdout) failed");

  /* 2. A pipe is not a console: GetConsoleMode fails, GetFileType is PIPE. */
  if(!CreatePipe(&rd, &wr, NULL, 0))
    FAILF("CreatePipe");
  if(GetConsoleMode(rd, &mode))
    FAILF("GetConsoleMode succeeded on a pipe read end");
  if(GetFileType(rd) != FILE_TYPE_PIPE)
    FAILF("GetFileType(pipe read end) is not FILE_TYPE_PIPE");

  fd = _open_osfhandle((intptr_t)rd, _O_RDONLY);
  if(fd < 0)
    FAILF("_open_osfhandle(pipe read end)");
  if(_isatty(fd) != 0) {
    _close(fd);
    FAILF("_isatty(pipe-backed fd) reports a terminal");
  }
  _close(fd);  /* closes rd */
  rd = NULL;
  CloseHandle(wr);
  wr = NULL;

  /* 3. SetStdHandle is observable through GetStdHandle and can be restored. */
  if(!CreatePipe(&rd, &wr, NULL, 0))
    FAILF("CreatePipe(second)");
  orig_err = GetStdHandle(STD_ERROR_HANDLE);
  if(!SetStdHandle(STD_ERROR_HANDLE, wr))
    FAILF("SetStdHandle(STD_ERROR_HANDLE, pipe)");
  got = GetStdHandle(STD_ERROR_HANDLE);
  if(got != wr) {
    SetStdHandle(STD_ERROR_HANDLE, orig_err);
    FAILF("GetStdHandle(STD_ERROR_HANDLE) does not return the value set");
  }
  if(!SetStdHandle(STD_ERROR_HANDLE, orig_err))
    FAILF("SetStdHandle restore");
  if(GetStdHandle(STD_ERROR_HANDLE) != orig_err)
    FAILF("GetStdHandle after restore differs from original");

  CloseHandle(rd);
  CloseHandle(wr);

  /* 4. Install and remove a console control handler. */
  if(!SetConsoleCtrlHandler(test_ctrl_handler, TRUE))
    FAILF("SetConsoleCtrlHandler(install)");
  if(!SetConsoleCtrlHandler(test_ctrl_handler, FALSE))
    FAILF("SetConsoleCtrlHandler(remove)");

  return 0;
}

int main(void)
{
  int rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
