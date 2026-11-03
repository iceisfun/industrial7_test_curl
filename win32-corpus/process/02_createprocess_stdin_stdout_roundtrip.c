/*
 * Test: 02_createprocess_stdin_stdout_roundtrip
 *
 * Purpose: drive a child process over two redirected pipes: the parent writes
 *   data into the child's stdin, closes its write end to signal EOF, and reads
 *   the transformed data the child produces on stdout. This covers the full
 *   bidirectional std-handle redirection used by helper processes, including
 *   the requirement that the child sees a pipe on stdin and gets EOF (broken
 *   pipe) once the parent closes its write end.
 *
 * APIs: CreatePipe (x2), SetHandleInformation(HANDLE_FLAG_INHERIT),
 *   GetHandleInformation, CreateFileW("NUL"), CreateProcessW with
 *   STARTF_USESTDHANDLES, WriteFile, ReadFile, GetFileType, GetStdHandle,
 *   WaitForSingleObject, GetExitCodeProcess.
 *
 * Success means: the parent-side ends (in_wr, out_rd) are not inheritable and
 *   the child-side ends are; the child reports GetFileType(stdin)==
 *   FILE_TYPE_PIPE and exits 0; the output is exactly "ABC DEF\nGHI\n".
 *
 * Source reference: src/tool_doswin.c:922 (DuplicateHandle of
 *   GetStdHandle(STD_INPUT_HANDLE)) and lib/telnet.c:1277 (GetStdHandle
 *   (STD_INPUT_HANDLE) taken as the stdin source), both of which need the
 *   standard input handle to be a valid, readable handle.
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

#define NAME "createprocess_stdin_stdout_roundtrip"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

#define CHILD_FLAG L"--child-upper"

static const char input[] = "abc def\nghi\n";
static const char expect[] = "ABC DEF\nGHI\n";

/* Child mode: copy stdin to stdout uppercased until EOF. */
static int child_main(void)
{
  char buf[128];
  DWORD n = 0, w = 0;
  DWORD i;
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);

  if(in == NULL || in == INVALID_HANDLE_VALUE)
    return 3;
  if(out == NULL || out == INVALID_HANDLE_VALUE)
    return 3;
  if(GetFileType(in) != FILE_TYPE_PIPE)
    return 6;

  for(;;) {
    if(!ReadFile(in, buf, sizeof(buf), &n, NULL)) {
      if(GetLastError() == ERROR_BROKEN_PIPE)
        break;  /* parent closed its write end: EOF */
      return 4;
    }
    if(n == 0)
      break;
    for(i = 0; i < n; i++) {
      if(buf[i] >= 'a' && buf[i] <= 'z')
        buf[i] = (char)(buf[i] - 'a' + 'A');
    }
    if(!WriteFile(out, buf, n, &w, NULL) || w != n)
      return 5;
  }
  return 0;
}

static int run(void)
{
  wchar_t exe[MAX_PATH * 4];
  wchar_t cmd[MAX_PATH * 4 + 64];
  SECURITY_ATTRIBUTES sa;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  HANDLE in_rd = NULL, in_wr = NULL, out_rd = NULL, out_wr = NULL;
  HANDLE nul = INVALID_HANDLE_VALUE;
  DWORD flags = 0, n, w = 0, code = 0, total = 0;
  char buf[256];

  n = GetModuleFileNameW(NULL, exe, (DWORD)(sizeof(exe) / sizeof(exe[0])));
  if(n == 0 || n >= sizeof(exe) / sizeof(exe[0]))
    FAILF("GetModuleFileNameW");

  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  if(!CreatePipe(&in_rd, &in_wr, &sa, 0))
    FAILF("CreatePipe(stdin)");
  if(!CreatePipe(&out_rd, &out_wr, &sa, 0))
    FAILF("CreatePipe(stdout)");

  /* Parent-only ends must not leak into the child. */
  if(!SetHandleInformation(in_wr, HANDLE_FLAG_INHERIT, 0))
    FAILF("SetHandleInformation(in_wr)");
  if(!SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0))
    FAILF("SetHandleInformation(out_rd)");

  if(!GetHandleInformation(in_wr, &flags) || (flags & HANDLE_FLAG_INHERIT))
    FAILF("in_wr still inheritable (flags=0x%lx)", (unsigned long)flags);
  if(!GetHandleInformation(out_rd, &flags) || (flags & HANDLE_FLAG_INHERIT))
    FAILF("out_rd still inheritable (flags=0x%lx)", (unsigned long)flags);
  if(!GetHandleInformation(in_rd, &flags) || !(flags & HANDLE_FLAG_INHERIT))
    FAILF("in_rd not inheritable (flags=0x%lx)", (unsigned long)flags);
  if(!GetHandleInformation(out_wr, &flags) || !(flags & HANDLE_FLAG_INHERIT))
    FAILF("out_wr not inheritable (flags=0x%lx)", (unsigned long)flags);

  nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
  if(nul == INVALID_HANDLE_VALUE)
    FAILF("CreateFileW(NUL)");

  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = in_rd;
  si.hStdOutput = out_wr;
  si.hStdError = nul;

  wcscpy(cmd, L"\"");
  wcscat(cmd, exe);
  wcscat(cmd, L"\" " CHILD_FLAG);

  memset(&pi, 0, sizeof(pi));
  if(!CreateProcessW(exe, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                     NULL, NULL, &si, &pi))
    FAILF("CreateProcessW");

  /* Close child-side ends in the parent so EOF propagates correctly. */
  CloseHandle(in_rd);
  in_rd = NULL;
  CloseHandle(out_wr);
  out_wr = NULL;
  CloseHandle(nul);
  nul = INVALID_HANDLE_VALUE;
  CloseHandle(pi.hThread);

  if(!WriteFile(in_wr, input, (DWORD)(sizeof(input) - 1), &w, NULL))
    FAILF("WriteFile(child stdin)");
  if(w != sizeof(input) - 1)
    FAILF("short write to child stdin: %lu", (unsigned long)w);
  CloseHandle(in_wr);  /* EOF for the child */
  in_wr = NULL;

  for(;;) {
    DWORD got = 0;
    if(total >= sizeof(buf) - 1)
      break;
    if(!ReadFile(out_rd, buf + total, (DWORD)(sizeof(buf) - 1 - total), &got, NULL)) {
      if(GetLastError() == ERROR_BROKEN_PIPE)
        break;
      FAILF("ReadFile(child stdout)");
    }
    if(got == 0)
      break;
    total += got;
  }
  buf[total] = 0;

  if(WaitForSingleObject(pi.hProcess, 30000) != WAIT_OBJECT_0)
    FAILF("child did not exit after stdin EOF");
  if(!GetExitCodeProcess(pi.hProcess, &code))
    FAILF("GetExitCodeProcess");
  CloseHandle(pi.hProcess);
  CloseHandle(out_rd);

  if(code != 0)
    FAILF("child exit code %lu, expected 0", (unsigned long)code);
  if(strcmp(buf, expect) != 0)
    FAILF("child output \"%s\", expected \"%s\"", buf, expect);

  return 0;
}

int main(void)
{
  int rc;

  if(wcsstr(GetCommandLineW(), CHILD_FLAG))
    return child_main();

  rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
