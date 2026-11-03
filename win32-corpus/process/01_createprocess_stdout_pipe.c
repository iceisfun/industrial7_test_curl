/*
 * Test: 01_createprocess_stdout_pipe
 *
 * Purpose: spawn a child process with its stdout and stderr redirected into an
 *   anonymous pipe, read everything the child writes until EOF, and collect
 *   its exit code. This is the basic child-output capture pattern that curl's
 *   test servers and tool helpers rely on when standard handles are inherited.
 *
 * APIs: CreatePipe, SetHandleInformation(HANDLE_FLAG_INHERIT),
 *   GetHandleInformation, CreateFileW("NUL"), GetModuleFileNameW,
 *   CreateProcessW (STARTF_USESTDHANDLES, bInheritHandles=TRUE), ReadFile,
 *   WaitForSingleObject, GetExitCodeProcess, GetProcessId,
 *   GetCurrentProcessId, GetStdHandle, WriteFile (child side).
 *
 * Success means all of the following hold:
 *   - the read end of the pipe is not inheritable, the write end is;
 *   - the child's captured stdout is exactly "stdout-ok <child pid>\n";
 *   - the pid written by the child equals the pid CreateProcessW returned;
 *   - the pipe reaches EOF once the child exits (write ends all closed);
 *   - the child's exit code is exactly 42.
 *
 * Source reference: src/tool_doswin.c:639 (GetStdHandle(STD_OUTPUT_HANDLE)
 *   on the standard output handle) and tests/server/util.c:467 (WriteFile to
 *   GetStdHandle(STD_ERROR_HANDLE)), which both assume standard handles are
 *   valid and writable in the process.
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

#define NAME "createprocess_stdout_pipe"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

#define CHILD_FLAG L"--child-stdout"
#define CHILD_EXIT 42

/* Child mode: write "stdout-ok <pid>\n" to the inherited stdout and exit 42. */
static int child_main(void)
{
  char line[64];
  DWORD written = 0;
  DWORD len;
  HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);

  if(out == NULL || out == INVALID_HANDLE_VALUE)
    return 3;
  snprintf(line, sizeof(line), "stdout-ok %lu\n",
           (unsigned long)GetCurrentProcessId());
  len = (DWORD)strlen(line);
  if(!WriteFile(out, line, len, &written, NULL) || written != len)
    return 4;
  return CHILD_EXIT;
}

static int run(void)
{
  wchar_t exe[MAX_PATH * 4];
  wchar_t cmd[MAX_PATH * 4 + 64];
  SECURITY_ATTRIBUTES sa;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  HANDLE rd = NULL, wr = NULL, nul = INVALID_HANDLE_VALUE;
  DWORD flags = 0;
  DWORD code = 0;
  DWORD n;
  char buf[256];
  char expect[64];
  DWORD total = 0;

  n = GetModuleFileNameW(NULL, exe, (DWORD)(sizeof(exe) / sizeof(exe[0])));
  if(n == 0 || n >= sizeof(exe) / sizeof(exe[0]))
    FAILF("GetModuleFileNameW");

  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  if(!CreatePipe(&rd, &wr, &sa, 0))
    FAILF("CreatePipe");

  if(!SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0))
    FAILF("SetHandleInformation(read end, 0)");

  if(!GetHandleInformation(rd, &flags))
    FAILF("GetHandleInformation(read end)");
  if(flags & HANDLE_FLAG_INHERIT)
    FAILF("read end still inheritable (flags=0x%lx)", (unsigned long)flags);

  if(!GetHandleInformation(wr, &flags))
    FAILF("GetHandleInformation(write end)");
  if(!(flags & HANDLE_FLAG_INHERIT))
    FAILF("write end is not inheritable (flags=0x%lx)", (unsigned long)flags);

  nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
  if(nul == INVALID_HANDLE_VALUE)
    FAILF("CreateFileW(NUL)");

  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = nul;
  si.hStdOutput = wr;
  si.hStdError = wr;

  wcscpy(cmd, L"\"");
  wcscat(cmd, exe);
  wcscat(cmd, L"\" " CHILD_FLAG);

  memset(&pi, 0, sizeof(pi));
  if(!CreateProcessW(exe, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                     NULL, NULL, &si, &pi))
    FAILF("CreateProcessW");

  /* The parent must drop its copy of the write end, otherwise EOF never comes. */
  CloseHandle(wr);
  wr = NULL;
  CloseHandle(nul);
  nul = INVALID_HANDLE_VALUE;
  CloseHandle(pi.hThread);

  if(GetProcessId(pi.hProcess) != pi.dwProcessId)
    FAILF("GetProcessId(child)=%lu != CreateProcessW dwProcessId=%lu",
          (unsigned long)GetProcessId(pi.hProcess),
          (unsigned long)pi.dwProcessId);

  for(;;) {
    DWORD got = 0;
    if(total >= sizeof(buf) - 1)
      break;
    if(!ReadFile(rd, buf + total, (DWORD)(sizeof(buf) - 1 - total), &got, NULL)) {
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
    FAILF("WaitForSingleObject(child) did not signal");
  if(!GetExitCodeProcess(pi.hProcess, &code))
    FAILF("GetExitCodeProcess");
  CloseHandle(pi.hProcess);
  CloseHandle(rd);

  snprintf(expect, sizeof(expect), "stdout-ok %lu\n", (unsigned long)pi.dwProcessId);
  if(strcmp(buf, expect) != 0)
    FAILF("child stdout was \"%s\", expected \"%s\"", buf, expect);
  if(code != CHILD_EXIT)
    FAILF("child exit code %lu, expected %d", (unsigned long)code, CHILD_EXIT);

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
