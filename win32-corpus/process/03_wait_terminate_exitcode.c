/*
 * Test: 03_wait_terminate_exitcode
 *
 * Purpose: exercise the process lifecycle calls that curl relies on when it
 *   spawns helper processes (test servers, ssh helpers) and has to reap or kill
 *   them. Phase 1 spawns a child that exits quickly with code 7 and checks the
 *   exit code. Phase 2 spawns a child that sleeps for a long time and checks
 *   that WaitForSingleObject times out while it is alive (STILL_ACTIVE), then
 *   calls TerminateProcess and verifies the exit code it was given.
 *
 * APIs: CreateProcessW, WaitForSingleObject (timeout and INFINITE-style
 *   success), GetExitCodeProcess, TerminateProcess, GetProcessId,
 *   GetCurrentProcessId, GetModuleFileNameW.
 *
 * Success means: phase 1 exit code is 7; phase 2 WaitForSingleObject(0 ms)
 *   returns WAIT_TIMEOUT, GetExitCodeProcess reports STILL_ACTIVE (259), after
 *   TerminateProcess(123) the wait returns WAIT_OBJECT_0 and the exit code is
 *   123. The child is always one we spawned; nothing else is terminated.
 *
 * Source reference: lib/curl_threads.c:57 (WaitForSingleObjectEx on a thread
 *   handle with a WAIT_OBJECT_0 check, then CloseHandle) and
 *   tests/server/sockfilt.c:771 (WaitForSingleObjectEx on spawned worker
 *   handles followed by CloseHandle), the same wait-and-reap idiom.
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

#define NAME "wait_terminate_exitcode"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

#define CHILD_EXIT7 L"--child-exit7"
#define CHILD_SLEEP L"--child-sleep"

static int child_main(void)
{
  if(wcsstr(GetCommandLineW(), CHILD_SLEEP)) {
    Sleep(120000);  /* parent must terminate us long before this */
    return 0;
  }
  return 7;
}

static int spawn(const wchar_t *exe, const wchar_t *flag, PROCESS_INFORMATION *pi)
{
  wchar_t cmd[MAX_PATH * 4 + 64];
  STARTUPINFOW si;

  wcscpy(cmd, L"\"");
  wcscat(cmd, exe);
  wcscat(cmd, L"\" ");
  wcscat(cmd, flag);

  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(pi, 0, sizeof(*pi));
  return CreateProcessW(exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, pi);
}

static int run(void)
{
  wchar_t exe[MAX_PATH * 4];
  PROCESS_INFORMATION pi;
  DWORD code = 0;
  DWORD n;

  n = GetModuleFileNameW(NULL, exe, (DWORD)(sizeof(exe) / sizeof(exe[0])));
  if(n == 0 || n >= sizeof(exe) / sizeof(exe[0]))
    FAILF("GetModuleFileNameW");

  /* Phase 1: normal exit and exit code retrieval. */
  if(!spawn(exe, CHILD_EXIT7, &pi))
    FAILF("CreateProcessW(exit7)");
  CloseHandle(pi.hThread);
  if(WaitForSingleObject(pi.hProcess, 30000) != WAIT_OBJECT_0)
    FAILF("WaitForSingleObject(exit7 child)");
  if(!GetExitCodeProcess(pi.hProcess, &code))
    FAILF("GetExitCodeProcess(exit7 child)");
  if(code != 7)
    FAILF("exit7 child code %lu, expected 7", (unsigned long)code);
  CloseHandle(pi.hProcess);

  /* Phase 2: a live child must not be reported as finished. */
  if(!spawn(exe, CHILD_SLEEP, &pi))
    FAILF("CreateProcessW(sleep)");
  CloseHandle(pi.hThread);

  /* Any failure below must not leave the sleeping child running. */
  if(GetProcessId(pi.hProcess) != pi.dwProcessId) {
    TerminateProcess(pi.hProcess, 124);
    FAILF("GetProcessId mismatch for sleep child");
  }
  if(pi.dwProcessId == GetCurrentProcessId()) {
    TerminateProcess(pi.hProcess, 124);
    FAILF("child pid equals parent pid");
  }

  if(WaitForSingleObject(pi.hProcess, 100) != WAIT_TIMEOUT) {
    TerminateProcess(pi.hProcess, 124);
    FAILF("live child did not time out in WaitForSingleObject");
  }
  if(!GetExitCodeProcess(pi.hProcess, &code)) {
    TerminateProcess(pi.hProcess, 124);
    FAILF("GetExitCodeProcess(live child)");
  }
  if(code != STILL_ACTIVE) {
    TerminateProcess(pi.hProcess, 124);
    FAILF("live child exit code %lu, expected STILL_ACTIVE (259)",
          (unsigned long)code);
  }

  if(!TerminateProcess(pi.hProcess, 123)) {
    TerminateProcess(pi.hProcess, 124);
    FAILF("TerminateProcess(sleep child)");
  }
  if(WaitForSingleObject(pi.hProcess, 10000) != WAIT_OBJECT_0)
    FAILF("terminated child did not signal");
  if(!GetExitCodeProcess(pi.hProcess, &code))
    FAILF("GetExitCodeProcess(terminated child)");
  if(code != 123)
    FAILF("terminated child code %lu, expected 123", (unsigned long)code);

  /* Waiting on an already-finished process returns immediately. */
  if(WaitForSingleObject(pi.hProcess, 0) != WAIT_OBJECT_0)
    FAILF("second wait on finished child did not signal");
  CloseHandle(pi.hProcess);

  return 0;
}

int main(void)
{
  int rc;

  if(wcsstr(GetCommandLineW(), CHILD_EXIT7) || wcsstr(GetCommandLineW(), CHILD_SLEEP))
    return child_main();

  rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
