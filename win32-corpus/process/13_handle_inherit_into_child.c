/*
 * Test: 13_handle_inherit_into_child
 *
 * Purpose: verify that handle inheritance across CreateProcessW is controlled
 *   by both HANDLE_FLAG_INHERIT (set with SetHandleInformation) and the
 *   bInheritHandles argument. The parent passes the numeric value of an event
 *   handle to a child, and the child tries SetEvent on it. Four cases:
 *     A. inheritable handle, bInheritHandles=TRUE: child can signal it.
 *     B. non-inheritable handle, bInheritHandles=TRUE: child cannot use it.
 *     C. inheritable flag cleared with SetHandleInformation: child cannot use it.
 *     D. inheritable handle, bInheritHandles=FALSE: child cannot use it.
 *   This is the mechanism by which curl's parent process hands pipes and
 *   sockets to helper processes without leaking the rest.
 *
 * APIs: CreateEventW, SetHandleInformation, GetHandleInformation,
 *   CreateProcessW (bInheritHandles TRUE/FALSE), WaitForSingleObject,
 *   GetExitCodeProcess, SetEvent (child), GetCommandLineW, wcsstr, wcstoull,
 *   wcstoul.
 *
 * Success means: case A child exits 0 and the parent observes the event
 *   signalled by the child; cases B, C and D children exit 0 (SetEvent failed
 *   with the handle invalid in the child) and the event stays unsignalled in
 *   the parent.
 *
 * Source reference: src/tool_doswin.c:922 (DuplicateHandle of the stdin handle
 *   via GetCurrentProcess, the same handle-copy step this test performs with
 *   CreateProcessW inheritance) and tests/server/util.c:629 (WaitForSingleObjectEx
 *   on a thread-owned handle, the handle wait style used when handing work to
 *   another thread or process).
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
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdint.h>

#define NAME "handle_inherit_into_child"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

#define CHILD_FLAG L"--child-check"

/*
 * Child mode: argv is "--child-check <handle> <expect>".
 *   expect=1: SetEvent must succeed on the inherited handle, else exit 2.
 *   expect=0: SetEvent must fail on the handle value (not inherited), else 3.
 */
static int child_main(const wchar_t *cl)
{
  const wchar_t *p = wcsstr(cl, CHILD_FLAG);
  wchar_t *end = NULL;
  unsigned long long h;
  unsigned long expect;
  BOOL ok;

  if(!p)
    return 9;
  p += wcslen(CHILD_FLAG);
  h = wcstoull(p, &end, 10);
  expect = wcstoul(end, &end, 10);

  ok = SetEvent((HANDLE)(uintptr_t)h);
  if(expect)
    return ok ? 0 : 2;
  return ok ? 3 : 0;
}

static void put_u(wchar_t *dst, unsigned long long v)
{
  wchar_t tmp[32];
  size_t n = 0, i;
  do {
    tmp[n++] = (wchar_t)(L'0' + (v % 10));
    v /= 10;
  } while(v);
  for(i = 0; i < n; i++)
    dst[i] = tmp[n - 1 - i];
  dst[n] = 0;
}

/* Spawn the child with the handle value and expectation; returns child exit code via *code. */
static int run_child(const wchar_t *exe, HANDLE h, int expect, BOOL inherit, DWORD *code)
{
  wchar_t cmd[2048];
  size_t len;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;

  wcscpy(cmd, L"\"");
  wcscat(cmd, exe);
  wcscat(cmd, L"\" " CHILD_FLAG L" ");
  len = wcslen(cmd);
  put_u(cmd + len, (unsigned long long)(uintptr_t)h);
  len = wcslen(cmd);
  cmd[len++] = L' ';
  put_u(cmd + len, expect ? 1ULL : 0ULL);

  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  if(!CreateProcessW(exe, cmd, NULL, NULL, inherit, CREATE_NO_WINDOW,
                     NULL, NULL, &si, &pi))
    return 0;
  CloseHandle(pi.hThread);
  if(WaitForSingleObject(pi.hProcess, 20000) != WAIT_OBJECT_0) {
    CloseHandle(pi.hProcess);
    return 0;
  }
  if(!GetExitCodeProcess(pi.hProcess, code)) {
    CloseHandle(pi.hProcess);
    return 0;
  }
  CloseHandle(pi.hProcess);
  return 1;
}

static int run(void)
{
  wchar_t exe[MAX_PATH * 4];
  SECURITY_ATTRIBUTES sa;
  HANDLE inh, priv;
  DWORD flags = 0, code = 0;
  DWORD n;

  n = GetModuleFileNameW(NULL, exe, (DWORD)(sizeof(exe) / sizeof(exe[0])));
  if(n == 0 || n >= sizeof(exe) / sizeof(exe[0]))
    FAILF("GetModuleFileNameW");

  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  inh = CreateEventW(&sa, TRUE, FALSE, NULL);
  if(!inh)
    FAILF("CreateEventW(inheritable)");
  priv = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!priv)
    FAILF("CreateEventW(private)");

  if(!GetHandleInformation(inh, &flags) || !(flags & HANDLE_FLAG_INHERIT))
    FAILF("inheritable event lacks HANDLE_FLAG_INHERIT");
  if(!GetHandleInformation(priv, &flags) || (flags & HANDLE_FLAG_INHERIT))
    FAILF("private event has HANDLE_FLAG_INHERIT");

  /* A: inheritable + bInheritHandles=TRUE -> child signals it. */
  if(!run_child(exe, inh, 1, TRUE, &code))
    FAILF("case A: could not run child");
  if(code != 0)
    FAILF("case A: child exit %lu, expected 0 (SetEvent on inherited handle)",
          (unsigned long)code);
  if(WaitForSingleObject(inh, 10000) != WAIT_OBJECT_0)
    FAILF("case A: parent did not observe the child's SetEvent");
  ResetEvent(inh);

  /* B: a non-inheritable handle must not be usable in the child. */
  if(!run_child(exe, priv, 0, TRUE, &code))
    FAILF("case B: could not run child");
  if(code != 0)
    FAILF("case B: child exit %lu, expected 0 (private handle must be invalid there)",
          (unsigned long)code);
  if(WaitForSingleObject(priv, 0) != WAIT_TIMEOUT)
    FAILF("case B: private event was signalled by the child");

  /* C: clear HANDLE_FLAG_INHERIT on the inheritable handle. */
  if(!SetHandleInformation(inh, HANDLE_FLAG_INHERIT, 0))
    FAILF("SetHandleInformation(inh, 0)");
  if(!run_child(exe, inh, 0, TRUE, &code))
    FAILF("case C: could not run child");
  if(code != 0)
    FAILF("case C: child exit %lu, expected 0 (inherit flag cleared)",
          (unsigned long)code);
  if(WaitForSingleObject(inh, 0) != WAIT_TIMEOUT)
    FAILF("case C: event signalled despite cleared inherit flag");

  /* D: inheritable handle, but bInheritHandles=FALSE. */
  if(!SetHandleInformation(inh, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    FAILF("SetHandleInformation(inh, INHERIT)");
  if(!run_child(exe, inh, 0, FALSE, &code))
    FAILF("case D: could not run child");
  if(code != 0)
    FAILF("case D: child exit %lu, expected 0 (bInheritHandles=FALSE)",
          (unsigned long)code);
  if(WaitForSingleObject(inh, 0) != WAIT_TIMEOUT)
    FAILF("case D: event signalled despite bInheritHandles=FALSE");

  CloseHandle(inh);
  CloseHandle(priv);
  return 0;
}

int main(void)
{
  int rc;

  if(wcsstr(GetCommandLineW(), CHILD_FLAG))
    return child_main(GetCommandLineW());

  rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
