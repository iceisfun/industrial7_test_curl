/*
 * Test: 14_wmain_commandline_argv
 *
 * Purpose: check wide command-line handling end to end. The program is a
 *          wmain() program. With no arguments it is the parent: it builds a
 *          command line with quoting edge cases (non-ASCII text, a space, an
 *          embedded quote after a backslash, an empty argument, a trailing
 *          backslash), parses it with CommandLineToArgvW, then starts itself
 *          with CreateProcessW and checks the argv the child receives through
 *          wmain. The child (argv[1] == "--child") only validates and returns
 *          an exit code, printing nothing.
 *
 * APIs:    wmain (requires -municode), GetModuleFileNameW,
 *          CommandLineToArgvW, LocalFree, CreateProcessW,
 *          WaitForSingleObject, GetExitCodeProcess, CloseHandle,
 *          GetLastError
 *
 * Success: - CommandLineToArgvW on the built command line returns 6 args:
 *            program, --child, "ü€ x", back\"slash, (empty),
 *            tail\
 *          - the child's wmain sees argc == 6 and the same four strings
 *          - the child exits with code 0
 *
 * Source:  curl's Windows argv handling is in src/tool_main.c:150 (wmain,
 *          UNICODE build). The wide argv produced here is what curl's tool
 *          receives when a URL or a -o path contains non-ASCII text.
 *          The CRT argv parsing that wmain uses is not in curl, so the child
 *          run also checks it with the same quoting rules.
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
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define NAME "wmain_commandline_argv"

#define ARG_UMLAUT L"ü€ x"
#define ARG_QUOTE L"back\\\"slash"
#define ARG_EMPTY L""
#define ARG_TAIL L"tail\\"
#define EXPECT_ARGC 6

#define CMD_FMT L"\"%ls\" --child \"ü€ x\" \"back\\\\\\\"slash\" \"\" \"tail\\\\\""

static int child_check(int argc, wchar_t **argv)
{
  if(argc != EXPECT_ARGC)
    return 10;
  if(wcscmp(argv[1], L"--child") != 0)
    return 11;
  if(wcscmp(argv[2], ARG_UMLAUT) != 0)
    return 12;
  if(wcscmp(argv[3], ARG_QUOTE) != 0)
    return 13;
  if(wcscmp(argv[4], ARG_EMPTY) != 0)
    return 14;
  if(wcscmp(argv[5], ARG_TAIL) != 0)
    return 15;
  return 0;
}

int wmain(int argc, wchar_t **argv)
{
  int rc = 0;
  wchar_t self[MAX_PATH];
  wchar_t cmd[1024];
  wchar_t **parsed = NULL;
  int nparsed = 0;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD code = 0, n;
  int have_proc = 0;

  if(argc >= 2 && wcscmp(argv[1], L"--child") == 0)
    return child_check(argc, argv);

  n = GetModuleFileNameW(NULL, self, MAX_PATH);
  if(n == 0 || n >= MAX_PATH) {
    printf("FAIL %s: GetModuleFileNameW failed\n", NAME);
    return 1;
  }

  _snwprintf(cmd, 1024, CMD_FMT, self);
  cmd[1023] = 0;

  /* 1. parse the same command line in the parent */
  parsed = CommandLineToArgvW(cmd, &nparsed);
  if(!parsed) {
    printf("FAIL %s: CommandLineToArgvW failed (%lu)\n", NAME,
           (unsigned long)GetLastError());
    return 1;
  }
  if(nparsed != EXPECT_ARGC) {
    printf("FAIL %s: CommandLineToArgvW returned %d args, expected 6\n",
           NAME, nparsed);
    rc = 1;
    goto out;
  }
  if(wcscmp(parsed[0], self) != 0) {
    printf("FAIL %s: argv[0] '%ls' differs from module path\n", NAME,
           parsed[0]);
    rc = 1;
    goto out;
  }
  if(wcscmp(parsed[1], L"--child") != 0 || wcscmp(parsed[2], ARG_UMLAUT) != 0 ||
     wcscmp(parsed[3], ARG_QUOTE) != 0 || wcscmp(parsed[4], ARG_EMPTY) != 0 ||
     wcscmp(parsed[5], ARG_TAIL) != 0) {
    printf("FAIL %s: CommandLineToArgvW split quoting differently\n", NAME);
    rc = 1;
    goto out;
  }

  /* 2. run the child through the wide CreateProcess path */
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  if(!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    printf("FAIL %s: CreateProcessW failed (%lu)\n", NAME,
           (unsigned long)GetLastError());
    rc = 1;
    goto out;
  }
  have_proc = 1;
  CloseHandle(pi.hThread);

  if(WaitForSingleObject(pi.hProcess, 30000) != WAIT_OBJECT_0) {
    printf("FAIL %s: child did not exit within 30 s\n", NAME);
    rc = 1;
    goto out;
  }
  if(!GetExitCodeProcess(pi.hProcess, &code)) {
    printf("FAIL %s: GetExitCodeProcess failed (%lu)\n", NAME,
           (unsigned long)GetLastError());
    rc = 1;
    goto out;
  }
  if(code != 0) {
    printf("FAIL %s: child argv check failed with code %lu\n", NAME,
           (unsigned long)code);
    rc = 1;
    goto out;
  }

  printf("PASS %s\n", NAME);

out:
  if(have_proc)
    CloseHandle(pi.hProcess);
  if(parsed)
    LocalFree(parsed);
  return rc;
}
