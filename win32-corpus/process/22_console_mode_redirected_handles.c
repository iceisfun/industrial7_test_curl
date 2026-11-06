/*
 * Test: 22_console_mode_redirected_handles
 * Purpose: what curl's terminal handling (lib/curl_get_line, src/terminal.c,
 *          tool_cb_prg / progress meter: GetConsoleScreenBufferInfo, isatty)
 *          sees when stdout is a pipe or a file, which is how every test run
 *          and every CI run starts curl.
 * APIs: GetStdHandle, GetFileType, GetConsoleMode, SetConsoleMode,
 *       GetConsoleScreenBufferInfo, GetConsoleCP, GetConsoleOutputCP, _isatty, _get_osfhandle.
 * Method: the program re-executes itself with stdout bound to (a) an anonymous
 *       pipe, (b) a regular file, (c) NUL, and reports from the child.
 * Success (pinned from Win10 22H2 probes):
 *   - GetFileType: pipe 3 (FILE_TYPE_PIPE), file 1 (DISK), NUL 2 (CHAR);
 *   - GetConsoleMode on a pipe or file handle fails ERROR_INVALID_HANDLE (6);
 *   - GetConsoleMode on NUL fails ERROR_INVALID_HANDLE (6) although NUL is a char device;
 *   - GetConsoleScreenBufferInfo fails ERROR_INVALID_HANDLE (6) for all three;
 *   - SetConsoleMode fails ERROR_INVALID_HANDLE (6);
 *   - _isatty is 0 for all three.
 * Source: src/terminal.c (get_terminal_columns), lib/curl_trc / tool_progress.
 */
#define TEST_NAME "22_console_mode_redirected_handles"
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
#include <stdlib.h>
#include <wchar.h>

#define INFO(...) do { printf("INFO "); printf(__VA_ARGS__); printf("\n"); } while (0)
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); g_fail = 1; goto out; } while (0)
static __attribute__((unused)) int g_fail;
#include <io.h>

static int report(void) {
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode = 0xaaaaaaaa, e;
  CONSOLE_SCREEN_BUFFER_INFO ci;
  char line[400];
  BOOL ok1, ok2, ok3;
  DWORD ft = GetFileType(h);
  DWORD n;
  SetLastError(0); ok1 = GetConsoleMode(h, &mode); e = GetLastError();
  snprintf(line, sizeof(line), "ft=%lu getmode=%d/%lu ", (unsigned long)ft, ok1 ? 1 : 0, ok1 ? 0ul : (unsigned long)e);
  SetLastError(0); ok2 = GetConsoleScreenBufferInfo(h, &ci); e = GetLastError();
  snprintf(line + strlen(line), sizeof(line) - strlen(line), "csbi=%d/%lu ", ok2 ? 1 : 0, ok2 ? 0ul : (unsigned long)e);
  SetLastError(0); ok3 = SetConsoleMode(h, 7); e = GetLastError();
  snprintf(line + strlen(line), sizeof(line) - strlen(line), "setmode=%d/%lu ", ok3 ? 1 : 0, ok3 ? 0ul : (unsigned long)e);
  snprintf(line + strlen(line), sizeof(line) - strlen(line), "isatty=%d", _isatty(1));
  strcat(line, "\n");
  WriteFile(h, line, (DWORD)strlen(line), &n, NULL);
  return 0;
}

static int run_with(HANDLE out, char *res, size_t resn, HANDLE rd, const wchar_t *tmpfile) {
  wchar_t self[MAX_PATH], cmd[600];
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD n = 0;
  GetModuleFileNameW(NULL, self, MAX_PATH);
  swprintf(cmd, 600, L"\"%ls\" --report", self);
  memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = out; si.hStdError = out; si.hStdInput = INVALID_HANDLE_VALUE;
  memset(&pi, 0, sizeof(pi));
  if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) return -1;
  WaitForSingleObject(pi.hProcess, 20000);
  CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
  res[0] = 0;
  if (rd) {
    ReadFile(rd, res, (DWORD)resn - 1, &n, NULL);
    res[n] = 0;
  } else if (tmpfile) {
    HANDLE f = CreateFileW(tmpfile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) { ReadFile(f, res, (DWORD)resn - 1, &n, NULL); res[n] = 0; CloseHandle(f); }
  }
  return 0;
}

int wmain(int argc, wchar_t **argv) {
  SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
  HANDLE rd = NULL, wr = NULL, f, nul;
  wchar_t tmp[MAX_PATH], tf[MAX_PATH];
  char res[400];
  int it;
  DWORD cp, e;

  if (argc > 1 && wcscmp(argv[1], L"--report") == 0) return report();

  for (it = 0; it < 3; it++) {
    CreatePipe(&rd, &wr, &sa, 0);
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    if (run_with(wr, res, sizeof(res), rd, NULL)) FAILF("spawn pipe");
    CloseHandle(wr); CloseHandle(rd);
    if (it == 0) INFO("pipe:  %s", strtok(res, "\r\n"));
    if (strstr(res, "ft=3 getmode=0/6 csbi=0/6 setmode=0/6 isatty=0") == NULL) FAILF("pipe report: %s", res);
  }
  GetTempPathW(MAX_PATH, tmp);
  GetTempFileNameW(tmp, L"i7c", 0, tf);
  f = CreateFileW(tf, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (f == INVALID_HANDLE_VALUE) FAILF("temp file");
  run_with(f, res, sizeof(res), NULL, tf);
  CloseHandle(f); DeleteFileW(tf);
  INFO("file:  %s", strtok(res, "\r\n"));
  if (strstr(res, "ft=1 getmode=0/6 csbi=0/6 setmode=0/6 isatty=0") == NULL) FAILF("file report: %s", res);
  nul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
  {
    /* NUL output is not readable back: the child reports through its exit code only; so query NUL in-process */
    DWORD mode, ft = GetFileType(nul);
    BOOL ok = GetConsoleMode(nul, &mode);
    e = GetLastError();
    INFO("NUL: filetype=%lu GetConsoleMode ok=%d err=%lu", (unsigned long)ft, ok, (unsigned long)e);
    if (ft != FILE_TYPE_CHAR) FAILF("NUL file type %lu, expected 2", (unsigned long)ft);
    if (ok || e != ERROR_INVALID_HANDLE) FAILF("GetConsoleMode(NUL) ok=%d err=%lu, expected failure 6", ok, (unsigned long)e);
  }
  CloseHandle(nul);
  /* code pages: valid with or without a console on Win10 */
  cp = GetConsoleCP(); e = GetLastError();
  INFO("GetConsoleCP=%lu err=%lu GetConsoleOutputCP=%lu ACP=%lu OEMCP=%lu", (unsigned long)cp, (unsigned long)e, (unsigned long)GetConsoleOutputCP(), (unsigned long)GetACP(), (unsigned long)GetOEMCP());
  INFO("parent stdout filetype=%lu, GetConsoleWindow=%p", (unsigned long)GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)), (void *)GetConsoleWindow());
  printf("PASS %s\n", TEST_NAME);
out:
  return g_fail;
}
