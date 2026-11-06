/*
 * Test: 20_createprocess_handle_list
 * Purpose: how a test-server launcher (curl's tests/runtests.pl starts
 *          servers; the Windows equivalent is CreateProcess) controls which
 *          handles a child inherits. Inheriting everything (bInheritHandles)
 *          vs an explicit PROC_THREAD_ATTRIBUTE_HANDLE_LIST in STARTUPINFOEX.
 * APIs: CreateProcessW, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
 *       SetHandleInformation, GetHandleInformation, CreatePipe.
 * Method: the program re-executes itself as a child with "--child H1 H2 H3"
 *       (decimal handle values). The child reports on stdout (a pipe) for each
 *       handle whether GetHandleInformation succeeds and with which error.
 * Success (pinned from Win10 22H2 probes below):
 *   - bInheritHandles=TRUE: every inheritable handle (A, B) is valid in the
 *     child, the non-inheritable one (C) is not (ERROR_INVALID_HANDLE 6);
 *   - handle list naming only A: A is valid, B (inheritable but not listed)
 *     is not;
 *   - a handle in the list that is not inheritable: CreateProcess fails with
 *     ERROR_INVALID_PARAMETER (87);
 *   - the child sees the same numeric handle values (handles are inherited at
 *     their parent value).
 * Source: tests/runtests.pl + tests/server sources spawn model; lib/ has no CreateProcess.
 */
#define TEST_NAME "20_createprocess_handle_list"
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

static int child_main(int argc, wchar_t **argv) {
  int i;
  for (i = 2; i < argc; i++) {
    HANDLE h = (HANDLE)(ULONG_PTR)_wcstoui64(argv[i], NULL, 10);
    DWORD fl = 0;
    BOOL ok = GetHandleInformation(h, &fl);
    DWORD e = ok ? 0 : GetLastError();
    printf("H%d ok=%d err=%lu\n", i - 1, ok ? 1 : 0, (unsigned long)e);
  }
  return 0;
}

typedef struct { int ok[4]; unsigned long err[4]; int n; DWORD cpErr; BOOL cpOk; DWORD exitc; } res_t;

static int run_child(HANDLE *hs, int nh, BOOL inherit_all, res_t *res) {
  wchar_t self[MAX_PATH], cmd[1024], tmp[64];
  STARTUPINFOEXW si;
  PROCESS_INFORMATION pi;
  SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
  HANDLE rd = NULL, wr = NULL;
  char out[1024];
  DWORD n, tot = 0;
  int i, k;

  memset(res, 0, sizeof(*res));
  GetModuleFileNameW(NULL, self, MAX_PATH);
  CreatePipe(&rd, &wr, &sa, 0);
  SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
  swprintf(cmd, 1024, L"\"%ls\" --child", self);
  for (i = 0; i < nh; i++) { swprintf(tmp, 64, L" %llu", (unsigned long long)(ULONG_PTR)hs[i]); wcscat(cmd, tmp); }
  memset(&si, 0, sizeof(si));
  si.StartupInfo.cb = sizeof(si);
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  si.StartupInfo.hStdOutput = wr;
  si.StartupInfo.hStdError = wr;
  si.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
  memset(&pi, 0, sizeof(pi));
  res->cpOk = CreateProcessW(NULL, cmd, NULL, NULL, inherit_all, 0, NULL, NULL, &si.StartupInfo, &pi);
  res->cpErr = res->cpOk ? 0 : GetLastError();
  CloseHandle(wr);
  if (!res->cpOk) { CloseHandle(rd); return 0; }
  while (tot < sizeof(out) - 1 && ReadFile(rd, out + tot, (DWORD)(sizeof(out) - 1 - tot), &n, NULL) && n) tot += n;
  out[tot] = 0;
  WaitForSingleObject(pi.hProcess, 20000);
  GetExitCodeProcess(pi.hProcess, &res->exitc);
  CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(rd);
  for (k = 0; k < nh; k++) {
    char key[16]; char *p; snprintf(key, sizeof(key), "H%d ok=", k + 1);
    p = strstr(out, key);
    if (p) { res->ok[k] = p[strlen(key)] == '1'; p = strstr(p, "err="); res->err[k] = p ? strtoul(p + 4, NULL, 10) : 0; res->n++; }
  }
  return 0;
}

int wmain(int argc, wchar_t **argv) {
  HANDLE a = NULL, b = NULL, c = NULL;
  HANDLE p1r = NULL, p2r = NULL, p3r = NULL;
  SECURITY_ATTRIBUTES inh = { sizeof(inh), NULL, TRUE }, noinh = { sizeof(noinh), NULL, FALSE };
  res_t r;
  HANDLE hs[3];
  int it;

  if (argc > 1 && wcscmp(argv[1], L"--child") == 0) return child_main(argc, argv);
  CreatePipe(&p1r, &a, &inh, 0);
  CreatePipe(&p2r, &b, &inh, 0);
  CreatePipe(&p3r, &c, &noinh, 0);
  hs[0] = a; hs[1] = b; hs[2] = c;

  for (it = 0; it < 5; it++) {
    run_child(hs, 3, TRUE, &r);
    if (!r.cpOk) FAILF("inherit-all CreateProcess err=%lu", (unsigned long)r.cpErr);
    if (it == 0) INFO("inherit all: A ok=%d/%lu B ok=%d/%lu C ok=%d/%lu exit=%lu", r.ok[0], r.err[0], r.ok[1], r.err[1], r.ok[2], r.err[2], (unsigned long)r.exitc);
    if (r.n != 3 || !r.ok[0] || !r.ok[1] || r.ok[2] || r.err[2] != ERROR_INVALID_HANDLE)
      FAILF("inherit-all: A=%d B=%d C=%d/%lu n=%d", r.ok[0], r.ok[1], r.ok[2], r.err[2], r.n);
  }
  {
    /* list-based run: build everything here instead of run_child for exact control */
    wchar_t self[MAX_PATH], cmd[1024], tmp[64];
    STARTUPINFOEXW si;
    PROCESS_INFORMATION pi;
    HANDLE rd = NULL, wr = NULL, lst[2];
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    SIZE_T asz = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST al;
    char out[512];
    DWORD n, tot = 0, ex = 0;
    BOOL ok;
    int k;
    static const char *label[] = { "list{A,stdout}", "list{C non-inheritable}" };

    for (k = 0; k < 2; k++) {
      CreatePipe(&rd, &wr, &sa, 0);
      SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
      GetModuleFileNameW(NULL, self, MAX_PATH);
      swprintf(cmd, 1024, L"\"%ls\" --child", self);
      for (it = 0; it < 3; it++) { swprintf(tmp, 64, L" %llu", (unsigned long long)(ULONG_PTR)hs[it]); wcscat(cmd, tmp); }
      memset(&si, 0, sizeof(si));
      si.StartupInfo.cb = sizeof(si);
      si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
      si.StartupInfo.hStdOutput = wr; si.StartupInfo.hStdError = wr; si.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
      asz = 0;
      InitializeProcThreadAttributeList(NULL, 1, 0, &asz);
      al = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(asz);
      InitializeProcThreadAttributeList(al, 1, 0, &asz);
      lst[0] = wr; lst[1] = (k == 0) ? a : c;
      ok = UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, lst, sizeof(lst), NULL, NULL);
      INFO("%s: UpdateProcThreadAttribute ok=%d err=%lu", label[k], ok, ok ? 0ul : (unsigned long)GetLastError());
      si.lpAttributeList = al;
      memset(&pi, 0, sizeof(pi));
      ok = CreateProcessW(NULL, cmd, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
      INFO("%s: CreateProcess ok=%d err=%lu", label[k], ok, ok ? 0ul : (unsigned long)GetLastError());
      CloseHandle(wr);
      DeleteProcThreadAttributeList(al); free(al);
      if (k == 1) {
        if (ok) { WaitForSingleObject(pi.hProcess, 20000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
        CloseHandle(rd);
        if (ok) FAILF("a non-inheritable handle in the list was accepted");
        if (GetLastError() != ERROR_INVALID_PARAMETER) FAILF("error %lu, expected 87", (unsigned long)GetLastError());
        continue;
      }
      if (!ok) FAILF("list CreateProcess err=%lu", (unsigned long)GetLastError());
      tot = 0;
      while (tot < sizeof(out) - 1 && ReadFile(rd, out + tot, (DWORD)(sizeof(out) - 1 - tot), &n, NULL) && n) tot += n;
      out[tot] = 0;
      WaitForSingleObject(pi.hProcess, 20000);
      GetExitCodeProcess(pi.hProcess, &ex);
      CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(rd);
      INFO("%s child says: %s", label[k], out);
      /* H1 (A, listed) valid; H2 (B, inheritable, not listed) invalid; H3 (C) invalid */
      if (!strstr(out, "H1 ok=1")) FAILF("listed handle A not inherited: %s", out);
      if (!strstr(out, "H2 ok=0 err=6")) FAILF("unlisted inheritable handle B leaked into the child: %s", out);
      if (!strstr(out, "H3 ok=0 err=6")) FAILF("C: %s", out);
    }
  }
  printf("PASS %s\n", TEST_NAME);
out:
  return g_fail;
}
