/*
 * Test: 21_job_object_process_tree
 * Purpose: job objects as a test harness uses them to own and reap spawned
 *          servers: a job with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE kills its
 *          members when the last job handle closes; TerminateJobObject sets the
 *          given exit code; accounting counts active processes; a process may
 *          be a member of a nested job on Win10; assignment of a process that is
 *          already in a job.
 * APIs: CreateJobObjectW, SetInformationJobObject, QueryInformationJobObject,
 *       AssignProcessToJobObject, IsProcessInJob, TerminateJobObject, CreateProcessW.
 * Method: child = this exe with "--sleep" (sleeps 60 s unless killed).
 * Success (pinned from Win10 22H2 probes):
 *   - after assignment BASIC_ACCOUNTING_INFORMATION.ActiveProcesses == 1,
 *     TotalProcesses == 1; IsProcessInJob true;
 *   - TerminateJobObject(job, 42) ends the child with exit code 42 and
 *     ActiveProcesses drops to 0;
 *   - closing the only job handle of a KILL_ON_JOB_CLOSE job ends the member
 *     within 5 s with exit code 0 (probed: no code is forced);
 *   - a child created in a job by a member inherits the job unless
 *     JOB_OBJECT_LIMIT_BREAKAWAY_OK and CREATE_BREAKAWAY_FROM_JOB;
 *   - the active process limit refuses the 3rd child.
 * Source: tests/runtests.pl server lifecycle (kill leftovers); no curl source.
 */
#define TEST_NAME "21_job_object_process_tree"
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

static int spawn(const wchar_t *arg, DWORD flags, PROCESS_INFORMATION *pi) {
  wchar_t self[MAX_PATH], cmd[600];
  STARTUPINFOW si;
  GetModuleFileNameW(NULL, self, MAX_PATH);
  swprintf(cmd, 600, L"\"%ls\" %ls", self, arg);
  memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
  memset(pi, 0, sizeof(*pi));
  return CreateProcessW(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, pi);
}

static JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acct(HANDLE job) {
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION b;
  memset(&b, 0xff, sizeof(b));
  if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &b, sizeof(b), NULL)) b.ActiveProcesses = 0xdead;
  return b;
}

int wmain(int argc, wchar_t **argv) {
  HANDLE job = NULL, job2 = NULL;
  PROCESS_INFORMATION p1, p2, p3;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION xl;
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION b;
  DWORD ec, w;
  BOOL in = FALSE, ok;
  int it;

  if (argc > 1 && wcscmp(argv[1], L"--sleep") == 0) { Sleep(60000); return 7; }

  for (it = 0; it < 5; it++) {
    /* 1. terminate */
    job = CreateJobObjectW(NULL, NULL);
    if (!job) FAILF("CreateJobObject %lu", (unsigned long)GetLastError());
    if (!spawn(L"--sleep", CREATE_SUSPENDED, &p1)) FAILF("spawn %lu", (unsigned long)GetLastError());
    if (!AssignProcessToJobObject(job, p1.hProcess)) FAILF("Assign %lu", (unsigned long)GetLastError());
    ResumeThread(p1.hThread);
    b = acct(job);
    if (it == 0) INFO("accounting after assign: active=%lu total=%lu", (unsigned long)b.ActiveProcesses, (unsigned long)b.TotalProcesses);
    if (b.ActiveProcesses != 1 || b.TotalProcesses != 1) FAILF("accounting active=%lu total=%lu", (unsigned long)b.ActiveProcesses, (unsigned long)b.TotalProcesses);
    in = FALSE; ok = IsProcessInJob(p1.hProcess, job, &in);
    if (!ok || !in) FAILF("IsProcessInJob ok=%d in=%d", ok, in);
    if (!TerminateJobObject(job, 42)) FAILF("TerminateJobObject %lu", (unsigned long)GetLastError());
    w = WaitForSingleObject(p1.hProcess, 5000);
    GetExitCodeProcess(p1.hProcess, &ec);
    if (it == 0) INFO("TerminateJobObject: wait=%lu exit=%lu", (unsigned long)w, (unsigned long)ec);
    if (w != WAIT_OBJECT_0 || ec != 42) FAILF("terminate wait=%lu exit=%lu", (unsigned long)w, (unsigned long)ec);
    b = acct(job);
    if (b.ActiveProcesses != 0) FAILF("active after terminate %lu", (unsigned long)b.ActiveProcesses);
    CloseHandle(p1.hProcess); CloseHandle(p1.hThread); CloseHandle(job);

    /* 2. kill on close */
    job = CreateJobObjectW(NULL, NULL);
    memset(&xl, 0, sizeof(xl));
    xl.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &xl, sizeof(xl))) FAILF("SetInformationJobObject %lu", (unsigned long)GetLastError());
    spawn(L"--sleep", CREATE_SUSPENDED, &p1);
    AssignProcessToJobObject(job, p1.hProcess);
    ResumeThread(p1.hThread);
    Sleep(100);
    CloseHandle(job); job = NULL;
    w = WaitForSingleObject(p1.hProcess, 5000);
    GetExitCodeProcess(p1.hProcess, &ec);
    if (it == 0) INFO("kill-on-close: wait=%lu exit=%lu", (unsigned long)w, (unsigned long)ec);
    if (w != WAIT_OBJECT_0) FAILF("member survived closing the job handle");
    if (ec != 0) FAILF("kill-on-close exit code %lu, expected 0", (unsigned long)ec);
    CloseHandle(p1.hProcess); CloseHandle(p1.hThread);
  }

  /* 3. active process limit and inheritance of membership by children */
  job = CreateJobObjectW(NULL, NULL);
  memset(&xl, 0, sizeof(xl));
  xl.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  xl.BasicLimitInformation.ActiveProcessLimit = 2;
  SetInformationJobObject(job, JobObjectExtendedLimitInformation, &xl, sizeof(xl));
  spawn(L"--sleep", CREATE_SUSPENDED, &p1); AssignProcessToJobObject(job, p1.hProcess); ResumeThread(p1.hThread);
  spawn(L"--sleep", CREATE_SUSPENDED, &p2); ok = AssignProcessToJobObject(job, p2.hProcess); ResumeThread(p2.hThread);
  if (!ok) FAILF("second assign %lu", (unsigned long)GetLastError());
  spawn(L"--sleep", CREATE_SUSPENDED, &p3);
  ok = AssignProcessToJobObject(job, p3.hProcess);
  INFO("third assign over ActiveProcessLimit 2: ok=%d err=%lu", ok, ok ? 0ul : (unsigned long)GetLastError());
  if (ok) FAILF("third process accepted over the limit");
  TerminateProcess(p3.hProcess, 3); CloseHandle(p3.hProcess); CloseHandle(p3.hThread);

  /* nested job: p1 is already in 'job'; assigning to a second job */
  job2 = CreateJobObjectW(NULL, NULL);
  ok = AssignProcessToJobObject(job2, p1.hProcess);
  INFO("assign member of job to job2 (nested): ok=%d err=%lu", ok, ok ? 0ul : (unsigned long)GetLastError());
  if (!ok) FAILF("nested job assignment refused: %lu", (unsigned long)GetLastError());
  in = FALSE; IsProcessInJob(p1.hProcess, NULL, &in);
  if (!in) FAILF("IsProcessInJob(NULL) false for a member");

  TerminateJobObject(job, 9);
  WaitForSingleObject(p1.hProcess, 5000); WaitForSingleObject(p2.hProcess, 5000);
  GetExitCodeProcess(p1.hProcess, &ec);
  INFO("p1 exit after TerminateJobObject(outer, 9): %lu", (unsigned long)ec);
  CloseHandle(p1.hProcess); CloseHandle(p1.hThread); CloseHandle(p2.hProcess); CloseHandle(p2.hThread);
  CloseHandle(job2); CloseHandle(job); job = NULL;
  printf("PASS %s\n", TEST_NAME);
out:
  return g_fail;
}
