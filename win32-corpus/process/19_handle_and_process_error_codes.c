/*
 * Test: 19_handle_and_process_error_codes
 *
 * Purpose: exact error codes of handle, wait, process and memory calls that
 *   curl's cleanup and spawn paths hit. Probed on Win10 22H2, std and adm
 *   identical; each value was seen on every run.
 *
 * Success:
 *   - CloseHandle(closed handle) and CloseHandle(NULL): FALSE, 6 (ERROR_INVALID_HANDLE).
 *   - CloseHandle(INVALID_HANDLE_VALUE) returns TRUE (it is the current-process
 *     pseudo handle) and does not break the process.
 *   - WaitForSingleObject(NULL) and (bogus 0x7777): WAIT_FAILED, 6.
 *   - WaitForMultipleObjects with 65 handles: WAIT_FAILED, 87.
 *   - CreateProcessW: missing absolute exe -> 3 (PATH_NOT_FOUND); missing bare
 *     name in the command line -> 2 (FILE_NOT_FOUND).
 *   - TerminateProcess on an already terminated process: FALSE, 5 (ACCESS_DENIED);
 *     a running child's STILL_ACTIVE (259) exit code; a terminated child
 *     reports the given exit code (0xC0DE); a child exiting 7 reports 7.
 *   - VirtualAlloc(2^50) fails with 87 (ERROR_INVALID_PARAMETER); HeapAlloc
 *     of (SIZE_T)-1 fails with 8 (ERROR_NOT_ENOUGH_MEMORY).
 *   - GetConsoleMode on a redirected stdout (a file/pipe): FALSE, 6.
 *   - anonymous pipe: ReadFile after the writer closed fails with 109
 *     (BROKEN_PIPE); named pipe server WriteFile after the client closed
 *     fails with 232 (NO_DATA), ReadFile with 109; opening a missing pipe: 2.
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

#define NAME "handle_and_process_error_codes"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)
#define EXPECT_ERR(what, want) do { DWORD e_ = GetLastError(); if (e_ != (DWORD)(want)) \
    FAILF("%s: error %lu, expected %lu", what, (unsigned long)e_, (unsigned long)(want)); } while (0)

int wmain(int argc, wchar_t **argv)
{
    HANDLE ev, r, w, srv, cli;
    wchar_t exe[MAX_PATH], cl[MAX_PATH + 32];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD n, code;
    HANDLE many[65];
    int i;
    char buf[4];
    void *p;

    if (argc > 1) {                          /* child modes */
        if (wcscmp(argv[1], L"exit7") == 0) return 7;
        if (wcscmp(argv[1], L"sleep") == 0) { Sleep(60000); return 0; }
        return 99;
    }

    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    CloseHandle(ev);
    SetLastError(0);
    if (CloseHandle(ev)) FAILF("double CloseHandle succeeded");
    EXPECT_ERR("double CloseHandle", ERROR_INVALID_HANDLE);
    SetLastError(0);
    if (CloseHandle(NULL)) FAILF("CloseHandle(NULL) succeeded");
    EXPECT_ERR("CloseHandle(NULL)", ERROR_INVALID_HANDLE);
    if (!CloseHandle(INVALID_HANDLE_VALUE)) FAILF("CloseHandle(INVALID_HANDLE_VALUE) failed");

    SetLastError(0);
    if (WaitForSingleObject(NULL, 0) != WAIT_FAILED) FAILF("wait NULL");
    EXPECT_ERR("WaitForSingleObject(NULL)", ERROR_INVALID_HANDLE);
    SetLastError(0);
    if (WaitForSingleObject((HANDLE)(ULONG_PTR)0x7777, 0) != WAIT_FAILED) FAILF("wait bogus");
    EXPECT_ERR("WaitForSingleObject(bogus)", ERROR_INVALID_HANDLE);
    ev = CreateEventW(NULL, TRUE, TRUE, NULL);
    for (i = 0; i < 65; i++) many[i] = ev;
    SetLastError(0);
    if (WaitForMultipleObjects(65, many, FALSE, 0) != WAIT_FAILED) FAILF("wait 65");
    EXPECT_ERR("WaitForMultipleObjects(65)", ERROR_INVALID_PARAMETER);
    CloseHandle(ev);

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    SetLastError(0);
    if (CreateProcessW(L"C:\\no\\such\\tc19.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        FAILF("CreateProcessW of missing exe succeeded");
    EXPECT_ERR("CreateProcessW missing absolute", ERROR_PATH_NOT_FOUND);
    wcscpy(cl, L"tc19_no_such_program arg");
    SetLastError(0);
    if (CreateProcessW(NULL, cl, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        FAILF("CreateProcessW of missing bare name succeeded");
    EXPECT_ERR("CreateProcessW missing bare", ERROR_FILE_NOT_FOUND);

    GetModuleFileNameW(NULL, exe, MAX_PATH);
    swprintf(cl, MAX_PATH + 32, L"\"%ls\" exit7", exe);
    if (!CreateProcessW(NULL, cl, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        FAILF("spawn exit7 err=%lu", (unsigned long)GetLastError());
    WaitForSingleObject(pi.hProcess, 20000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    if (code != 7) FAILF("child exit code %lu, expected 7", (unsigned long)code);

    swprintf(cl, MAX_PATH + 32, L"\"%ls\" sleep", exe);
    if (!CreateProcessW(NULL, cl, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        FAILF("spawn sleep err=%lu", (unsigned long)GetLastError());
    GetExitCodeProcess(pi.hProcess, &code);
    if (code != STILL_ACTIVE) FAILF("running child exit code %lu, expected 259", (unsigned long)code);
    if (WaitForSingleObject(pi.hProcess, 100) != WAIT_TIMEOUT) FAILF("running child wait did not time out");
    if (!TerminateProcess(pi.hProcess, 0xC0DE)) FAILF("TerminateProcess err=%lu", (unsigned long)GetLastError());
    WaitForSingleObject(pi.hProcess, 20000);
    GetExitCodeProcess(pi.hProcess, &code);
    if (code != 0xC0DE) FAILF("terminated child exit code 0x%lx", (unsigned long)code);
    SetLastError(0);
    if (TerminateProcess(pi.hProcess, 1)) FAILF("TerminateProcess on dead process succeeded");
    EXPECT_ERR("TerminateProcess(dead)", ERROR_ACCESS_DENIED);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);

    SetLastError(0);
    p = VirtualAlloc(NULL, (SIZE_T)1 << 50, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p) FAILF("VirtualAlloc(2^50) succeeded");
    EXPECT_ERR("VirtualAlloc(2^50)", ERROR_INVALID_PARAMETER);
    SetLastError(0);
    p = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)-1);
    if (p) FAILF("HeapAlloc(-1) succeeded");
    EXPECT_ERR("HeapAlloc(-1)", ERROR_NOT_ENOUGH_MEMORY);

    /* stdout of this process is redirected by the harness (file or pipe), but
       when run interactively it may be a console: only check when it is not. */
    {
        DWORD m;
        HANDLE so = GetStdHandle(STD_OUTPUT_HANDLE);
        if (so && so != INVALID_HANDLE_VALUE && GetFileType(so) != FILE_TYPE_CHAR) {
            SetLastError(0);
            if (GetConsoleMode(so, &m)) FAILF("GetConsoleMode succeeded on a non-character handle");
            EXPECT_ERR("GetConsoleMode(redirected)", ERROR_INVALID_HANDLE);
        }
    }

    if (!CreatePipe(&r, &w, NULL, 0)) FAILF("CreatePipe");
    CloseHandle(w);
    SetLastError(0);
    if (ReadFile(r, buf, 4, &n, NULL)) FAILF("ReadFile at EOF succeeded");
    EXPECT_ERR("anon ReadFile at EOF", ERROR_BROKEN_PIPE);
    CloseHandle(r);

    {
        wchar_t pn[64];
        swprintf(pn, 64, L"\\\\.\\pipe\\tc19_%lu", (unsigned long)GetCurrentProcessId());
        srv = CreateNamedPipeW(pn, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
        if (srv == INVALID_HANDLE_VALUE) FAILF("CreateNamedPipeW err=%lu", (unsigned long)GetLastError());
        cli = CreateFileW(pn, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (cli == INVALID_HANDLE_VALUE) FAILF("open client err=%lu", (unsigned long)GetLastError());
        CloseHandle(cli);
        SetLastError(0);
        if (WriteFile(srv, "x", 1, &n, NULL)) FAILF("server WriteFile after client close succeeded");
        EXPECT_ERR("named pipe WriteFile after client close", ERROR_NO_DATA);
        SetLastError(0);
        if (ReadFile(srv, buf, 4, &n, NULL)) FAILF("server ReadFile after client close succeeded");
        EXPECT_ERR("named pipe ReadFile after client close", ERROR_BROKEN_PIPE);
        CloseHandle(srv);
        swprintf(pn, 64, L"\\\\.\\pipe\\tc19_none_%lu", (unsigned long)GetCurrentProcessId());
        SetLastError(0);
        cli = CreateFileW(pn, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (cli != INVALID_HANDLE_VALUE) FAILF("opened a missing pipe");
        EXPECT_ERR("open missing pipe", ERROR_FILE_NOT_FOUND);
    }

    printf("PASS " NAME "\n");
    return 0;
}
