/*
 * Test: 09_setdlldirectory_restore
 *
 * Purpose: SetDllDirectoryW installs a process-wide DLL search directory that
 *   GetDllDirectoryW reports back exactly, including the size-query contract.
 *   Passing NULL restores the default (empty) state. A DLL that exists only in
 *   the temporary "DLL directory" is found by bare name while it is installed,
 *   and is not found after it is removed.
 *
 * APIs: SetDllDirectoryW, GetDllDirectoryW, LoadLibraryW, GetTempPathW,
 *   CreateDirectoryW, CreateFileW, WriteFile, DeleteFileW, RemoveDirectoryW,
 *   GetLastError
 *
 * Success:
 *   - SetDllDirectoryW(tmp) == TRUE.
 *   - GetDllDirectoryW(0, NULL) == wcslen(tmp) + 1 (size query).
 *   - GetDllDirectoryW(size, buf) returns wcslen(tmp) and buf == tmp.
 *   - With the directory installed, LoadLibraryW(L"tc_probe_09.dll") fails with
 *     ERROR_BAD_EXE_FORMAT (193): the file was found, it is just not a PE.
 *     This proves the directory is on the search path.
 *   - SetDllDirectoryW(NULL) == TRUE and GetDllDirectoryW returns 0 (empty).
 *   - After reset, LoadLibraryW(L"tc_probe_09.dll") fails with
 *     ERROR_MOD_NOT_FOUND (126).
 *
 * Source reference: none direct; curl does not install a DLL directory. This
 *   covers the process-global state a loader-based DLL-search change would touch.
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
#include <wchar.h>

#define NAME "setdlldirectory_restore"

static wchar_t g_tmp[MAX_PATH];
static wchar_t g_file[MAX_PATH + 32];
static int g_have_dir, g_have_file;

static void cleanup(void);

#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); cleanup(); return 1; } while (0)

static void cleanup(void)
{
    SetDllDirectoryW(NULL);
    if (g_have_file)
        DeleteFileW(g_file);
    if (g_have_dir)
        RemoveDirectoryW(g_tmp);
}

int main(void)
{
    wchar_t base[MAX_PATH];
    wchar_t got[MAX_PATH];
    HANDLE f;
    HMODULE h;
    DWORD n, written, size;

    n = GetTempPathW(MAX_PATH, base);
    if (n == 0 || n >= MAX_PATH)
        FAILF("GetTempPathW err=%lu", (unsigned long)GetLastError());
    if (swprintf(g_tmp, MAX_PATH, L"%ls" L"tc_dynload_09_%lu", base,
                 (unsigned long)GetCurrentProcessId()) < 0)
        FAILF("swprintf dir failed");
    if (!CreateDirectoryW(g_tmp, NULL))
        FAILF("CreateDirectoryW err=%lu", (unsigned long)GetLastError());
    g_have_dir = 1;

    if (swprintf(g_file, MAX_PATH + 32, L"%ls\\tc_probe_09.dll", g_tmp) < 0)
        FAILF("swprintf file failed");
    f = CreateFileW(g_file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        FAILF("CreateFileW err=%lu", (unsigned long)GetLastError());
    if (!WriteFile(f, "not-a-pe", 8, &written, NULL)) {
        CloseHandle(f);
        FAILF("WriteFile err=%lu", (unsigned long)GetLastError());
    }
    CloseHandle(f);
    g_have_file = 1;

    if (!SetDllDirectoryW(g_tmp))
        FAILF("SetDllDirectoryW(tmp) err=%lu", (unsigned long)GetLastError());

    size = GetDllDirectoryW(0, NULL);
    if (size != wcslen(g_tmp) + 1)
        FAILF("GetDllDirectoryW size query=%lu expected %lu",
              (unsigned long)size, (unsigned long)(wcslen(g_tmp) + 1));

    n = GetDllDirectoryW(MAX_PATH, got);
    if (n != wcslen(g_tmp) || wcscmp(got, g_tmp) != 0)
        FAILF("GetDllDirectoryW returned %lu '%ls', expected '%ls'",
              (unsigned long)n, got, g_tmp);

    /* Installed directory is searched: the file is found, but is not a PE. */
    SetLastError(0);
    h = LoadLibraryW(L"tc_probe_09.dll");
    if (h != NULL) {
        FreeLibrary(h);
        FAILF("non-PE probe DLL loaded successfully");
    }
    if (GetLastError() != ERROR_BAD_EXE_FORMAT)
        FAILF("probe with dir installed: expected ERROR_BAD_EXE_FORMAT(193) got %lu",
              (unsigned long)GetLastError());

    /* Reset to the default state. */
    if (!SetDllDirectoryW(NULL))
        FAILF("SetDllDirectoryW(NULL) err=%lu", (unsigned long)GetLastError());
    n = GetDllDirectoryW(MAX_PATH, got);
    if (n != 0)
        FAILF("after reset GetDllDirectoryW returned %lu, expected 0", (unsigned long)n);

    SetLastError(0);
    h = LoadLibraryW(L"tc_probe_09.dll");
    if (h != NULL) {
        FreeLibrary(h);
        FAILF("probe DLL still found after directory reset");
    }
    if (GetLastError() != ERROR_MOD_NOT_FOUND)
        FAILF("after reset: expected ERROR_MOD_NOT_FOUND(126) got %lu",
              (unsigned long)GetLastError());

    cleanup();
    printf("PASS " NAME "\n");
    return 0;
}
