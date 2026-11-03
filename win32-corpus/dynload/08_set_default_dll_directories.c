/*
 * Test: 08_set_default_dll_directories
 *
 * Purpose: SetDefaultDllDirectories restricts the search that plain LoadLibraryW
 *   performs. After SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32),
 *   a DLL that exists only in the current directory (a temp directory set as
 *   CWD) must NOT be found, while a system DLL still loads. The temp directory
 *   and its file are removed at the end.
 *
 * APIs: SetDefaultDllDirectories, LoadLibraryW, GetLastError, GetTempPathW,
 *   CreateDirectoryW, CreateFileW, SetCurrentDirectoryW, GetCurrentDirectoryW,
 *   DeleteFileW, RemoveDirectoryW, GetProcAddress, FreeLibrary
 *
 * Success:
 *   - SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS)
 *     returns TRUE.
 *   - LoadLibraryW(L"tc_probe_08.dll") with CWD = temp dir (file present there)
 *     returns NULL with ERROR_MOD_NOT_FOUND (126) because CWD and the
 *     application directory are excluded from the restricted search.
 *   - LoadLibraryW(L"version.dll") still succeeds (system32 is searched).
 *
 * Source reference: none in curl (curl never calls SetDefaultDllDirectories or
 *   LoadLibrary). This checks the loader contract a hardened build would rely
 *   on so that an untrusted CWD cannot inject a DLL.
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

#define NAME "set_default_dll_directories"

static wchar_t g_tmp[MAX_PATH];
static wchar_t g_old_cwd[MAX_PATH];
static wchar_t g_file[MAX_PATH + 32];
static int g_have_dir, g_have_file, g_have_cwd;

static void cleanup(void);

#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); cleanup(); return 1; } while (0)

static void cleanup(void)
{
    if (g_have_cwd)
        SetCurrentDirectoryW(g_old_cwd);
    if (g_have_file)
        DeleteFileW(g_file);
    if (g_have_dir)
        RemoveDirectoryW(g_tmp);
}

int main(void)
{
    wchar_t base[MAX_PATH];
    HANDLE f;
    HMODULE h;
    DWORD n;

    n = GetTempPathW(MAX_PATH, base);
    if (n == 0 || n >= MAX_PATH)
        FAILF("GetTempPathW err=%lu", (unsigned long)GetLastError());
    if (swprintf(g_tmp, MAX_PATH, L"%ls" L"tc_dynload_08_%lu", base,
                 (unsigned long)GetCurrentProcessId()) < 0)
        FAILF("swprintf failed");
    if (!CreateDirectoryW(g_tmp, NULL))
        FAILF("CreateDirectoryW(%ls) err=%lu", g_tmp, (unsigned long)GetLastError());
    g_have_dir = 1;

    if (swprintf(g_file, MAX_PATH + 32, L"%ls\\tc_probe_08.dll", g_tmp) < 0)
        FAILF("swprintf file failed");
    f = CreateFileW(g_file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        FAILF("CreateFileW(probe) err=%lu", (unsigned long)GetLastError());
    /* Not a PE image on purpose: if the restricted search is bypassed the
     * load would fail with ERROR_BAD_EXE_FORMAT instead of ERROR_MOD_NOT_FOUND. */
    if (!WriteFile(f, "MZ-not-a-real-dll", 17, &n, NULL)) {
        CloseHandle(f);
        FAILF("WriteFile(probe) err=%lu", (unsigned long)GetLastError());
    }
    CloseHandle(f);
    g_have_file = 1;

    n = GetCurrentDirectoryW(MAX_PATH, g_old_cwd);
    if (n == 0 || n >= MAX_PATH)
        FAILF("GetCurrentDirectoryW err=%lu", (unsigned long)GetLastError());
    if (!SetCurrentDirectoryW(g_tmp))
        FAILF("SetCurrentDirectoryW err=%lu", (unsigned long)GetLastError());
    g_have_cwd = 1;

    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS))
        FAILF("SetDefaultDllDirectories err=%lu", (unsigned long)GetLastError());

    SetLastError(0);
    h = LoadLibraryW(L"tc_probe_08.dll");
    if (h != NULL) {
        FreeLibrary(h);
        FAILF("probe DLL in CWD was found despite restricted search");
    }
    if (GetLastError() != ERROR_MOD_NOT_FOUND)
        FAILF("probe DLL: expected ERROR_MOD_NOT_FOUND(126) got %lu",
              (unsigned long)GetLastError());

    h = LoadLibraryW(L"version.dll");
    if (!h)
        FAILF("system DLL version.dll failed under restricted search err=%lu",
              (unsigned long)GetLastError());
    if (!FreeLibrary(h))
        FAILF("FreeLibrary(version.dll) err=%lu", (unsigned long)GetLastError());

    cleanup();
    printf("PASS " NAME "\n");
    return 0;
}
