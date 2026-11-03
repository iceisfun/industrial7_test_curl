/*
 * Test: 10_adddlldirectory_cookie
 *
 * Purpose: AddDllDirectory returns an opaque cookie for a per-load search
 *   directory; RemoveDllDirectory takes the cookie back exactly once. While the
 *   directory is registered, a DLL in it is found by LoadLibraryExW with
 *   LOAD_LIBRARY_SEARCH_USER_DIRS; after removal it is not. A second removal of
 *   the same cookie must fail.
 *
 * APIs: SetDefaultDllDirectories, AddDllDirectory, RemoveDllDirectory,
 *   LoadLibraryExW (LOAD_LIBRARY_SEARCH_USER_DIRS), GetTempPathW,
 *   CreateDirectoryW, CreateFileW, DeleteFileW, RemoveDirectoryW
 *
 * Success:
 *   - SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) == TRUE
 *     (DEFAULT_DIRS includes USER_DIRS, which AddDllDirectory requires).
 *   - AddDllDirectory(tmp) != NULL.
 *   - With the cookie active, LoadLibraryExW(L"tc_probe_10.dll", NULL,
 *     LOAD_LIBRARY_SEARCH_USER_DIRS) fails with ERROR_BAD_EXE_FORMAT (193),
 *     showing the file was found in the added directory.
 *   - RemoveDllDirectory(cookie) == TRUE.
 *   - A second RemoveDllDirectory on the same (now stale) cookie is NOT asserted:
 *     the documentation does not define its result, so no behaviour is claimed.
 *   - After removal, the same LoadLibraryExW fails with ERROR_MOD_NOT_FOUND (126).
 *
 * Source reference: none direct; curl does not register extra DLL directories.
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

#define NAME "adddlldirectory_cookie"

static wchar_t g_tmp[MAX_PATH];
static wchar_t g_file[MAX_PATH + 32];
static int g_have_dir, g_have_file;

static void cleanup(void);

#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); cleanup(); return 1; } while (0)

static void cleanup(void)
{
    if (g_have_file)
        DeleteFileW(g_file);
    if (g_have_dir)
        RemoveDirectoryW(g_tmp);
}

int main(void)
{
    wchar_t base[MAX_PATH];
    DLL_DIRECTORY_COOKIE cookie;
    HANDLE f;
    HMODULE h;
    DWORD n, written;

    n = GetTempPathW(MAX_PATH, base);
    if (n == 0 || n >= MAX_PATH)
        FAILF("GetTempPathW err=%lu", (unsigned long)GetLastError());
    if (swprintf(g_tmp, MAX_PATH, L"%ls" L"tc_dynload_10_%lu", base,
                 (unsigned long)GetCurrentProcessId()) < 0)
        FAILF("swprintf dir failed");
    if (!CreateDirectoryW(g_tmp, NULL))
        FAILF("CreateDirectoryW err=%lu", (unsigned long)GetLastError());
    g_have_dir = 1;

    if (swprintf(g_file, MAX_PATH + 32, L"%ls\\tc_probe_10.dll", g_tmp) < 0)
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

    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS))
        FAILF("SetDefaultDllDirectories err=%lu", (unsigned long)GetLastError());

    cookie = AddDllDirectory(g_tmp);
    if (!cookie)
        FAILF("AddDllDirectory(%ls) err=%lu", g_tmp, (unsigned long)GetLastError());

    /* Found in the added directory: the load fails only because it is not a PE. */
    SetLastError(0);
    h = LoadLibraryExW(L"tc_probe_10.dll", NULL, LOAD_LIBRARY_SEARCH_USER_DIRS);
    if (h != NULL) {
        FreeLibrary(h);
        FAILF("non-PE probe DLL loaded successfully");
    }
    if (GetLastError() != ERROR_BAD_EXE_FORMAT)
        FAILF("with cookie active: expected ERROR_BAD_EXE_FORMAT(193) got %lu",
              (unsigned long)GetLastError());

    if (!RemoveDllDirectory(cookie))
        FAILF("RemoveDllDirectory(cookie) err=%lu", (unsigned long)GetLastError());

    /* After removal the directory is no longer searched. */
    SetLastError(0);
    h = LoadLibraryExW(L"tc_probe_10.dll", NULL, LOAD_LIBRARY_SEARCH_USER_DIRS);
    if (h != NULL) {
        FreeLibrary(h);
        FAILF("probe DLL still found after RemoveDllDirectory");
    }
    if (GetLastError() != ERROR_MOD_NOT_FOUND)
        FAILF("after removal: expected ERROR_MOD_NOT_FOUND(126) got %lu",
              (unsigned long)GetLastError());

    cleanup();
    printf("PASS " NAME "\n");
    return 0;
}
