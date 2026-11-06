/*
 * Test: 17_longpath_file_ops
 *
 * Purpose: file operations on paths longer than MAX_PATH as curl's Windows
 *   file code does (CreateFileW, GetFileAttributesExW, _wfopen on a \\?\
 *   path). Probed on Win10 22H2 (build 19045, LongPathsEnabled=0, exe has no
 *   longPathAware manifest), std and adm identical.
 *
 * Success (path ~300 chars: a temp dir plus five 50-char directories):
 *   - CreateDirectoryW, CreateFileW (CREATE_ALWAYS), WriteFile of 3 bytes,
 *     GetFileAttributesExW (size 3, FILE_ATTRIBUTE_ARCHIVE only), _wfopen("rb")
 *     read of 3 bytes and GetShortPathNameW all work with the \\?\ prefix.
 *   - the same path WITHOUT the prefix fails to open with ERROR_PATH_NOT_FOUND
 *     (3) when HKLM\...\FileSystem\LongPathsEnabled is 0 (this check is skipped
 *     when the registry value is 1: environment dependent).
 *   - missing directory: GetFileAttributesExW fails with 3; missing file in
 *     an existing directory: 2; C:\Windows reports FILE_ATTRIBUTE_DIRECTORY.
 *   - DeleteFileW and RemoveDirectoryW (bottom-up) clean the tree.
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

#define NAME "longpath_file_ops"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); rc = 1; goto done; } while (0)

int main(void)
{
    wchar_t tmp[MAX_PATH], base[MAX_PATH + 8], lp[2000], fp[2100], shortp[MAX_PATH];
    wchar_t dirs[6][2000];
    int nd = 0, i, j, rc = 0;
    HANDLE f;
    DWORD w, longpaths = 0, sz = sizeof longpaths;
    HKEY k;
    WIN32_FILE_ATTRIBUTE_DATA ad;
    FILE *fh;
    char b[8];
    int have_file = 0;

    if (!GetTempPathW(MAX_PATH, tmp))
        FAILF("GetTempPathW");
    swprintf(base, MAX_PATH + 8, L"%lstc17_%lu", tmp, (unsigned long)GetCurrentProcessId());
    if (!CreateDirectoryW(base, NULL))
        FAILF("CreateDirectoryW(base) err=%lu", (unsigned long)GetLastError());
    swprintf(lp, 2000, L"\\\\?\\%ls", base);
    wcscpy(dirs[nd++], lp);
    for (i = 0; i < 5; i++) {
        wcscat(lp, L"\\");
        for (j = 0; j < 50; j++) wcscat(lp, L"d");
        if (!CreateDirectoryW(lp, NULL))
            FAILF("CreateDirectoryW level %d err=%lu", i, (unsigned long)GetLastError());
        wcscpy(dirs[nd++], lp);
    }
    if (wcslen(lp) - 4 < 270)
        FAILF("test path too short (%lu)", (unsigned long)wcslen(lp));

    swprintf(fp, 2100, L"%ls\\f.txt", lp);
    f = CreateFileW(fp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        FAILF("CreateFileW long err=%lu", (unsigned long)GetLastError());
    have_file = 1;
    if (!WriteFile(f, "abc", 3, &w, NULL) || w != 3) { CloseHandle(f); FAILF("WriteFile"); }
    CloseHandle(f);

    memset(&ad, 0, sizeof ad);
    if (!GetFileAttributesExW(fp, GetFileExInfoStandard, &ad))
        FAILF("GetFileAttributesExW long err=%lu", (unsigned long)GetLastError());
    if (ad.nFileSizeLow != 3 || ad.nFileSizeHigh != 0 || ad.dwFileAttributes != FILE_ATTRIBUTE_ARCHIVE)
        FAILF("attributes: size %lu attr 0x%lx", (unsigned long)ad.nFileSizeLow, (unsigned long)ad.dwFileAttributes);

    fh = _wfopen(fp, L"rb");
    if (!fh)
        FAILF("_wfopen long");
    if (fread(b, 1, 8, fh) != 3 || memcmp(b, "abc", 3) != 0) { fclose(fh); FAILF("_wfopen read"); }
    fclose(fh);

    w = GetShortPathNameW(fp, shortp, MAX_PATH);
    if (w == 0 || w >= MAX_PATH)
        FAILF("GetShortPathNameW returned %lu err=%lu", (unsigned long)w, (unsigned long)GetLastError());

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\FileSystem", 0, KEY_READ, &k) == 0) {
        if (RegQueryValueExW(k, L"LongPathsEnabled", NULL, NULL, (BYTE *)&longpaths, &sz) != 0)
            longpaths = 0;
        RegCloseKey(k);
    }
    if (longpaths == 0) {
        SetLastError(0);
        f = CreateFileW(fp + 4, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) { CloseHandle(f); FAILF("unprefixed long path opened although LongPathsEnabled=0"); }
        if (GetLastError() != ERROR_PATH_NOT_FOUND)
            FAILF("unprefixed long path: error %lu, expected 3", (unsigned long)GetLastError());
    }

    SetLastError(0);
    if (GetFileAttributesExW(L"C:\\tc17_no_such_dir\\x", GetFileExInfoStandard, &ad) || GetLastError() != ERROR_PATH_NOT_FOUND)
        FAILF("missing dir: err=%lu, expected 3", (unsigned long)GetLastError());
    SetLastError(0);
    if (GetFileAttributesExW(L"C:\\Windows\\tc17_no_such_file", GetFileExInfoStandard, &ad) || GetLastError() != ERROR_FILE_NOT_FOUND)
        FAILF("missing file: err=%lu, expected 2", (unsigned long)GetLastError());
    if (!GetFileAttributesExW(L"C:\\Windows", GetFileExInfoStandard, &ad) || !(ad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        FAILF("C:\\Windows is not a directory");

done:
    if (have_file) DeleteFileW(fp);
    for (i = nd - 1; i >= 0; i--) RemoveDirectoryW(dirs[i]);
    RemoveDirectoryW(base);
    if (rc == 0)
        printf("PASS " NAME "\n");
    return rc;
}
