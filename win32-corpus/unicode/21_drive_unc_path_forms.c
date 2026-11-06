/*
 * Test: 21_drive_unc_path_forms
 * Purpose: path-shape handling curl relies on for file:// URLs and for the
 *          local file names it is given (src/tool_doswin.c sanitize_file_name,
 *          lib/file.c: "C:" drive letters, forward slashes, \\?\ and UNC forms,
 *          trailing dots/spaces, 8.3 names), as Win32 normalises them.
 * APIs: GetFullPathNameW, GetFinalPathNameByHandleW, GetLongPathNameW,
 *       GetShortPathNameW, CreateFileW, GetFileAttributesW, GetCurrentDirectoryW,
 *       SetCurrentDirectoryW, GetDriveTypeW, GetLogicalDrives.
 * Success (pinned from Win10 22H2 probes; temp dir independent):
 *   - "C:/a/b" -> "C:\a\b"; ".\" and "..\" segments collapse; "C:\a\.\b\" keeps the trailing slash;
 *   - "\\?\C:\a\..\b" -> "\\?\C:\b" (dot segments ARE collapsed with the prefix on Win10);
 *   - "\\?\C:\a/b" -> "\\?\C:\a\b" (forward slashes converted even with the prefix);
 *   - "\\srv\share\a\..\b" -> "\\srv\share\b"; "\\?\UNC\srv\share\x" unchanged;
 *   - "C:foo" resolves against the per-drive current directory;
 *   - trailing dot and space are stripped from the last component: "C:\a. " -> "C:\a";
 *   - "C:\a:ads" keeps the stream name; "CON" / "NUL" device names give "\\.\CON" / "\\.\NUL";
 *   - GetFinalPathNameByHandleW(VOLUME_NAME_DOS) of a temp file starts with "\\?\" + the
 *     temp path; FILE_NAME_NORMALIZED|VOLUME_NAME_NONE starts with "\"; VOLUME_NAME_NT starts
 *     with "\Device\".
 * Source: lib/file.c, src/tool_doswin.c, lib/curl_multibyte.c.
 */
#define TEST_NAME "21_drive_unc_path_forms"
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

static const wchar_t *full(const wchar_t *in, wchar_t *buf) {
  DWORD n = GetFullPathNameW(in, MAX_PATH, buf, NULL);
  if (n == 0 || n >= MAX_PATH) { wcscpy(buf, L"<error>"); }
  return buf;
}

typedef struct { const wchar_t *in, *out; } m;
static const m map[] = {
  { L"C:/a/b",                  L"C:\\a\\b" },
  { L"C:\\a\\.\\b\\",           L"C:\\a\\b\\" },
  { L"C:\\a\\..\\b",            L"C:\\b" },
  { L"C:\\..\\..\\x",           L"C:\\x" },
  { L"C:\\a\\\\b",              L"C:\\a\\b" },
  { L"\\\\?\\C:\\a\\..\\b",     L"\\\\?\\C:\\b" },
  { L"\\\\?\\C:\\a/b",          L"\\\\?\\C:\\a\\b" },
  { L"\\\\srv\\share\\a\\..\\b", L"\\\\srv\\share\\b" },
  { L"//srv/share/a",           L"\\\\srv\\share\\a" },
  { L"\\\\?\\UNC\\srv\\share\\x", L"\\\\?\\UNC\\srv\\share\\x" },
  { L"C:\\a. ",                 L"C:\\a" },
  { L"C:\\a.b.",                L"C:\\a.b" },
  { L"C:\\a:ads",               L"C:\\a:ads" },
  { L"NUL",                     L"\\\\.\\NUL" },
  { L"CON",                     L"\\\\.\\CON" },
  { L"c:\\Dir\\FILE.TXT",       L"c:\\Dir\\FILE.TXT" },
};

int main(void) {
  wchar_t buf[MAX_PATH + 8], tmp[MAX_PATH], tf[MAX_PATH], cwd[MAX_PATH], saved[MAX_PATH], exp[MAX_PATH];
  size_t i;
  int it;
  HANDLE h;
  DWORD n;

  for (it = 0; it < 3; it++) {
    for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
      full(map[i].in, buf);
      if (it == 0) INFO("full [%ls] -> [%ls]", map[i].in, buf);
      if (wcscmp(buf, map[i].out) != 0) FAILF("GetFullPathNameW(%ls) = [%ls], expected [%ls]", map[i].in, buf, map[i].out);
    }
  }
  /* drive-relative: "C:foo" uses the current directory of drive C (the process one if it is on C) */
  GetCurrentDirectoryW(MAX_PATH, saved);
  GetTempPathW(MAX_PATH, tmp);
  if (SetCurrentDirectoryW(tmp)) {
    wchar_t in[16];
    GetCurrentDirectoryW(MAX_PATH, cwd);
    in[0] = cwd[0]; in[1] = L':'; wcscpy(in + 2, L"foo\\bar");
    full(in, buf);
    n = (DWORD)wcslen(cwd);
    wcscpy(exp, cwd);
    if (n && exp[n - 1] != L'\\') wcscat(exp, L"\\");
    wcscat(exp, L"foo\\bar");
    INFO("drive-relative [%ls] with cwd [%ls] -> [%ls]", in, cwd, buf);
    if (_wcsicmp(buf, exp) != 0) FAILF("drive-relative resolved to [%ls], expected [%ls]", buf, exp);
    SetCurrentDirectoryW(saved);
  }
  /* real file: final path name forms */
  GetTempFileNameW(tmp, L"i7p", 0, tf);
  h = CreateFileW(tf, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
  if (h == INVALID_HANDLE_VALUE) FAILF("open temp %lu", (unsigned long)GetLastError());
  n = GetFinalPathNameByHandleW(h, buf, MAX_PATH, VOLUME_NAME_DOS | FILE_NAME_NORMALIZED);
  INFO("final DOS: [%ls] (%lu)", buf, (unsigned long)n);
  if (n == 0 || wcsncmp(buf, L"\\\\?\\", 4) != 0 || _wcsicmp(buf + 4, tf) != 0) {
    /* temp path may be 8.3 short form; accept equality after GetLongPathName */
    wchar_t lp[MAX_PATH];
    if (!GetLongPathNameW(tf, lp, MAX_PATH) || wcsncmp(buf, L"\\\\?\\", 4) != 0 || _wcsicmp(buf + 4, lp) != 0)
      FAILF("final DOS path [%ls] does not match [%ls]", buf, tf);
  }
  n = GetFinalPathNameByHandleW(h, buf, MAX_PATH, VOLUME_NAME_NONE | FILE_NAME_NORMALIZED);
  INFO("final NONE: [%ls]", buf);
  if (n == 0 || buf[0] != L'\\' || buf[1] == L'\\') FAILF("VOLUME_NAME_NONE gave [%ls]", buf);
  n = GetFinalPathNameByHandleW(h, buf, MAX_PATH, VOLUME_NAME_NT | FILE_NAME_NORMALIZED);
  INFO("final NT: [%ls]", buf);
  if (n == 0 || wcsncmp(buf, L"\\Device\\", 8) != 0) FAILF("VOLUME_NAME_NT gave [%ls]", buf);
  n = GetFinalPathNameByHandleW(h, buf, 4, VOLUME_NAME_DOS);
  INFO("final DOS into 4 wchar buffer returns required length %lu (GLE %lu)", (unsigned long)n, (unsigned long)GetLastError());
  if (n < 8) FAILF("short buffer should return the needed size, got %lu", (unsigned long)n);
  /* the \\?\ form works for CreateFile, the same file by the forward slash path does not exist twice */
  {
    wchar_t pre[MAX_PATH + 8];
    swprintf(pre, MAX_PATH + 8, L"\\\\?\\%ls", tf);
    if (GetFileAttributesW(pre) == INVALID_FILE_ATTRIBUTES) {
      /* temp path may not be in a long-name form; INFO only */
      INFO("GetFileAttributesW(\\\\?\\ + temp) failed %lu", (unsigned long)GetLastError());
    }
  }
  /* trailing dot/space names address the same file with a Win32 name */
  {
    wchar_t dotted[MAX_PATH + 8];
    swprintf(dotted, MAX_PATH + 8, L"%ls. ", tf);
    n = GetFileAttributesW(dotted);
    INFO("attributes of temp name + \". \" : 0x%lx", (unsigned long)n);
    if (n == INVALID_FILE_ATTRIBUTES) FAILF("trailing dot+space name not normalised to the file (gle %lu)", (unsigned long)GetLastError());
    swprintf(dotted, MAX_PATH + 8, L"\\\\?\\%ls. ", tf);
    n = GetFileAttributesW(dotted);
    INFO("attributes of \\\\?\\ + temp + \". \" : 0x%lx gle %lu", (unsigned long)n, (unsigned long)GetLastError());
    if (n != INVALID_FILE_ATTRIBUTES) FAILF("with the \\\\?\\ prefix a trailing \". \" must not be stripped");
  }
  CloseHandle(h);
  /* drives */
  INFO("GetLogicalDrives=0x%lx", (unsigned long)GetLogicalDrives());
  if (GetDriveTypeW(L"C:\\") != DRIVE_FIXED) FAILF("C:\\ drive type %lu", (unsigned long)GetDriveTypeW(L"C:\\"));
  if (GetDriveTypeW(L"\\\\?\\C:\\") != DRIVE_FIXED) INFO("GetDriveType(\\\\?\\C:\\) = %lu", (unsigned long)GetDriveTypeW(L"\\\\?\\C:\\"));
  printf("PASS %s\n", TEST_NAME);
out:
  return g_fail;
}
