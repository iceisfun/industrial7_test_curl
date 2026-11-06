/*
 * Test: 20_commandlinetoargvw_rules
 * Purpose: the CommandLineToArgvW parsing rules (backslash/quote doubling,
 *          empty arguments, unterminated quotes, argv[0] special cases) that
 *          decide how a path or URL given to curl.exe on a Windows command line
 *          reaches main(); curl's wide-character build gets its argv from the same
 *          rules (the CRT matches them except for argv[0] and the "" quirks).
 * APIs: CommandLineToArgvW, GetCommandLineW, LocalFree.
 * Success: every row of the table below produces exactly the listed argv
 *          (probed on Win10 22H2, identical in std and adm); a NULL command line is not
 *          tested: it crashes with an access violation on 22H2.
 * Source: src/tool_main.c (wide argv handling), tool_doswin.c.
 */
#define TEST_NAME "20_commandlinetoargvw_rules"
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
#include <shellapi.h>

#define MAXA 8
typedef struct { const wchar_t *cmd; int n; const wchar_t *a[MAXA]; } row;

static const row rows[] = {
  { L"a b c",                 3, { L"a", L"b", L"c" } },
  { L"prog \"a b\" c",        3, { L"prog", L"a b", L"c" } },
  { L"prog \"\" x",           3, { L"prog", L"", L"x" } },
  { L"prog a\\b c",           3, { L"prog", L"a\\b", L"c" } },
  { L"prog a\\\\b",           2, { L"prog", L"a\\\\b" } },
  { L"prog \"a\\\"b\"",       2, { L"prog", L"a\"b" } },
  { L"prog \"a\\\\\" b",      3, { L"prog", L"a\\", L"b" } },
  { L"prog \"a\\\\\\\" b\"",  2, { L"prog", L"a\\\" b" } },
  { L"prog a\"b c\"d e",      3, { L"prog", L"ab cd", L"e" } },
  { L"prog \"abc",            2, { L"prog", L"abc" } },
  { L"prog \"\"\"",           2, { L"prog", L"\"" } },
  { L"prog \"a\"\"b\"",       2, { L"prog", L"a\"b" } },
  { L"prog  \t x",            2, { L"prog", L"x" } },
  { L"prog http://h/p?a=1&b=2 -o \"C:\\dir with space\\f.txt\"", 4, { L"prog", L"http://h/p?a=1&b=2", L"-o", L"C:\\dir with space\\f.txt" } },
  { L"\"C:\\Program Files\\x\\prog.exe\" -V", 2, { L"C:\\Program Files\\x\\prog.exe", L"-V" } },
  { L"\"prog\\\" a",          2, { L"prog\\", L"a" } },
  { L"prog \\\\server\\share\\f", 2, { L"prog", L"\\\\server\\share\\f" } },
  { L"prog \"\\\\server\\share\\\"", 2, { L"prog", L"\\\\server\\share\"" } },
  { L"prog caf\xe9 \x65e5\x672c", 3, { L"prog", L"caf\xe9", L"\x65e5\x672c" } },
  { L"prog a\"\"b",           2, { L"prog", L"ab" } },
};

int main(void) {
  size_t i;
  int j, argc, it;
  setvbuf(stdout, NULL, _IONBF, 0);
  wchar_t **argv;

  for (it = 0; it < 3; it++) {
    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
      argc = -1;
      argv = CommandLineToArgvW(rows[i].cmd, &argc);
      if (!argv) FAILF("row %u: NULL argv (gle %lu)", (unsigned)i, (unsigned long)GetLastError());
      if (it == 0) {
        printf("INFO row %2u argc=%d:", (unsigned)i, argc);
        for (j = 0; j < argc; j++) printf(" [%ls]", argv[j]);
        printf("\n");
      }
      if (argc != rows[i].n) { LocalFree(argv); FAILF("row %u: argc %d, expected %d (%ls)", (unsigned)i, argc, rows[i].n, rows[i].cmd); }
      for (j = 0; j < argc; j++)
        if (wcscmp(argv[j], rows[i].a[j]) != 0) { LocalFree(argv); FAILF("row %u arg %d is [%ls], expected [%ls]", (unsigned)i, j, argv[j], rows[i].a[j]); }
      LocalFree(argv);
    }
  }
  /* empty string: argv[0] is the current exe path, argc 1 */
  argc = -1; SetLastError(0);
  argv = CommandLineToArgvW(L"", &argc);
  if (argv) {
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    INFO("empty command line: argc=%d argv0=[%ls]", argc, argc > 0 ? argv[0] : L"");
    if (argc != 1 || _wcsicmp(argv[0], self) != 0) { LocalFree(argv); FAILF("empty command line gave argc %d", argc); }
    LocalFree(argv);
  } else FAILF("empty command line failed %lu", (unsigned long)GetLastError());
  /* the real command line parsed by us matches GetCommandLineW's single program token */
  argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!argv || argc < 1) FAILF("own command line");
  INFO("own command line: argc=%d argv0=[%ls]", argc, argv[0]);
  LocalFree(argv);
  /* CommandLineToArgvW(NULL, &argc) raises an access violation on Win10 22H2 (probed): never pass NULL. */
  printf("PASS %s\n", TEST_NAME);
out:
  return g_fail;
}
