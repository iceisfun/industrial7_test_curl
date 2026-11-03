/*
 * Test: 13_console_cp_setmode_u16
 *
 * Purpose: cover the console and text-mode calls that curl's Windows tool
 *          touches when it sets up wide or UTF-8 output: SetConsoleOutputCP
 *          and GetConsoleOutputCP for CP_UTF8, and _setmode(_O_U16TEXT)
 *          which switches a CRT stream to UTF-16 text. The U16 check runs on
 *          a temporary file stream, not on stdout, so the harness's stdout
 *          is never put into a mode that breaks printf.
 *
 * APIs:    SetConsoleOutputCP, GetConsoleOutputCP, _wfopen, _fileno,
 *          _setmode, fputws, fclose, fread, GetTempPathW, DeleteFileW,
 *          GetLastError
 *
 * Success: - SetConsoleOutputCP(65001) succeeds (or the test SKIPs when no
 *            console is attached: error 6 ERROR_INVALID_HANDLE, 12
 *            ERROR_INVALID_ACCESS as wine reports it, or 120
 *            ERROR_CALL_NOT_IMPLEMENTED; any other error is a FAIL), and
 *            GetConsoleOutputCP then
 *            returns 65001; the original code page is restored
 *          - _setmode(fd, _O_U16TEXT) on a file opened with "wb" returns the
 *            previous mode _O_BINARY (0x8000)
 *          - fputws(L"h\u00e9\u20ac\n") writes 68 00 E9 00 AC 20 followed by
 *            the newline. A byte-order mark FF FE in front is CRT dependent
 *            (wine writes none), so it is accepted but not required. The
 *            newline is accepted as LF or CR LF for the same reason
 *            (wine writes CR LF)
 *
 * Source:  lib/curlx/win32-fopen.c (wide-path plumbing) and
 *          lib/curlx/multibyte.c (UTF-8 handling) are the code that
 *          depends on a UTF-8 console and U16 text output for wide tools.
 *          The curl build sets _setmode(_O_BINARY) on its own streams
 *          (lib/curl_setup.h:1281, CURL_BINMODE), which this test does not
 *          repeat; it checks the mode switch itself.
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
#include <errno.h>
#include <fcntl.h>
#include <io.h>

#define NAME "console_cp_setmode_u16"

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if(!(cond)) {                                                          \
      printf("FAIL %s: ", NAME);                                           \
      printf(__VA_ARGS__);                                                 \
      printf(" [line %d, GetLastError=%lu, errno=%d]\n", __LINE__,         \
             (unsigned long)GetLastError(), errno);                        \
      rc = 1;                                                              \
      goto out;                                                            \
    }                                                                      \
  } while(0)

int main(void)
{
  int rc = 0;
  UINT orig_cp = 0;
  int restore_cp = 0;
  wchar_t tmp[MAX_PATH];
  wchar_t path[MAX_PATH + 64];
  FILE *f = NULL;
  int fd, prev;
  unsigned char raw[32];
  size_t got;
  static const unsigned char want_units[] = {
    0x68, 0x00, 0xE9, 0x00, 0xAC, 0x20
  };
  size_t off;
  int wrote_file = 0;
  int console_skip = 0;
  DWORD console_err = 0;

  /* 1. console code page */
  orig_cp = GetConsoleOutputCP();
  if(!SetConsoleOutputCP(65001)) {
    /* no console attached (the harness usually has none): the console part
     * cannot run, but the U16 file check below still does */
    console_err = GetLastError();
    if(console_err == ERROR_INVALID_HANDLE ||
       console_err == ERROR_INVALID_ACCESS ||
       console_err == ERROR_CALL_NOT_IMPLEMENTED)
      console_skip = 1;
    else
      CHECK(0, "SetConsoleOutputCP(65001) failed");
  }
  else {
    restore_cp = 1;
    CHECK(GetConsoleOutputCP() == 65001, "GetConsoleOutputCP returned %u",
          (unsigned)GetConsoleOutputCP());
    CHECK(SetConsoleOutputCP(orig_cp ? orig_cp : 437),
          "restoring console code page failed");
    restore_cp = 0;
  }

  /* 2. U16 text mode on a file stream */
  CHECK(GetTempPathW(MAX_PATH, tmp) > 0, "GetTempPathW failed");
  _snwprintf(path, MAX_PATH + 64, L"%lsucorp13-%lu.txt", tmp,
             (unsigned long)GetCurrentProcessId());
  path[MAX_PATH + 63] = 0;

  f = _wfopen(path, L"wb");
  CHECK(f != NULL, "_wfopen(wb) failed");
  wrote_file = 1;
  fd = _fileno(f);
  CHECK(fd >= 0, "_fileno returned %d", fd);

  prev = _setmode(fd, _O_U16TEXT);
  CHECK(prev == _O_BINARY, "_setmode previous mode 0x%x, expected _O_BINARY",
        (unsigned)prev);

  CHECK(fputws(L"hé€\n", f) >= 0, "fputws failed");
  CHECK(fclose(f) == 0, "fclose after U16 write failed");
  f = NULL;

  /* 3. read the raw bytes back in binary mode */
  f = _wfopen(path, L"rb");
  CHECK(f != NULL, "_wfopen(rb) failed");
  memset(raw, 0, sizeof(raw));
  got = fread(raw, 1, sizeof(raw), f);
  /* optional BOM (CRT dependent), then h e-acute euro, then the newline */
  off = (got >= 2 && raw[0] == 0xFF && raw[1] == 0xFE) ? 2 : 0;
  CHECK(got - off == 6 + 2 || got - off == 6 + 4,
        "U16 payload is %lu bytes after BOM, expected 8 or 10",
        (unsigned long)(got - off));
  CHECK(memcmp(raw + off, want_units, sizeof(want_units)) == 0,
        "U16 code units differ from 68 00 E9 00 AC 20");
  /* newline: LF or CR LF, both accepted */
  if(got - off == 10)
    CHECK(raw[off + 6] == 0x0D && raw[off + 7] == 0x00 &&
          raw[off + 8] == 0x0A && raw[off + 9] == 0x00,
          "CRLF newline bytes wrong");
  else
    CHECK(raw[off + 6] == 0x0A && raw[off + 7] == 0x00,
          "LF newline bytes wrong");
  CHECK(fclose(f) == 0, "fclose after read failed");
  f = NULL;

  if(console_skip) {
    printf("SKIP %s: no console attached (SetConsoleOutputCP error %lu); "
           "U16 text-mode part passed\n", NAME, (unsigned long)console_err);
    rc = 77;
  }
  else
    printf("PASS %s\n", NAME);

out:
  if(f)
    fclose(f);
  if(restore_cp && orig_cp)
    SetConsoleOutputCP(orig_cp);
  if(wrote_file)
    _wunlink(path);
  return rc;
}
