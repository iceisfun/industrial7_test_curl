# Windows API test corpus (for getting curl running on Windows)

295 standalone C programs, one API behaviour each, grouped by area:
dynload, threads, tls, winsock, afd, dns, iocp, unicode, crypto, schannel,
timing, process, netinfo, curlsupport (sequences copied from curl's
`lib/`), ipc (WSAEventSelect wakeups).

## Run

    ./run.sh              # compile all with x86_64-w64-mingw32-gcc, run under wine
    ./run.sh winsock tls  # only some areas

Exit codes: 0 PASS, 77 SKIP, 1 FAIL. Build outputs go to `build/`
(`build/summary.txt` has one line per test).

## Last run: Windows 10 22H2 (build 19045)

Final verification: a clean mingw build of all 295 programs (`-Wall -Wextra
-Werror`, no build failures), then the whole corpus in fresh virtual machines,
three runs as a standard user (medium integrity) and three as an elevated
administrator. Every run produced 295 result rows.

| mode | runs | PASS | FAIL | SKIP | crash | timeout | differing between runs |
|------|------|------|------|------|-------|---------|------------------------|
| standard user | 3 | 294 | 0 | 1 | 0 | 0 | 0 |
| administrator | 3 | 294 | 0 | 1 | 0 | 0 | 0 |

Per-program outcomes are identical across all six runs. The one SKIP is
tls/09 (see below).

The earlier wine-only results (188 PASS, 17 SKIP) no longer apply. Of the 11
tests once marked as wine gaps, 7 passed unchanged on Windows; the other 4
(dns/05, dns/11, ipc/03, threads/10) had a wrong or incomplete expectation
that was corrected to the probed Windows behaviour. Two further tests that
printed "wine gap" (unicode/06, winsock/05) match Windows exactly. The tests
that were corrected to Windows behaviour (exact error codes, the former
wine-gap tests, ipc/03, dynload/05-07 and others) FAIL under wine by design.
A missing API on a Windows 10 machine is a FAIL, not a SKIP.

## Running on Windows

1. Cross-compile on Linux with the compiler and flags from `run.sh`
   (`x86_64-w64-mingw32-gcc`, `-municode` for `wmain` programs); `./run.sh`
   leaves the executables in `build/<area>/<name>.exe`.
2. Copy the `.exe` files to one directory on the Windows machine (a local
   disk, not a network share). Use a flat directory and prefix the names with
   the area, for example `winsock__01_foo.exe`.
3. Run each program as its own process from that directory, one at a time or
   a few in parallel, with a 60 second limit per program. Run `timing`, `dns`
   and `netinfo` serially: they measure time or depend on the network stack
   state. Disable real-time antivirus scanning or expect slower runs.
4. The exit code is the result: 0 PASS, 77 SKIP, 1 FAIL, anything else (for
   example 0xC0000005) is a crash, a program killed at the limit is a timeout.
   Each program also prints a `PASS`, `SKIP` or `FAIL` line with a reason.
5. A run is complete only when the number of result rows equals the number of
   programs (295). Collect the results as one archive; directories on small
   virtual FAT shares cannot grow.
6. Run both as a standard user and as an elevated administrator, in a freshly
   booted machine each time, and compare the per-program outcomes between
   repeats.

All programs only use loopback and localhost; no external network is needed.

## What the SKIPs mean

The only SKIP left on Windows 10 is tls/09 (the mingw GCC ignores
`__declspec(thread)`; tls/10 covers the GNU and C11 spellings). Other SKIP
paths are environmental and print their reason: no loopback TCP, a console
not attached, a certificate store without roots.

Some assertions depend on the machine: timer resolution (a process that raised
it to 1 ms switches the 15.6 ms tick checks off), the number of DNS servers or
proxy settings (structure checks only), the build number. Those are marked in
the program headers.

## Known open items

- Not covered: TLS 1.3 resumption (Windows 10 Schannel has no TLS 1.3),
  SNI-based server certificate selection, WSAConnectByName, TransmitFile,
  GetConsoleMode on a real attached console, UNC paths to a real server, IPv6
  connect timeouts.
- The curlsupport, afd and netinfo tests that look at DNS servers or proxy
  settings are structure checks only on a machine that has none.
- `../corpus/` (curl's own runtests.pl tests) needs the curl source tree, perl
  and test servers and was not part of this validation.
- tls/09_declspec_thread_isolation SKIPs because the mingw GCC does not
  apply `__declspec(thread)`; needs an MSVC build.
- The corpus does not yet build or run curl itself on Windows.
