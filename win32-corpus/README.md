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

## Reference runs

The authority is a real Windows 10 22H2 machine (build 19045), run both as a
standard user (medium integrity) and as an elevated administrator, each in a
fresh virtual machine. Each program is its own process with a 60 second limit;
a run is complete only when the number of result rows equals the number of
programs. Exit codes: 0 PASS, 77 SKIP, 1 FAIL, anything else is a crash.

The programs run under wine only partly: tests that were corrected to the
Windows 10 22H2 behaviour (exact error codes, the wine-gap tests, ipc/03,
dynload/05-07 and others) FAIL under wine by design. A missing API on a
Windows 10 machine is a FAIL, not a SKIP.

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

- tls/09_declspec_thread_isolation SKIPs because the mingw GCC does not
  apply `__declspec(thread)`; needs an MSVC build.
- The corpus does not yet build or run curl itself on Windows.
