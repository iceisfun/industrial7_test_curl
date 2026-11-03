# Windows API test corpus (for getting curl running on Windows)

205 standalone C programs, one API behaviour each, grouped by area:
dynload, threads, tls, winsock, afd, dns, iocp, unicode, crypto, schannel,
timing, process, netinfo, curlsupport (sequences copied from curl's
`lib/`), ipc (WSAEventSelect wakeups).

## Run

    ./run.sh              # compile all with x86_64-w64-mingw32-gcc, run under wine
    ./run.sh winsock tls  # only some areas

Exit codes: 0 PASS, 77 SKIP, 1 FAIL. Build outputs go to `build/`
(`build/summary.txt` has one line per test).

## Last run (wine)

- 188 PASS, 17 SKIP, 0 FAIL, 0 build failures.

## What the SKIPs mean

Each SKIP prints its reason. Two kinds:

1. Wine gaps (11 tests). These tests detect wine via the `wine_get_version`
   export of ntdll. Under wine they SKIP for a specific documented wine
   defect (e.g. TCP_NODELAY optlen, GetFullPathNameW on `\\?\` paths,
   InitOnceExecuteOnce with an out-param). On real Windows the same check
   still FAILs, so these are not hidden. The wine-gap diagnoses were made
   by triage agents with small probes, not confirmed on real Windows.
2. Feature absence (e.g. AFD_CONNECT not dispatched, DnsQueryEx stub,
   SIO_TCP_INITIAL_RTO unsupported, no console attached). These are
   expected to be real on a Windows machine that has the feature, so run
   them there.

## Known open items

- tls/09_declspec_thread_isolation SKIPs because the mingw GCC does not
  apply `__declspec(thread)`. Real Windows coverage of `__declspec(thread)`
  needs an MSVC build, or the test should use `__thread`/`_Thread_local`.
- These tests have not been run on real Windows.
- The corpus does not yet build or run curl itself on Windows. The next
  step is cross-compiling curl with mingw and running it under wine.
