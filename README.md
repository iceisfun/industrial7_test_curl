# industrial7_test_curl

Test corpora for getting curl running in our environment. The curl source
itself is not tracked here (it lives in `curl/`, which is excluded from this
repo and keeps its own upstream git history).

## Contents

- `corpus/`: a focused subset of curl's own test suite (208 tests from
  `curl/tests/data`), run with curl's `runtests.pl` against a local build.
  See `corpus/README.md`.
- `win32-corpus/`: 205 standalone C programs that exercise the Windows APIs
  curl depends on (LoadLibrary/GetProcAddress, threads, TLS, Winsock, AFD,
  DNS, Schannel, ...). Compiled with mingw and run under wine. See
  `win32-corpus/README.md`.

## Quick start

    corpus/run.sh --build          # build curl and its test servers, then run the corpus
    win32-corpus/run.sh            # compile and run the Windows API tests under wine

`curl/` must be present next to these directories for `corpus/run.sh`.
