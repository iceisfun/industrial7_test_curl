# Focused curl test corpus

A curated subset of curl's own test suite (`curl/tests/data/testNNNN`), run
with curl's stock `runtests.pl` against the curl tree in `../curl`.

- `tests.txt`: the selected tests, one per line: `<number> <category> <name>`.
  Edit it to add or drop tests; `run.sh` reads the numbers from here.
- `run.sh`: builds (optional) and runs the corpus.
- `results/`: one log per run.

## Usage

```sh
corpus/run.sh --build        # first time: autoreconf, configure, make curl + test servers
corpus/run.sh                # run all selected tests, 8 jobs
corpus/run.sh -j 4           # fewer jobs
corpus/run.sh 1 2 9          # run specific test numbers only
corpus/run.sh --list         # print selected numbers
```

## Selection

- 208 tests selected from the 992 HTTP-only tests plus the file-protocol tests.
  Tests that need a separate tool/libtest binary, or a non-HTTP server
  (ftp, smtp, imap, pop3, sftp, mqtt, ...), are left out. Nothing here needs
  stunnel, nghttpx or the HTTP/2 and HTTP/3 servers.
- Categories and caps: core (20), request-body (24), transfer (20),
  redirect (20), output (18), auth (18), file (16), proxy (14), cookies (14),
  url (14), errors (14), headers (13), multi (3). Within each category the
  picks are spread evenly across the category's numeric range.
- Last run: 193 of 208 ran, all 193 passed. The other 15 are skipped by
  curl's own feature checks on this build (no IDN, PSL, GSS-API, httpsig,
  Unicode, ssl-sessions support), so they are not failures.

## Build configuration

`--enable-debug --with-openssl --with-zlib --with-brotli --with-zstd --without-libpsl --disable-manual --disable-docs`

libpsl is not installed here, so it is disabled. Add it to `run.sh`'s
configure line if you install it.

## Notes

- `runtests.pl` silently runs nothing if test numbers have leading zeros,
  so `run.sh` strips them. Keep that in mind if you call `runtests.pl` directly.
