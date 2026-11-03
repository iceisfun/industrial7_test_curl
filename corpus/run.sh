#!/usr/bin/env bash
# Run the focused curl test corpus against the curl tree next to this directory.
#
#   corpus/run.sh                 run all tests in corpus/tests.txt (8 jobs)
#   corpus/run.sh -j 4            change parallelism
#   corpus/run.sh --build         configure + build curl and its test servers first
#   corpus/run.sh 0001 0012       run only the given test numbers
#   corpus/run.sh --list          print the selected test numbers and exit
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
CURL_SRC="$ROOT/curl"
LIST="$HERE/tests.txt"
JOBS=8
BUILD=0
LIST_ONLY=0
TESTS=()

while [ $# -gt 0 ]; do
  case "$1" in
    -j) JOBS="$2"; shift 2 ;;
    -j*) JOBS="${1#-j}"; shift ;;
    --build) BUILD=1; shift ;;
    --list) LIST_ONLY=1; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) TESTS+=("$((10#$1))"); shift ;;
  esac
done

if [ "$LIST_ONLY" = 1 ]; then
  awk '!/^#/ && NF {print $1+0}' "$LIST"
  exit 0
fi

if [ "$BUILD" = 1 ]; then
  cd "$CURL_SRC"
  if [ ! -x configure ]; then autoreconf -fi; fi
  if [ ! -f Makefile ]; then
    ./configure --enable-debug --with-openssl --with-zlib --with-brotli --with-zstd \
      --without-libpsl --disable-manual --disable-docs
  fi
  make -j"$(nproc)"
  make -C tests -j"$(nproc)"
fi

CURL_BIN="$CURL_SRC/src/curl"
if [ ! -x "$CURL_BIN" ] || [ ! -x "$CURL_SRC/tests/server/servers" ]; then
  echo "curl or its test servers are missing; re-run with --build" >&2
  exit 1
fi

if [ ${#TESTS[@]} -gt 0 ]; then
  NUMS=("${TESTS[@]}")
else
  # runtests.pl takes unpadded numbers ("0001" matches nothing), so strip zeros.
  mapfile -t NUMS < <(awk '!/^#/ && NF {print $1+0}' "$LIST")
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="$HERE/results/run-$STAMP.log"
mkdir -p "$HERE/results"

cd "$CURL_SRC/tests"
set +e
perl runtests.pl -c ../src/curl -a -j"$JOBS" "${NUMS[@]}" 2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}
set -e
echo "log: $LOG"
exit "$RC"
