#!/usr/bin/env bash
# Compile every win32-corpus test with mingw and run it under wine.
# Usage: win32-corpus/run.sh [area ...]     (default: all areas)
# Exit codes per test: 0 PASS, 77 SKIP, 1 FAIL. Prints a summary.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="$HERE/build"
CC=x86_64-w64-mingw32-gcc
FLAGS=(-std=c11 -Wall -Wextra -Werror -D_WIN32_WINNT=0x0A00 -DUNICODE -D_UNICODE)
LIBS=(-lws2_32 -ladvapi32 -lbcrypt -lcrypt32 -lsecur32 -ldnsapi -liphlpapi -lwinmm -lnormaliz -luser32 -lkernel32)
if [ $# -gt 0 ]; then AREAS=("$@"); else AREAS=($(cd "$HERE" && ls -d */ | grep -v '^build/' | tr -d /)); fi
export HERE BUILD CC
export FLAGS_STR="${FLAGS[*]}" LIBS_STR="${LIBS[*]}"
rm -rf "$BUILD"; mkdir -p "$BUILD"
one() {
  src="$1"; area="$(basename "$(dirname "$src")")"; name="$(basename "$src" .c)"
  out="$BUILD/$area/$name.exe"; mkdir -p "$BUILD/$area"
  extra=""
  grep -q '\bwmain\b' "$src" && extra="-municode"   # wmain needs the wide entry point
  if ! $CC $FLAGS_STR $extra -o "$out" "$src" $LIBS_STR > "$BUILD/$area/$name.build.log" 2>&1; then
    echo "BUILDFAIL $area/$name"; return
  fi
  line="$(WINEDEBUG=-all timeout 60 wine "$out" 2>/dev/null | tail -1)"
  rc=$?
  echo "RESULT $area/$name $(echo "$line" | cut -c1-160)"
}
export -f one
for a in "${AREAS[@]}"; do find "$HERE/$a" -name '*.c'; done | xargs -P"$(nproc)" -I{} bash -c 'one "$@"' _ {} | tee "$BUILD/summary.txt"
echo "--- summary"
awk '{print $1}' "$BUILD/summary.txt" | sort | uniq -c
