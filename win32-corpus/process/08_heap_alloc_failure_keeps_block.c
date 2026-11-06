/*
 * Test: 08_heap_alloc_failure_keeps_block
 *
 * Purpose: verify the failure paths of the heap allocator as curl's safe
 *   realloc pattern uses them. A HeapAlloc of an impossible size must return
 *   NULL, and a HeapReAlloc to an impossible size must return NULL while
 *   leaving the original block allocated and unchanged, so the caller can
 *   still free it. Without this guarantee a "p = realloc(p, n)" style caller
 *   leaks or corrupts memory.
 *
 * APIs: GetProcessHeap, HeapAlloc, HeapReAlloc, HeapSize, HeapValidate,
 *   HeapFree, GetLastError.
 *
 * Success means: HeapAlloc(2^50 bytes) returns NULL with a memory-related
 *   error (ERROR_NOT_ENOUGH_MEMORY, 8, on Win10 22H2); HeapReAlloc to 2^50
 *   returns NULL; the original 100-byte block still holds its pattern and
 *   HeapSize still reports >= 100; HeapValidate passes; HeapFree succeeds.
 *
 * Source reference: grep of lib/, src/ and tests/ finds no direct HeapAlloc
 *   or HeapReAlloc call sites. The contract tested (a failed realloc leaves the
 *   old block valid) is what curl's grow-buffer code needs: lib/getenv.c:42
 *   reallocs into a temporary, checks it, and only then overwrites buf.
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

#define NAME "heap_alloc_failure_keeps_block"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

static int run(void)
{
  HANDLE heap = GetProcessHeap();
  SIZE_T huge = (SIZE_T)1 << 50;  /* 1 PiB: cannot be satisfied */
  unsigned char *p, *q, *r;
  SIZE_T i, sz;
  DWORD err;

  if(heap == NULL)
    FAILF("GetProcessHeap returned NULL");

  /* 1. Impossible allocation returns NULL. */
  SetLastError(0);
  r = (unsigned char *)HeapAlloc(heap, 0, huge);
  err = GetLastError();
  if(r != NULL) {
    HeapFree(heap, 0, r);
    FAILF("HeapAlloc(2^50) unexpectedly succeeded");
  }
  if(err != ERROR_NOT_ENOUGH_MEMORY)
    FAILF("HeapAlloc(2^50) error %lu, expected ERROR_NOT_ENOUGH_MEMORY (8)",
          (unsigned long)err);

  /* 2. Failed HeapReAlloc leaves the original block intact. */
  p = (unsigned char *)HeapAlloc(heap, HEAP_ZERO_MEMORY, 100);
  if(!p)
    FAILF("HeapAlloc(100)");
  for(i = 0; i < 100; i++)
    p[i] = (unsigned char)(0x40 + (i % 26));

  q = (unsigned char *)HeapReAlloc(heap, 0, p, huge);
  if(q != NULL) {
    HeapFree(heap, 0, q);
    FAILF("HeapReAlloc(2^50) unexpectedly succeeded");
  }

  /* The old block must still be valid and unchanged. */
  for(i = 0; i < 100; i++) {
    if(p[i] != (unsigned char)(0x40 + (i % 26)))
      FAILF("original block corrupted at offset %lu after failed realloc", (unsigned long)i);
  }
  sz = HeapSize(heap, 0, p);
  if(sz == (SIZE_T)-1)
    FAILF("HeapSize on original block after failed realloc");
  if(sz < 100)
    FAILF("HeapSize=%lu after failed realloc, expected >= 100", (unsigned long)sz);
  if(!HeapValidate(heap, 0, p))
    FAILF("HeapValidate after failed realloc");

  if(!HeapFree(heap, 0, p))
    FAILF("HeapFree of original block after failed realloc");

  return 0;
}

int main(void)
{
  int rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
