/*
 * Test: 07_heap_alloc_realloc_free
 *
 * Purpose: exercise the process default heap (GetProcessHeap) through the
 *   allocation pattern curl uses on Windows: zeroed allocation, growing and
 *   shrinking with HeapReAlloc, HeapSize, HeapValidate, and HeapFree. Also
 *   covers a private heap created with HeapCreate and destroyed with
 *   HeapDestroy.
 *
 * APIs: GetProcessHeap, HeapAlloc (HEAP_ZERO_MEMORY), HeapReAlloc (flags 0 and
 *   HEAP_ZERO_MEMORY), HeapSize, HeapValidate, HeapFree, HeapCreate,
 *   HeapDestroy.
 *
 * Success means: HEAP_ZERO_MEMORY zeroes the initial block; HeapReAlloc keeps
 *   the old contents on growth and shrink; with HEAP_ZERO_MEMORY the newly
 *   added tail is zero; HeapSize reports at least the requested size; the
 *   default heap validates; HeapFree and HeapDestroy return TRUE.
 *
 * Source reference: grep of lib/, src/ and tests/ finds no direct HeapAlloc
 *   or HeapReAlloc call sites. curl allocates through the CRT (malloc/realloc),
 *   and this test covers the Win32 heap contract beneath that layer, which the
 *   CRT allocations depend on.
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

#define NAME "heap_alloc_realloc_free"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

static int run(void)
{
  HANDLE heap = GetProcessHeap();
  HANDLE priv;
  unsigned char *p, *q, *r, *s;
  SIZE_T i, sz;

  if(heap == NULL)
    FAILF("GetProcessHeap returned NULL");

  /* 1. Zeroed allocation. */
  p = (unsigned char *)HeapAlloc(heap, HEAP_ZERO_MEMORY, 100);
  if(!p)
    FAILF("HeapAlloc(100, HEAP_ZERO_MEMORY)");
  for(i = 0; i < 100; i++) {
    if(p[i] != 0)
      FAILF("HEAP_ZERO_MEMORY not honoured at offset %lu", (unsigned long)i);
  }
  memset(p, 0xAB, 100);

  sz = HeapSize(heap, 0, p);
  if(sz == (SIZE_T)-1)
    FAILF("HeapSize failed");
  if(sz < 100)
    FAILF("HeapSize=%lu, expected >= 100", (unsigned long)sz);

  /* 2. Grow without zeroing: old bytes preserved. */
  q = (unsigned char *)HeapReAlloc(heap, 0, p, 5000);
  if(!q)
    FAILF("HeapReAlloc(grow to 5000)");
  for(i = 0; i < 100; i++) {
    if(q[i] != 0xAB)
      FAILF("grow lost contents at offset %lu", (unsigned long)i);
  }
  memset(q, 0x11, 5000);

  /* 3. Grow with HEAP_ZERO_MEMORY: the new tail is zero, old bytes kept. */
  r = NULL;
  p = (unsigned char *)HeapAlloc(heap, 0, 64);
  if(!p)
    FAILF("HeapAlloc(64)");
  memset(p, 0x22, 64);
  HeapFree(heap, 0, q);  /* free the 5000-byte block from step 2 */
  q = NULL;
  r = (unsigned char *)HeapReAlloc(heap, HEAP_ZERO_MEMORY, p, 4096);
  if(!r)
    FAILF("HeapReAlloc(HEAP_ZERO_MEMORY, 4096)");
  for(i = 0; i < 64; i++) {
    if(r[i] != 0x22)
      FAILF("zeroed grow lost contents at offset %lu", (unsigned long)i);
  }
  for(i = 64; i < 4096; i++) {
    if(r[i] != 0)
      FAILF("HEAP_ZERO_MEMORY did not zero the new tail at offset %lu", (unsigned long)i);
  }

  /* 4. Shrink keeps the leading bytes. */
  s = (unsigned char *)HeapReAlloc(heap, 0, r, 16);
  if(!s)
    FAILF("HeapReAlloc(shrink to 16)");
  for(i = 0; i < 16; i++) {
    if(s[i] != 0x22)
      FAILF("shrink lost contents at offset %lu", (unsigned long)i);
  }
  sz = HeapSize(heap, 0, s);
  if(sz == (SIZE_T)-1 || sz < 16)
    FAILF("HeapSize after shrink=%lu", (unsigned long)sz);

  if(!HeapValidate(heap, 0, s))
    FAILF("HeapValidate(process heap, block) failed");
  if(!HeapFree(heap, 0, s))
    FAILF("HeapFree(process heap)");

  /* 5. Private heap lifecycle. */
  priv = HeapCreate(0, 0, 0);
  if(!priv)
    FAILF("HeapCreate");
  p = (unsigned char *)HeapAlloc(priv, HEAP_ZERO_MEMORY, 256);
  if(!p)
    FAILF("HeapAlloc on private heap");
  memset(p, 0x5C, 256);
  if(!HeapFree(priv, 0, p))
    FAILF("HeapFree on private heap");
  if(!HeapDestroy(priv))
    FAILF("HeapDestroy");

  return 0;
}

int main(void)
{
  int rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
