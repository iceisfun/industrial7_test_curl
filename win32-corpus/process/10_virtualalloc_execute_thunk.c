/*
 * Test: 10_virtualalloc_execute_thunk
 *
 * Purpose: allocate a page with VirtualAlloc, write a tiny x64 machine-code
 *   function into it, flip the page to PAGE_EXECUTE_READ with VirtualProtect
 *   (W^X transition, as JIT and trampoline code does), and call it. Verifies
 *   that the executable transition is honoured and that the code returns the
 *   expected value. Finally flips back to read-write and releases the page.
 *
 * APIs: GetSystemInfo, VirtualAlloc (MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE),
 *   VirtualProtect (PAGE_EXECUTE_READ, then PAGE_READWRITE), VirtualQuery,
 *   VirtualFree (MEM_RELEASE).
 *
 * Success means: VirtualProtect to PAGE_EXECUTE_READ reports old PAGE_READWRITE,
 *   VirtualQuery reports PAGE_EXECUTE_READ, the call through the function
 *   pointer returns 42, and restoring PAGE_READWRITE reports old
 *   PAGE_EXECUTE_READ before the page is released.
 *
 * Source reference: none. grep of lib/, src/ and tests/ finds no executable
 *   page allocation; this covers the W^X permission transition used by
 *   generated code, which the corpus needs for later JIT-style helpers.
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

#define NAME "virtualalloc_execute_thunk"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

typedef int (*thunk_fn)(void);

/* mov eax, 42 ; ret   (x64 Windows and x86-64 SysV both return int in eax) */
static const unsigned char thunk_42[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

static int run(void)
{
  void *mem;
  DWORD old = 0;
  thunk_fn fn;
  MEMORY_BASIC_INFORMATION mbi;
  int r;

  mem = VirtualAlloc(NULL, sizeof(thunk_42), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if(!mem) {
    if(GetLastError() == ERROR_NOT_SUPPORTED)
      SKIPF("VirtualAlloc not supported");
    FAILF("VirtualAlloc(RW)");
  }
  memcpy(mem, thunk_42, sizeof(thunk_42));

  if(!VirtualProtect(mem, sizeof(thunk_42), PAGE_EXECUTE_READ, &old))
    FAILF("VirtualProtect(PAGE_EXECUTE_READ)");
  if(old != PAGE_READWRITE)
    FAILF("old protection 0x%lx, expected PAGE_READWRITE", (unsigned long)old);

  if(VirtualQuery(mem, &mbi, sizeof(mbi)) != sizeof(mbi))
    FAILF("VirtualQuery");
  if(mbi.Protect != PAGE_EXECUTE_READ)
    FAILF("protect 0x%lx after transition, expected PAGE_EXECUTE_READ",
          (unsigned long)mbi.Protect);

  /* The function pointer is obtained by copying the bits; no UB casts. */
  memcpy(&fn, &mem, sizeof(fn));
  r = fn();
  if(r != 42)
    FAILF("thunk returned %d, expected 42", r);

  /* Return to writable memory before releasing it. */
  old = 0;
  if(!VirtualProtect(mem, sizeof(thunk_42), PAGE_READWRITE, &old))
    FAILF("VirtualProtect(PAGE_READWRITE)");
  if(old != PAGE_EXECUTE_READ)
    FAILF("old protection 0x%lx, expected PAGE_EXECUTE_READ", (unsigned long)old);

  if(!VirtualFree(mem, 0, MEM_RELEASE))
    FAILF("VirtualFree(MEM_RELEASE)");
  return 0;
}

int main(void)
{
  int rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
