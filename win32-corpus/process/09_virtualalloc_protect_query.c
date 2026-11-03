/*
 * Test: 09_virtualalloc_protect_query
 *
 * Purpose: exercise the page-level memory API: reserve address space with
 *   VirtualAlloc(MEM_RESERVE), commit one page, change its protection with
 *   VirtualProtect and verify the previous protection value it reports, check
 *   state and protection through VirtualQuery at each step, and release the
 *   whole reservation with VirtualFree(MEM_RELEASE). Verifies that an
 *   uncommitted neighbouring page stays in the MEM_RESERVE state.
 *
 * APIs: GetSystemInfo, VirtualAlloc (MEM_RESERVE, MEM_COMMIT), VirtualQuery,
 *   VirtualProtect, VirtualFree (MEM_RELEASE).
 *
 * Success means: reserve gives MEM_RESERVE; commit gives MEM_COMMIT with
 *   PAGE_READWRITE; VirtualProtect(PAGE_READONLY) reports old PAGE_READWRITE;
 *   VirtualQuery shows PAGE_READONLY; restoring PAGE_READWRITE reports old
 *   PAGE_READONLY and writes then succeed; the second page is still MEM_RESERVE;
 *   after MEM_RELEASE, VirtualQuery reports MEM_FREE.
 *
 * Source reference: grep of lib/, src/ and tests/ finds no VirtualAlloc,
 *   VirtualProtect or VirtualQuery call sites. This covers the page layer
 *   beneath the heap that curl's allocations come from.
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

#define NAME "virtualalloc_protect_query"
#define FAILF(...) do { printf("FAIL %s: ", NAME); printf(__VA_ARGS__); \
  printf(" (gle=%lu)\n", (unsigned long)GetLastError()); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP %s: ", NAME); printf(__VA_ARGS__); \
  printf("\n"); return 77; } while (0)

static int query(const void *addr, DWORD *state, DWORD *protect)
{
  MEMORY_BASIC_INFORMATION mbi;
  if(VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi))
    return 0;
  *state = mbi.State;
  *protect = mbi.Protect;
  return 1;
}

static int run(void)
{
  SYSTEM_INFO si;
  SIZE_T page;
  unsigned char *p;
  DWORD state = 0, prot = 0, old = 0;
  SIZE_T i;

  GetSystemInfo(&si);
  page = si.dwPageSize;
  if(page == 0)
    FAILF("GetSystemInfo returned page size 0");

  p = (unsigned char *)VirtualAlloc(NULL, 2 * page, MEM_RESERVE, PAGE_NOACCESS);
  if(!p)
    FAILF("VirtualAlloc(MEM_RESERVE)");
  if(!query(p, &state, &prot))
    FAILF("VirtualQuery(reserved)");
  if(state != MEM_RESERVE)
    FAILF("state after MEM_RESERVE is 0x%lx, expected MEM_RESERVE", (unsigned long)state);

  if(!VirtualAlloc(p, page, MEM_COMMIT, PAGE_READWRITE))
    FAILF("VirtualAlloc(MEM_COMMIT, RW)");
  if(!query(p, &state, &prot))
    FAILF("VirtualQuery(committed)");
  if(state != MEM_COMMIT)
    FAILF("state after commit is 0x%lx, expected MEM_COMMIT", (unsigned long)state);
  if(prot != PAGE_READWRITE)
    FAILF("protect after commit is 0x%lx, expected PAGE_READWRITE", (unsigned long)prot);

  memset(p, 0x3C, page);
  for(i = 0; i < page; i++) {
    if(p[i] != 0x3C)
      FAILF("write/read mismatch at offset %lu", (unsigned long)i);
  }

  /* Drop to read-only and check the reported old protection. */
  if(!VirtualProtect(p, page, PAGE_READONLY, &old))
    FAILF("VirtualProtect(PAGE_READONLY)");
  if(old != PAGE_READWRITE)
    FAILF("VirtualProtect old=0x%lx, expected PAGE_READWRITE", (unsigned long)old);
  if(!query(p, &state, &prot))
    FAILF("VirtualQuery(after readonly)");
  if(prot != PAGE_READONLY)
    FAILF("protect after readonly is 0x%lx", (unsigned long)prot);

  /* Restore write access; the old value must now be PAGE_READONLY. */
  old = 0;
  if(!VirtualProtect(p, page, PAGE_READWRITE, &old))
    FAILF("VirtualProtect(PAGE_READWRITE)");
  if(old != PAGE_READONLY)
    FAILF("VirtualProtect old=0x%lx, expected PAGE_READONLY", (unsigned long)old);
  p[0] = 0x7E;
  if(p[0] != 0x7E)
    FAILF("write after restoring RW failed");

  /* The second page of the reservation has not been committed. */
  if(!query(p + page, &state, &prot))
    FAILF("VirtualQuery(second page)");
  if(state != MEM_RESERVE)
    FAILF("second page state 0x%lx, expected MEM_RESERVE", (unsigned long)state);

  /* Releasing the reservation frees the whole region. */
  if(!VirtualFree(p, 0, MEM_RELEASE))
    FAILF("VirtualFree(MEM_RELEASE)");
  if(!query(p, &state, &prot))
    FAILF("VirtualQuery(after release)");
  if(state != MEM_FREE)
    FAILF("state after release is 0x%lx, expected MEM_FREE", (unsigned long)state);

  return 0;
}

int main(void)
{
  int rc = run();
  if(rc == 0)
    printf("PASS %s\n", NAME);
  return rc;
}
