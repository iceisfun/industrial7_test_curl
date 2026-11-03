/*
 * Test: logical_processor_info_ex
 *
 * Purpose: Enumerate processor topology with GetLogicalProcessorInformationEx
 *   using the size-query protocol, walk the variable-length records by their
 *   Size fields, and check that the core records account for every active
 *   logical processor. NUMA node records are checked for at least one node.
 *
 * APIs: GetLogicalProcessorInformationEx, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
 *   GetActiveProcessorCount (kernel32).
 *
 * Success means: the NULL-buffer query returns FALSE with
 *   ERROR_INSUFFICIENT_BUFFER and a nonzero length; the sized query returns
 *   TRUE; every record has Size > 0 and stays inside the buffer; core records
 *   (RelationProcessorCore) sum their GroupMask bit counts to exactly
 *   GetActiveProcessorCount(ALL_PROCESSOR_GROUPS); at least one NUMA node
 *   record (RelationNumaNode) is present. SKIP (77) when the call reports
 *   ERROR_CALL_NOT_IMPLEMENTED or ERROR_NOT_SUPPORTED.
 *
 * Source reference: none in curl's tree. curl does not size threads from
 *   processor topology; this pins the topology contract for the corpus.
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
#define TEST_NAME "logical_processor_info_ex"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned popcount_kaff(ULONG_PTR v)
{
  unsigned n = 0;
  while(v) {
    n += (unsigned)(v & 1);
    v >>= 1;
  }
  return n;
}

/* Walks a buffer of variable-length records. Returns the core logical
 * processor total, or -1 on a malformed record. */
static long walk_records(unsigned char *buf, DWORD len, int *numa_nodes,
                         int *core_records)
{
  DWORD off = 0;
  long total = 0;

  *numa_nodes = 0;
  *core_records = 0;
  while(off < len) {
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *info =
      (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)(buf + off);
    DWORD g;

    if(info->Size == 0 || off + info->Size > len)
      return -1;

    if(info->Relationship == RelationProcessorCore) {
      (*core_records)++;
      for(g = 0; g < info->Processor.GroupCount; g++)
        total += popcount_kaff(info->Processor.GroupMask[g].Mask);
    }
    else if(info->Relationship == RelationNumaNode) {
      (*numa_nodes)++;
    }
    off += info->Size;
  }
  if(off != len)
    return -1;
  return total;
}

int main(void)
{
  DWORD len = 0, active;
  unsigned char *buf;
  BOOL ok;
  int numa = 0, cores = 0;
  long total;

  if(!GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len)) {
    DWORD err = GetLastError();
    if(err == ERROR_CALL_NOT_IMPLEMENTED || err == ERROR_NOT_SUPPORTED) {
      printf("SKIP %s: GetLogicalProcessorInformationEx not implemented (err=%lu)\n",
             TEST_NAME, (unsigned long)err);
      return 77;
    }
    if(err != ERROR_INSUFFICIENT_BUFFER) {
      printf("FAIL %s: size query GetLastError=%lu (want ERROR_INSUFFICIENT_BUFFER=122)\n",
             TEST_NAME, (unsigned long)err);
      return 1;
    }
  }
  else {
    printf("FAIL %s: NULL-buffer query unexpectedly succeeded\n", TEST_NAME);
    return 1;
  }
  if(len == 0) {
    printf("FAIL %s: size query returned length 0\n", TEST_NAME);
    return 1;
  }

  buf = (unsigned char *)malloc(len);
  if(!buf) {
    printf("FAIL %s: malloc(%lu) failed\n", TEST_NAME, (unsigned long)len);
    return 1;
  }
  ok = GetLogicalProcessorInformationEx(RelationProcessorCore,
                                        (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)buf,
                                        &len);
  if(!ok) {
    printf("FAIL %s: sized call GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    free(buf);
    return 1;
  }

  total = walk_records(buf, len, &numa, &cores);
  free(buf);
  if(total < 0) {
    printf("FAIL %s: malformed record stream in core query\n", TEST_NAME);
    return 1;
  }
  if(cores < 1) {
    printf("FAIL %s: no RelationProcessorCore records\n", TEST_NAME);
    return 1;
  }

  active = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
  if(total != (long)active) {
    printf("FAIL %s: core records account for %ld logical processors, active=%lu\n",
           TEST_NAME, total, (unsigned long)active);
    return 1;
  }

  /* NUMA query, same protocol. */
  len = 0;
  if(GetLogicalProcessorInformationEx(RelationNumaNode, NULL, &len) ||
     GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0) {
    printf("FAIL %s: NUMA size query did not report ERROR_INSUFFICIENT_BUFFER\n", TEST_NAME);
    return 1;
  }
  buf = (unsigned char *)malloc(len);
  if(!buf) {
    printf("FAIL %s: malloc for NUMA failed\n", TEST_NAME);
    return 1;
  }
  ok = GetLogicalProcessorInformationEx(RelationNumaNode,
                                        (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)buf,
                                        &len);
  if(!ok) {
    printf("FAIL %s: NUMA sized call GetLastError=%lu\n",
           TEST_NAME, (unsigned long)GetLastError());
    free(buf);
    return 1;
  }
  if(walk_records(buf, len, &numa, &cores) < 0) {
    free(buf);
    printf("FAIL %s: malformed NUMA record stream\n", TEST_NAME);
    return 1;
  }
  free(buf);
  if(numa < 1) {
    printf("FAIL %s: NUMA query returned no RelationNumaNode record\n", TEST_NAME);
    return 1;
  }

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
