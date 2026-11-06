/*
 * Test: thread_stack_limits
 *
 * Purpose: stack sizes of worker threads. curl's threaded resolver
 *   (Curl_thread_create -> CreateThread(NULL, 0, func, arg, 0, NULL)) runs
 *   getaddrinfo() on a worker whose stack comes from the executable's
 *   SizeOfStackReserve. This test pins how Windows applies the stack-size
 *   argument and the STACK_SIZE_PARAM_IS_A_RESERVATION flag, and that a
 *   resolver call fits in a small reserved stack.
 *
 * APIs: CreateThread (dwStackSize, STACK_SIZE_PARAM_IS_A_RESERVATION),
 *   GetCurrentThreadStackLimits, WaitForSingleObject, GetExitCodeThread,
 *   getaddrinfo.
 *
 * Success (probed on Windows 10 22H2): the main thread's reserved stack equals
 *   the PE header SizeOfStackReserve; a thread created with dwStackSize 0 has
 *   the same reserve; a non-zero dwStackSize WITHOUT the reservation flag only
 *   sets the initial commit, so the reserve is still the PE default; with the
 *   flag the reserve is exactly the requested size (64 KB, 256 KB, 8 MB, all
 *   page multiples); getaddrinfo("127.0.0.1") and getaddrinfo("localhost")
 *   succeed inside a 128 KB reserved stack.
 *
 * curl reference: lib/curl_threads.c:35 (CreateThread with stack size 0).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define TEST_NAME "thread_stack_limits"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static DWORD WINAPI report(LPVOID p)
{
  ULONG_PTR lo = 0, hi = 0;
  (void)p;
  GetCurrentThreadStackLimits(&lo, &hi);
  return (DWORD)((hi - lo) / 1024); /* KB */
}

static DWORD WINAPI resolve(LPVOID p)
{
  struct addrinfo hints, *res = NULL;
  int rc;
  (void)p;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  rc = getaddrinfo("127.0.0.1", "80", &hints, &res);
  if(rc != 0)
    return 1;
  freeaddrinfo(res);
  res = NULL;
  rc = getaddrinfo("localhost", "80", &hints, &res);
  if(rc != 0)
    return 2;
  freeaddrinfo(res);
  return 0;
}

static DWORD run(SIZE_T size, DWORD flags, DWORD (WINAPI *fn)(LPVOID), const char *what)
{
  DWORD code = 0xFFFFFFFF;
  HANDLE h = CreateThread(NULL, size, fn, NULL, flags, NULL);
  if(!h) {
    printf("FAIL %s: CreateThread(%s) failed (GLE=%lu)\n", TEST_NAME, what, GetLastError());
    return 0xFFFFFFFE;
  }
  if(WaitForSingleObject(h, 20000) != WAIT_OBJECT_0) {
    printf("FAIL %s: thread %s did not finish\n", TEST_NAME, what);
    CloseHandle(h);
    return 0xFFFFFFFD;
  }
  GetExitCodeThread(h, &code);
  CloseHandle(h);
  return code;
}

int main(void)
{
  WSADATA wsa;
  ULONG_PTR lo = 0, hi = 0;
  DWORD pe_kb, kb;
  const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)GetModuleHandleW(NULL);
  const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)((const char *)dos + dos->e_lfanew);

  pe_kb = (DWORD)(nt->OptionalHeader.SizeOfStackReserve / 1024);
  GetCurrentThreadStackLimits(&lo, &hi);
  if((DWORD)((hi - lo) / 1024) != pe_kb)
    FAILF("main stack %lu KB, PE SizeOfStackReserve %lu KB",
          (unsigned long)((hi - lo) / 1024), (unsigned long)pe_kb);

  kb = run(0, 0, report, "default");
  if(kb != pe_kb)
    FAILF("default thread stack %lu KB, expected PE reserve %lu KB", (unsigned long)kb, (unsigned long)pe_kb);

  kb = run(256 * 1024, 0, report, "256K commit");
  if(kb != pe_kb)
    FAILF("256 KB without the reservation flag gave a %lu KB stack, expected the PE reserve %lu KB",
          (unsigned long)kb, (unsigned long)pe_kb);

  kb = run(256 * 1024, STACK_SIZE_PARAM_IS_A_RESERVATION, report, "256K reserve");
  if(kb != 256)
    FAILF("256 KB reservation gave %lu KB", (unsigned long)kb);

  kb = run(64 * 1024, STACK_SIZE_PARAM_IS_A_RESERVATION, report, "64K reserve");
  if(kb != 64)
    FAILF("64 KB reservation gave %lu KB", (unsigned long)kb);

  kb = run(8u * 1024 * 1024, STACK_SIZE_PARAM_IS_A_RESERVATION, report, "8M reserve");
  if(kb != 8192)
    FAILF("8 MB reservation gave %lu KB", (unsigned long)kb);

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  kb = run(128 * 1024, STACK_SIZE_PARAM_IS_A_RESERVATION, resolve, "resolve in 128K");
  WSACleanup();
  if(kb != 0)
    FAILF("getaddrinfo in a 128 KB stack failed with code %lu", (unsigned long)kb);

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
