/*
 * Test 14_thread_local_state_isolation
 *
 * Purpose: per-thread state used by resolver code. Checks that
 * WSASetLastError()/WSAGetLastError() values are thread-local (a worker's
 * failed getaddrinfo() must not change the main thread's error), that a
 * TLS slot from TlsAlloc() and a __declspec(thread) variable each hold a
 * separate value per thread, and that a worker resolving a literal from its
 * own thread gets its own result. This is the state the threaded resolver
 * relies on when it reads SOCKERRNO inside a worker.
 *
 * APIs: WSAStartup, WSASetLastError, WSAGetLastError, TlsAlloc, TlsSetValue,
 *       TlsGetValue, TlsFree, CreateThread, WaitForSingleObject,
 *       GetExitCodeThread, getaddrinfo, freeaddrinfo, WSACleanup.
 *
 * Success: the main thread's WSAGetLastError() is still the sentinel value
 * (4242) after all workers have run and failed their lookups. Each worker
 * reads back its own TLS value and its own _Thread_local counter after a
 * busy-wait that lets the other workers interleave, and both equal what it
 * wrote. Each worker's literal lookup
 * returns 0 with its own port number. All workers exit with 0.
 *
 * Source: lib/vdns/asyn-thrdd.c:415-417 (per-request resolver call and
 *         sockerr capture in the worker), lib/vdns/asyn-thrdd.c:446
 *         (SOCKERRNO read on the worker side).
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
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define T "14_thread_local_state_isolation"
#define NTHREADS 6
#define SENTINEL 4242

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [WSA=%d GLE=%lu]\n", WSAGetLastError(), (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

static DWORD tls_slot = TLS_OUT_OF_INDEXES;
static _Thread_local int tls_counter = 0;

typedef struct {
  int index;
  int ok;
  int wsa_seen;
} worker_t;

static DWORD WINAPI worker(LPVOID arg)
{
  worker_t *w = (worker_t *)arg;
  struct addrinfo hints, *res = NULL;
  char port[16];
  int rc;
  int i;
  int ok = 1;
  unsigned value = 1000u + (unsigned)w->index;

  /* TLS slot: each thread stores a unique pointer-sized value. */
  if(!TlsSetValue(tls_slot, (LPVOID)(ULONG_PTR)value)) {
    w->ok = 0;
    return 1;
  }

  /* __declspec(thread): thread-private counter. */
  tls_counter = (int)value;

  /* A failing lookup on this thread. It may set this thread's WSA error,
     and must not change any other thread's error. */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST;
  rc = getaddrinfo("corpus-not-a-literal", "80", &hints, &res);
  if(rc == 0) {
    ok = 0;
  }
  if(res)
    freeaddrinfo(res);
  res = NULL;

  /* Set this thread WSA error to a unique value, then spin without any
     API calls so other workers interleave their own writes. Sleep() and
     TlsGetValue() both may clear the last-error on success, so the error is
     read back before any such call. */
  WSASetLastError(9000 + w->index);
  for(i = 0; i < 200000; i++) {
    volatile int spin = i;
    (void)spin;
  }
  w->wsa_seen = WSAGetLastError();
  if(w->wsa_seen != 9000 + w->index)
    ok = 0;

  if((unsigned long)(ULONG_PTR)TlsGetValue(tls_slot) != value)
    ok = 0;
  if(tls_counter != (int)value)
    ok = 0;

  /* Successful literal lookup on this thread gives this thread's port. */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  snprintf(port, sizeof(port), "%u", 30000u + value);
  rc = getaddrinfo("127.0.0.1", port, &hints, &res);
  if(rc != 0 || !res) {
    ok = 0;
  }
  else {
    const struct sockaddr_in *s4 = (const struct sockaddr_in *)res->ai_addr;
    if(s4->sin_port != htons((unsigned short)(30000u + value)))
      ok = 0;
  }
  if(res)
    freeaddrinfo(res);

  w->ok = ok;
  return ok ? 0 : 1;
}

int main(void)
{
  WSADATA wsa;
  HANDLE threads[NTHREADS];
  worker_t work[NTHREADS];
  int i, wsa_ok = 0, created = 0;
  DWORD waited;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

  tls_slot = TlsAlloc();
  if(tls_slot == TLS_OUT_OF_INDEXES)
    FAILF("TlsAlloc failed");

  /* Main thread sets its own error and TLS value before the workers run. */
  WSASetLastError(SENTINEL);
  if(!TlsSetValue(tls_slot, (LPVOID)(ULONG_PTR)7777))
    FAILF("TlsSetValue(main) failed");
  tls_counter = 7777;

  for(i = 0; i < NTHREADS; i++) {
    memset(&work[i], 0, sizeof(work[i]));
    work[i].index = i;
    threads[i] = CreateThread(NULL, 0, worker, &work[i], 0, NULL);
    if(!threads[i])
      FAILF("CreateThread(%d) failed", i);
    created++;
  }

  waited = WaitForMultipleObjects(NTHREADS, threads, TRUE, 60000);
  if(waited != WAIT_OBJECT_0)
    FAILF("workers did not finish (wait=%lu)", (unsigned long)waited);

  /* Main thread state must be exactly what it was before the workers ran. */
  if(WSAGetLastError() != SENTINEL)
    FAILF("main thread WSA error changed to %d, expected %d (not thread-local)",
          WSAGetLastError(), SENTINEL);
  if((unsigned long)(ULONG_PTR)TlsGetValue(tls_slot) != 7777)
    FAILF("main thread TLS slot changed to %lu, expected 7777",
          (unsigned long)(ULONG_PTR)TlsGetValue(tls_slot));
  if(tls_counter != 7777)
    FAILF("main thread __declspec(thread) counter is %d, expected 7777", tls_counter);

  for(i = 0; i < NTHREADS; i++) {
    DWORD code = 0;
    if(!GetExitCodeThread(threads[i], &code))
      FAILF("GetExitCodeThread(%d) failed", i);
    CloseHandle(threads[i]);
    threads[i] = NULL;
    if(!work[i].ok)
      FAILF("worker %d saw corrupted thread-local state or a wrong answer", i);
    if(work[i].wsa_seen != 9000 + i)
      FAILF("worker %d WSA error was %d, expected %d", i, work[i].wsa_seen, 9000 + i);
    if(code != 0)
      FAILF("worker %d exited with %lu", i, (unsigned long)code);
  }

out:
  for(i = 0; i < created; i++)
    if(threads[i])
      CloseHandle(threads[i]);
  if(tls_slot != TLS_OUT_OF_INDEXES)
    TlsFree(tls_slot);
  if(wsa_ok)
    WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
