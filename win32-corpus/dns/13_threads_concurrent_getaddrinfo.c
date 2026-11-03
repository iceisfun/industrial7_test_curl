/*
 * Test 13_threads_concurrent_getaddrinfo
 *
 * Purpose: thread safety of getaddrinfo()/freeaddrinfo() when many worker
 * threads resolve at the same time, which is how curl's threaded resolver
 * works: each worker thread calls getaddrinfo() for its own request and
 * frees the result on completion. Eight workers each run 60 iterations that
 * alternate a numeric literal (with a per-thread port) and "localhost",
 * checking every answer. Threads are created with CreateThread and joined
 * with WaitForMultipleObjects.
 *
 * APIs: WSAStartup, CreateThread, WaitForMultipleObjects, GetExitCodeThread,
 *       CloseHandle, getaddrinfo, freeaddrinfo, WSACleanup.
 *
 * Success: all workers return 0 (no wrong answers, no failed lookups) and
 * the main thread completes the join within 60 seconds. Any worker failure
 * is reported by its index and the first failing code.
 *
 * Source: lib/vdns/asyn-thrdd.c:395-420 (threaded resolver worker calls
 *         Curl_getaddrinfo_ex() per request and stores the result), and
 *         lib/vdns/asyn-thrdd.c:417 (sockerr from SOCKERRNO on failure).
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

#define T "13_threads_concurrent_getaddrinfo"
#define NTHREADS 8
#define ITERS 60

static int status = 0;

#define FAILF(...) do { \
    printf("FAIL %s: ", T); printf(__VA_ARGS__); \
    printf(" [WSA=%d GLE=%lu]\n", WSAGetLastError(), (unsigned long)GetLastError()); \
    status = 1; goto out; } while(0)

typedef struct {
  int index;
  int failures;
  int first_error;
  int completed;
} worker_t;

static int addr_is_loopback(const struct addrinfo *ai)
{
  if(ai->ai_family == AF_INET) {
    const struct sockaddr_in *s4 = (const struct sockaddr_in *)ai->ai_addr;
    return ntohl(s4->sin_addr.S_un.S_addr) == 0x7F000001UL;
  }
  if(ai->ai_family == AF_INET6) {
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ai->ai_addr;
    return IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr);
  }
  return 0;
}

static DWORD WINAPI worker(LPVOID arg)
{
  worker_t *w = (worker_t *)arg;
  int i;

  for(i = 0; i < ITERS; i++) {
    struct addrinfo hints, *res = NULL;
    char port[16];
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if(i & 1) {
      /* Name lookup: localhost must resolve to loopback. */
      hints.ai_family = AF_UNSPEC;
      rc = getaddrinfo("localhost", "80", &hints, &res);
      if(rc != 0 || !res) {
        w->failures++;
        if(!w->first_error)
          w->first_error = rc ? rc : -1;
      }
      else {
        int ok = 0;
        const struct addrinfo *ai;
        for(ai = res; ai; ai = ai->ai_next)
          if(addr_is_loopback(ai))
            ok = 1;
        if(!ok) {
          w->failures++;
          if(!w->first_error)
            w->first_error = -2;
        }
      }
    }
    else {
      /* Numeric lookup with a port unique to this thread and iteration. */
      unsigned port_no = 20000u + (unsigned)(w->index * 100 + i);
      snprintf(port, sizeof(port), "%u", port_no);
      hints.ai_family = AF_INET;
      hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
      rc = getaddrinfo("127.0.0.1", port, &hints, &res);
      if(rc != 0 || !res) {
        w->failures++;
        if(!w->first_error)
          w->first_error = rc ? rc : -3;
      }
      else {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)res->ai_addr;
        if(s4->sin_port != htons((unsigned short)port_no) ||
           ntohl(s4->sin_addr.S_un.S_addr) != 0x7F000001UL) {
          w->failures++;
          if(!w->first_error)
            w->first_error = -4;
        }
      }
    }
    if(res)
      freeaddrinfo(res);
  }
  w->completed = 1;
  return (DWORD)w->failures;
}

int main(void)
{
  WSADATA wsa;
  HANDLE threads[NTHREADS];
  worker_t work[NTHREADS];
  int i, wsa_ok = 0, created = 0;
  DWORD waited;
  int total_fail = 0;

  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    FAILF("WSAStartup failed");
  wsa_ok = 1;

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
    FAILF("worker threads did not finish within 60 seconds (wait=%lu)",
          (unsigned long)waited);

  for(i = 0; i < created; i++) {
    DWORD code = 0;
    if(!GetExitCodeThread(threads[i], &code))
      FAILF("GetExitCodeThread(%d) failed", i);
    CloseHandle(threads[i]);
    threads[i] = NULL;
    if(!work[i].completed)
      FAILF("worker %d did not complete", i);
    total_fail += work[i].failures;
    if(work[i].failures)
      FAILF("worker %d had %d bad lookups, first error code %d",
            i, work[i].failures, work[i].first_error);
  }
  if(total_fail != 0)
    FAILF("total failures %d", total_fail);

out:
  for(i = 0; i < created; i++)
    if(threads[i])
      CloseHandle(threads[i]);
  if(wsa_ok)
    WSACleanup();
  if(status == 0)
    printf("PASS %s\n", T);
  return status;
}
