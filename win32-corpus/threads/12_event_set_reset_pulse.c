/*
 * Test: event_set_reset_pulse
 *
 * Purpose: CreateEventW with manual and auto reset, SetEvent, ResetEvent and
 *   PulseEvent semantics, including broadcast of a manual-reset event to
 *   several waiting threads and the lost-pulse rule when nothing is waiting.
 *
 * APIs: CreateEventW, SetEvent, ResetEvent, PulseEvent, WaitForSingleObject,
 *   WaitForMultipleObjects, CreateThread, GetLastError, CloseHandle.
 *
 * Success: manual-reset stays signaled across waits until ResetEvent; auto-reset
 *   is consumed by one wait and double SetEvent collapses to one signal; initial
 *   state of CreateEventW(bInitialState=TRUE) is honoured; PulseEvent on
 *   manual-reset releases a blocked waiter and leaves the event non-signaled
 *   (one waiter is tested); PulseEvent on auto-reset releases one waiter;
 *   PulseEvent with no waiters leaves no pending signal; SetEvent on a
 *   manual-reset event wakes all three waiting threads.
 *
 * curl reference: curl's Windows helpers use event/handle waits for thread
 *   coordination; WSACreateEvent/WSASetEvent are used in lib/multi.c:311 and
 *   lib/multi.c:1697 (the Winsock event flavour of the same primitive).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

#define TEST_NAME "event_set_reset_pulse"
#define FAILF(...) do { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

static HANDLE pulse_manual;
static HANDLE pulse_auto;
static HANDLE broadcast_ev;
static HANDLE broadcast_ready[3];
static volatile LONG woke_pulse = 0;
static volatile LONG woke_auto = 0;
static volatile LONG woke_broadcast = 0;

static DWORD WINAPI pulse_waiter(LPVOID p)
{
  (void)p;
  if(WaitForSingleObject(pulse_manual, 5000) == WAIT_OBJECT_0)
    InterlockedExchange(&woke_pulse, 1);
  return 0;
}

static DWORD WINAPI auto_waiter(LPVOID p)
{
  (void)p;
  if(WaitForSingleObject(pulse_auto, 5000) == WAIT_OBJECT_0)
    InterlockedExchange(&woke_auto, 1);
  return 0;
}

static DWORD WINAPI broadcast_waiter(LPVOID p)
{
  LONG idx = (LONG)(LONG_PTR)p;
  SetEvent(broadcast_ready[idx]);
  if(WaitForSingleObject(broadcast_ev, 5000) == WAIT_OBJECT_0)
    InterlockedIncrement(&woke_broadcast);
  return 0;
}

int main(void)
{
  HANDLE th;
  HANDLE pending_auto;
  HANDLE waiters[3];
  int i;

  /* 1. manual reset, initially non-signaled */
  HANDLE m = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!m)
    FAILF("CreateEventW(manual) failed (GLE=%lu)", GetLastError());
  if(WaitForSingleObject(m, 0) != WAIT_TIMEOUT)
    FAILF("unsignaled manual-reset event did not time out");
  if(!SetEvent(m))
    FAILF("SetEvent(manual) failed (GLE=%lu)", GetLastError());
  if(WaitForSingleObject(m, 0) != WAIT_OBJECT_0)
    FAILF("signaled manual-reset event first wait not WAIT_OBJECT_0");
  if(WaitForSingleObject(m, 0) != WAIT_OBJECT_0)
    FAILF("manual-reset event was consumed by a wait (must stay signaled)");
  if(!ResetEvent(m))
    FAILF("ResetEvent failed (GLE=%lu)", GetLastError());
  if(WaitForSingleObject(m, 0) != WAIT_TIMEOUT)
    FAILF("manual-reset event still signaled after ResetEvent");
  CloseHandle(m);

  /* 2. auto reset: initially signaled, consumed by one wait */
  pending_auto = CreateEventW(NULL, FALSE, TRUE, NULL);
  if(!pending_auto)
    FAILF("CreateEventW(auto, initial TRUE) failed (GLE=%lu)", GetLastError());
  if(WaitForSingleObject(pending_auto, 0) != WAIT_OBJECT_0)
    FAILF("auto-reset initially signaled event did not signal");
  if(WaitForSingleObject(pending_auto, 0) != WAIT_TIMEOUT)
    FAILF("auto-reset event not consumed by wait");
  /* two SetEvent calls collapse into one signal */
  SetEvent(pending_auto);
  SetEvent(pending_auto);
  if(WaitForSingleObject(pending_auto, 0) != WAIT_OBJECT_0)
    FAILF("auto-reset SetEvent did not signal");
  if(WaitForSingleObject(pending_auto, 0) != WAIT_TIMEOUT)
    FAILF("two SetEvent calls produced two auto-reset signals");
  CloseHandle(pending_auto);

  /* 3. PulseEvent on manual-reset releases a blocked waiter */
  pulse_manual = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!pulse_manual)
    FAILF("CreateEventW(pulse manual) failed (GLE=%lu)", GetLastError());
  th = CreateThread(NULL, 0, pulse_waiter, NULL, 0, NULL);
  if(!th)
    FAILF("CreateThread(pulse_waiter) failed (GLE=%lu)", GetLastError());
  Sleep(200); /* let the waiter block */
  if(!PulseEvent(pulse_manual))
    FAILF("PulseEvent failed (GLE=%lu)", GetLastError());
  if(WaitForSingleObject(th, 5000) != WAIT_OBJECT_0)
    FAILF("blocked waiter not released by PulseEvent (GLE=%lu)", GetLastError());
  CloseHandle(th);
  if(InterlockedCompareExchange(&woke_pulse, 0, 0) != 1)
    FAILF("waiter did not observe the pulse");
  if(WaitForSingleObject(pulse_manual, 0) != WAIT_TIMEOUT)
    FAILF("manual-reset event left signaled after PulseEvent");

  /* 4. PulseEvent with no waiters is lost */
  if(!PulseEvent(pulse_manual))
    FAILF("PulseEvent with no waiters failed (GLE=%lu)", GetLastError());
  if(WaitForSingleObject(pulse_manual, 0) != WAIT_TIMEOUT)
    FAILF("PulseEvent with no waiters left a pending signal");
  CloseHandle(pulse_manual);

  /* 5. PulseEvent on auto-reset releases one waiter */
  pulse_auto = CreateEventW(NULL, FALSE, FALSE, NULL);
  if(!pulse_auto)
    FAILF("CreateEventW(pulse auto) failed (GLE=%lu)", GetLastError());
  th = CreateThread(NULL, 0, auto_waiter, NULL, 0, NULL);
  if(!th)
    FAILF("CreateThread(auto_waiter) failed (GLE=%lu)", GetLastError());
  Sleep(200);
  PulseEvent(pulse_auto);
  if(WaitForSingleObject(th, 5000) != WAIT_OBJECT_0)
    FAILF("auto-reset waiter not released by PulseEvent");
  CloseHandle(th);
  if(InterlockedCompareExchange(&woke_auto, 0, 0) != 1)
    FAILF("auto waiter did not observe pulse");
  if(WaitForSingleObject(pulse_auto, 0) != WAIT_TIMEOUT)
    FAILF("auto-reset event still signaled after pulse");
  CloseHandle(pulse_auto);

  /* 6. SetEvent on manual-reset wakes all waiters (broadcast) */
  broadcast_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if(!broadcast_ev)
    FAILF("CreateEventW(broadcast) failed (GLE=%lu)", GetLastError());
  for(i = 0; i < 3; i++) {
    broadcast_ready[i] = CreateEventW(NULL, FALSE, FALSE, NULL);
    if(!broadcast_ready[i])
      FAILF("CreateEventW(ready %d) failed (GLE=%lu)", i, GetLastError());
    waiters[i] = CreateThread(NULL, 0, broadcast_waiter, (LPVOID)(LONG_PTR)i, 0, NULL);
    if(!waiters[i])
      FAILF("CreateThread(broadcast %d) failed (GLE=%lu)", i, GetLastError());
  }
  for(i = 0; i < 3; i++) {
    if(WaitForSingleObject(broadcast_ready[i], 5000) != WAIT_OBJECT_0)
      FAILF("broadcast waiter %d never started", i);
  }
  Sleep(100); /* waiters now block on broadcast_ev */
  SetEvent(broadcast_ev);
  if(WaitForMultipleObjects(3, waiters, TRUE, 5000) != WAIT_OBJECT_0)
    FAILF("broadcast waiters did not all finish (GLE=%lu)", GetLastError());
  for(i = 0; i < 3; i++) {
    CloseHandle(waiters[i]);
    CloseHandle(broadcast_ready[i]);
  }
  if(InterlockedCompareExchange(&woke_broadcast, 0, 0) != 3)
    FAILF("only %ld of 3 waiters woke on SetEvent", (long)woke_broadcast);
  CloseHandle(broadcast_ev);

  printf("PASS %s\n", TEST_NAME);
  return 0;
}
