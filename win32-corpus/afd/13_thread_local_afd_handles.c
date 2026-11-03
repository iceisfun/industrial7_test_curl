/*
 * Test: 13_thread_local_afd_handles
 *
 * Purpose:
 *   Concurrency and thread-local state around AFD. Four worker threads start
 *   together (released by one manual-reset event) and each one:
 *     - opens its OWN \Device\Afd handle with NtCreateFile,
 *     - stores that handle in a TLS slot (TlsAlloc/TlsSetValue) and in a C11
 *       _Thread_local variable,
 *     - creates a private loopback socket pair,
 *     - sends a thread-unique payload and polls its receive side with
 *       IOCTL_AFD_POLL on its own AFD handle,
 *     - reads the payload back and checks it is the one it sent,
 *     - re-reads both TLS values after the I/O and checks they still belong to
 *       this thread (no cross-thread bleed).
 *   This is the pattern curl's threaded resolver and multi-handle code use:
 *   per-thread wakeup/event state with no shared mutable state.
 *
 * APIs used:
 *   ntdll!NtCreateFile, NtDeviceIoControlFile, NtClose (GetProcAddress),
 *   IOCTL_AFD_POLL (0x12024), kernel32!CreateThread, WaitForMultipleObjects,
 *   CreateEventW, SetEvent, TlsAlloc, TlsSetValue, TlsGetValue, TlsFree,
 *   ws2_32 socket/bind/listen/connect/accept/send/recv.
 *   AFD_POLL_INFO layout is reverse-engineered (wepoll).
 *
 * Success means: all four workers finish with PASS (payload intact, poll
 *   returned RECEIVE, TLS values unchanged and unique per thread).
 *
 * Source reference: lib/multi.c:311 (per-multi WSACreateEvent wakeup event)
 *   and lib/multi.c:1389 (per-socket WSAEventSelect) describe the per-handle
 *   event model this test reproduces across threads.
 *
 * Exit: 0 PASS, 77 SKIP (AFD cannot be opened), 1 FAIL.
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
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define TEST_NAME "13_thread_local_afd_handles"
#define NUM_WORKERS 4

/* ---- undocumented NT types (reverse-engineered, see header) ---- */
typedef LONG T_NTSTATUS;
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} T_UNICODE_STRING;
typedef struct {
    ULONG Length;
    HANDLE RootDirectory;
    T_UNICODE_STRING *ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} T_OBJECT_ATTRIBUTES;
typedef struct {
    union {
        T_NTSTATUS Status;
        PVOID Pointer;
    } u;
    ULONG_PTR Information;
} T_IO_STATUS_BLOCK;

/* AFD poll structures (reverse-engineered; layout matches wepoll). */
typedef struct {
    HANDLE Handle;
    ULONG Events;
    T_NTSTATUS Status;
} AFD_POLL_HANDLE_INFO;
typedef struct {
    LARGE_INTEGER Timeout; /* 100 ns units, negative = relative */
    ULONG NumberOfHandles;
    ULONG Exclusive;
    AFD_POLL_HANDLE_INFO Handles[2];
} AFD_POLL_INFO;

#define T_STATUS_SUCCESS ((T_NTSTATUS)0x00000000L)
#define T_STATUS_PENDING ((T_NTSTATUS)0x00000103L)
#define T_STATUS_INSUFFICIENT_RESOURCES ((T_NTSTATUS)0xC000009AL)
#define T_STATUS_HELPER_WAIT_EXPIRED ((T_NTSTATUS)0xE0000001L)
#define T_OBJ_CASE_INSENSITIVE 0x00000040UL
#define T_FILE_OPEN 0x00000001UL
#define T_IOCTL_AFD_POLL 0x00012024UL

#define AFD_POLL_RECEIVE 0x0001UL

typedef T_NTSTATUS(NTAPI *fn_NtCreateFile)(PHANDLE, ACCESS_MASK, T_OBJECT_ATTRIBUTES *,
                                           T_IO_STATUS_BLOCK *, PLARGE_INTEGER, ULONG,
                                           ULONG, ULONG, ULONG, PVOID, ULONG);
typedef T_NTSTATUS(NTAPI *fn_NtClose)(HANDLE);
typedef T_NTSTATUS(NTAPI *fn_NtDeviceIoControlFile)(HANDLE, HANDLE, PVOID, PVOID,
                                                    T_IO_STATUS_BLOCK *, ULONG, PVOID,
                                                    ULONG, PVOID, ULONG);

static fn_NtCreateFile p_NtCreateFile;
static fn_NtClose p_NtClose;
static fn_NtDeviceIoControlFile p_NtDeviceIoControlFile;

/* Per-thread state: C11 thread-local and a TLS slot, both per worker. */
static _Thread_local int tl_worker_index = -1;
static DWORD g_tls_afd;
static HANDLE g_start_event;

typedef struct {
    int index;
    DWORD result; /* 0 = PASS, 1 = FAIL */
    HANDLE afd;   /* owned by main, closed after all handles are compared */
    char msg[256];
} worker_t;

static int load_ntdll(void)
{
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h)
        h = LoadLibraryW(L"ntdll.dll");
    if (!h)
        return 0;
    p_NtCreateFile = (fn_NtCreateFile)(void *)GetProcAddress(h, "NtCreateFile");
    p_NtClose = (fn_NtClose)(void *)GetProcAddress(h, "NtClose");
    p_NtDeviceIoControlFile =
        (fn_NtDeviceIoControlFile)(void *)GetProcAddress(h, "NtDeviceIoControlFile");
    return p_NtCreateFile && p_NtClose && p_NtDeviceIoControlFile;
}

static T_NTSTATUS open_afd(HANDLE *out)
{
    wchar_t name[] = L"\\Device\\Afd";
    T_UNICODE_STRING us;
    T_OBJECT_ATTRIBUTES oa;
    T_IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    T_NTSTATUS st;

    us.Length = (USHORT)(wcslen(name) * sizeof(wchar_t));
    us.MaximumLength = (USHORT)(us.Length + sizeof(wchar_t));
    us.Buffer = name;
    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = T_OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;
    memset(&iosb, 0, sizeof(iosb));
    st = p_NtCreateFile(&h, SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE, &oa, &iosb, NULL, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, T_FILE_OPEN, 0, NULL, 0);
    *out = (st >= 0) ? h : NULL;
    return st;
}

/* Heap buffers so a timed-out wait can leak them without a dangling stack write. */
static T_NTSTATUS afd_poll(HANDLE afd, const SOCKET *socks, const ULONG *events, ULONG n,
                           LONGLONG timeout_100ns, DWORD wait_ms, AFD_POLL_INFO *out)
{
    AFD_POLL_INFO *info = (AFD_POLL_INFO *)calloc(1, sizeof(*info));
    T_IO_STATUS_BLOCK *iosb = (T_IO_STATUS_BLOCK *)calloc(1, sizeof(*iosb));
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    T_NTSTATUS st;
    ULONG i;

    if (!info || !iosb || !ev)
        return T_STATUS_INSUFFICIENT_RESOURCES;

    info->Timeout.QuadPart = timeout_100ns;
    info->NumberOfHandles = n;
    info->Exclusive = 0;
    for (i = 0; i < n; i++) {
        info->Handles[i].Handle = (HANDLE)(ULONG_PTR)socks[i];
        info->Handles[i].Events = events[i];
        info->Handles[i].Status = T_STATUS_PENDING; /* sentinel: kernel must overwrite on completion */
    }
    iosb->u.Status = T_STATUS_PENDING;

    st = p_NtDeviceIoControlFile(afd, ev, NULL, NULL, iosb, (ULONG)T_IOCTL_AFD_POLL, info,
                                 sizeof(*info), info, sizeof(*info));
    if (st == T_STATUS_PENDING) {
        if (WaitForSingleObject(ev, wait_ms) != WAIT_OBJECT_0)
            return T_STATUS_HELPER_WAIT_EXPIRED;
        st = iosb->u.Status;
    }
    *out = *info;
    CloseHandle(ev);
    free(info);
    free(iosb);
    return st;
}

static int loopback_pair(SOCKET *client, SOCKET *server)
{
    SOCKET l = INVALID_SOCKET, c = INVALID_SOCKET, s = INVALID_SOCKET;
    struct sockaddr_in sa;
    int len = sizeof(sa);

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (l == INVALID_SOCKET)
        goto fail;
    if (bind(l, (struct sockaddr *)&sa, sizeof(sa)) != 0)
        goto fail;
    if (listen(l, 1) != 0)
        goto fail;
    if (getsockname(l, (struct sockaddr *)&sa, &len) != 0)
        goto fail;
    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c == INVALID_SOCKET)
        goto fail;
    if (connect(c, (struct sockaddr *)&sa, sizeof(sa)) != 0)
        goto fail;
    s = accept(l, NULL, NULL);
    if (s == INVALID_SOCKET)
        goto fail;
    closesocket(l);
    *client = c;
    *server = s;
    return 1;
fail:
    if (l != INVALID_SOCKET)
        closesocket(l);
    if (c != INVALID_SOCKET)
        closesocket(c);
    if (s != INVALID_SOCKET)
        closesocket(s);
    return 0;
}

static DWORD WINAPI worker_main(LPVOID arg)
{
    worker_t *w = (worker_t *)arg;
    HANDLE afd = NULL;
    SOCKET c = INVALID_SOCKET, s = INVALID_SOCKET;
    SOCKET socks[1];
    ULONG events[1];
    AFD_POLL_INFO out;
    T_NTSTATUS st;
    char payload[32];
    char rx[32];
    int n, plen;

    tl_worker_index = w->index;
    w->result = 1;
    WaitForSingleObject(g_start_event, INFINITE);

    st = open_afd(&afd);
    if (st < 0 || afd == NULL) {
        snprintf(w->msg, sizeof(w->msg), "open \\Device\\Afd failed (0x%08lX)", (unsigned long)(ULONG)st);
        return 0;
    }
    w->afd = afd;
    if (!TlsSetValue(g_tls_afd, (LPVOID)afd)) {
        snprintf(w->msg, sizeof(w->msg), "TlsSetValue failed (GetLastError %lu)", GetLastError());
        return 0;
    }
    if (!loopback_pair(&c, &s)) {
        snprintf(w->msg, sizeof(w->msg), "loopback pair failed (WSA %d)", WSAGetLastError());
        return 0;
    }

    plen = snprintf(payload, sizeof(payload), "thread-%d", w->index);
    if (send(s, payload, plen, 0) != plen) {
        snprintf(w->msg, sizeof(w->msg), "send failed (WSA %d)", WSAGetLastError());
        goto cleanup;
    }

    socks[0] = c;
    events[0] = AFD_POLL_RECEIVE;
    memset(&out, 0, sizeof(out));
    st = afd_poll(afd, socks, events, 1, -100000000LL, 20000, &out);
    if (st == T_STATUS_HELPER_WAIT_EXPIRED) {
        snprintf(w->msg, sizeof(w->msg), "poll did not complete within 20 s");
        goto cleanup;
    }
    if (st != T_STATUS_SUCCESS || out.Handles[0].Status != T_STATUS_SUCCESS ||
        (out.Handles[0].Events & AFD_POLL_RECEIVE) == 0) {
        snprintf(w->msg, sizeof(w->msg), "poll returned 0x%08lX events 0x%lX",
                 (unsigned long)(ULONG)st, out.Handles[0].Events);
        goto cleanup;
    }

    n = recv(c, rx, sizeof(rx), 0);
    if (n != plen || memcmp(rx, payload, plen) != 0) {
        snprintf(w->msg, sizeof(w->msg), "recv returned %d bytes (WSA %d), expected \"%s\"", n,
                 WSAGetLastError(), payload);
        goto cleanup;
    }

    /* TLS and thread-local values must still belong to this worker. */
    if (TlsGetValue(g_tls_afd) != (LPVOID)afd) {
        snprintf(w->msg, sizeof(w->msg), "TLS slot changed to another handle");
        goto cleanup;
    }
    if (tl_worker_index != w->index) {
        snprintf(w->msg, sizeof(w->msg), "_Thread_local index is %d, expected %d",
                 tl_worker_index, w->index);
        goto cleanup;
    }

    w->result = 0;
    snprintf(w->msg, sizeof(w->msg), "ok");

cleanup:
    closesocket(c);
    closesocket(s);
    return 0;
}

int main(void)
{
    WSADATA wsa;
    worker_t workers[NUM_WORKERS];
    HANDLE threads[NUM_WORKERS];
    HANDLE afd_probe = NULL;
    T_NTSTATUS st;
    DWORD w;
    int i, j, failed = 0;
    char why[384] = "";

    if (!load_ntdll()) {
        printf("SKIP %s: ntdll does not export NtCreateFile/NtClose/NtDeviceIoControlFile\n",
               TEST_NAME);
        return 77;
    }
    st = open_afd(&afd_probe);
    if (st < 0 || afd_probe == NULL) {
        printf("SKIP %s: cannot open \\Device\\Afd (NTSTATUS 0x%08lX)\n", TEST_NAME,
               (unsigned long)(ULONG)st);
        return 77;
    }
    p_NtClose(afd_probe);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("FAIL %s: WSAStartup failed\n", TEST_NAME);
        return 1;
    }
    g_tls_afd = TlsAlloc();
    if (g_tls_afd == TLS_OUT_OF_INDEXES) {
        printf("FAIL %s: TlsAlloc failed (GetLastError %lu)\n", TEST_NAME, GetLastError());
        return 1;
    }
    g_start_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_start_event) {
        printf("FAIL %s: CreateEventW failed (GetLastError %lu)\n", TEST_NAME, GetLastError());
        return 1;
    }

    for (i = 0; i < NUM_WORKERS; i++) {
        workers[i].index = i;
        workers[i].result = 1;
        workers[i].msg[0] = '\0';
        threads[i] = CreateThread(NULL, 0, worker_main, &workers[i], 0, NULL);
        if (!threads[i]) {
            printf("FAIL %s: CreateThread %d failed (GetLastError %lu)\n", TEST_NAME, i,
                   GetLastError());
            return 1;
        }
    }

    SetEvent(g_start_event);
    w = WaitForMultipleObjects(NUM_WORKERS, threads, TRUE, 60000);
    if (w != WAIT_OBJECT_0) {
        printf("FAIL %s: workers did not finish within 60 s (wait=%lu)\n", TEST_NAME, w);
        return 1;
    }
    for (i = 0; i < NUM_WORKERS; i++) {
        CloseHandle(threads[i]);
        if (workers[i].result != 0 && !failed) {
            snprintf(why, sizeof(why), "worker %d: %s", i, workers[i].msg);
            failed = 1;
        }
    }
    /* All AFD handles are still open here, so they must be pairwise distinct. */
    for (i = 0; i < NUM_WORKERS && !failed; i++) {
        for (j = i + 1; j < NUM_WORKERS && !failed; j++) {
            if (workers[i].afd != NULL && workers[i].afd == workers[j].afd) {
                snprintf(why, sizeof(why), "workers %d and %d share AFD handle %p", i, j,
                         (void *)workers[i].afd);
                failed = 1;
            }
        }
    }
    for (i = 0; i < NUM_WORKERS; i++) {
        if (workers[i].afd != NULL)
            p_NtClose(workers[i].afd);
    }

    CloseHandle(g_start_event);
    TlsFree(g_tls_afd);
    WSACleanup();
    if (failed) {
        printf("FAIL %s: %s\n", TEST_NAME, why);
        return 1;
    }
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
