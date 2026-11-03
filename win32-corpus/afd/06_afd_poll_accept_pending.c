/*
 * Test: 06_afd_poll_accept_pending
 *
 * Purpose:
 *   Listening-socket readiness through IOCTL_AFD_POLL. AFD reports
 *   AFD_POLL_ACCEPT on a listening socket only while a completed connection
 *   sits in the backlog. The test checks: (1) no connection yet, poll times
 *   out with ACCEPT clear; (2) after a client connects, poll reports ACCEPT;
 *   (3) after accept(), ACCEPT is clear again. This is the readiness signal a
 *   server-side poll loop depends on.
 *
 * APIs used:
 *   ntdll!NtCreateFile, NtDeviceIoControlFile, NtClose (GetProcAddress),
 *   IOCTL_AFD_POLL (0x12024), ws2_32 socket/bind/listen/getsockname/connect/accept.
 *   AFD_POLL_INFO layout and AFD_POLL_ACCEPT (0x0080) are reverse-engineered.
 *
 * Success means:
 *   Poll #1 returns STATUS_TIMEOUT, or SUCCESS with ACCEPT clear.
 *   Poll #2 returns STATUS_SUCCESS with AFD_POLL_ACCEPT set.
 *   accept() returns a valid socket. Poll #3 has ACCEPT clear.
 *
 * Source reference: lib/multi.c:1389 registers the listening socket for
 *   FD_ACCEPT readiness through WSAEventSelect, which AFD services as
 *   AFD_POLL_ACCEPT.
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

#define TEST_NAME "06_afd_poll_accept_pending"

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
#define T_STATUS_TIMEOUT ((T_NTSTATUS)0x00000102L)
#define T_STATUS_INSUFFICIENT_RESOURCES ((T_NTSTATUS)0xC000009AL)
#define T_STATUS_HELPER_WAIT_EXPIRED ((T_NTSTATUS)0xE0000001L)
#define T_OBJ_CASE_INSENSITIVE 0x00000040UL
#define T_FILE_OPEN 0x00000001UL
#define T_IOCTL_AFD_POLL 0x00012024UL

#define AFD_POLL_RECEIVE 0x0001UL
#define AFD_POLL_ACCEPT 0x0080UL

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

static int wsa_start(void)
{
    WSADATA d;
    return WSAStartup(MAKEWORD(2, 2), &d) == 0;
}

/* Returns a listening loopback socket and its port-bound sockaddr. */
static SOCKET make_listener(struct sockaddr_in *sa)
{
    SOCKET l;
    int len = sizeof(*sa);

    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa->sin_port = 0;
    l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (l == INVALID_SOCKET)
        return INVALID_SOCKET;
    if (bind(l, (struct sockaddr *)sa, sizeof(*sa)) != 0 || listen(l, 4) != 0 ||
        getsockname(l, (struct sockaddr *)sa, &len) != 0) {
        closesocket(l);
        return INVALID_SOCKET;
    }
    return l;
}

int main(void)
{
    HANDLE afd = NULL;
    T_NTSTATUS st;
    SOCKET l, c, a;
    struct sockaddr_in sa;
    SOCKET socks[1];
    ULONG events[1];
    AFD_POLL_INFO out;

    if (!load_ntdll()) {
        printf("SKIP %s: ntdll does not export NtCreateFile/NtClose/NtDeviceIoControlFile\n",
               TEST_NAME);
        return 77;
    }
    st = open_afd(&afd);
    if (st < 0 || afd == NULL) {
        printf("SKIP %s: cannot open \\Device\\Afd (NTSTATUS 0x%08lX)\n", TEST_NAME,
               (unsigned long)(ULONG)st);
        return 77;
    }
    if (!wsa_start()) {
        printf("FAIL %s: WSAStartup failed (WSA %d)\n", TEST_NAME, WSAGetLastError());
        return 1;
    }
    l = make_listener(&sa);
    if (l == INVALID_SOCKET) {
        printf("FAIL %s: listener setup failed (WSA %d)\n", TEST_NAME, WSAGetLastError());
        return 1;
    }

    socks[0] = l;
    events[0] = AFD_POLL_ACCEPT;

    /* Poll #1: empty backlog. */
    memset(&out, 0, sizeof(out));
    st = afd_poll(afd, socks, events, 1, -1000000LL, 5000, &out);
    if (st == T_STATUS_HELPER_WAIT_EXPIRED) {
        printf("FAIL %s: poll #1 did not complete\n", TEST_NAME);
        return 1;
    }
    if (st != T_STATUS_TIMEOUT && !(st == T_STATUS_SUCCESS && (out.Handles[0].Status != T_STATUS_SUCCESS || (out.Handles[0].Events & AFD_POLL_ACCEPT) == 0))) {
        printf("FAIL %s: poll #1 with empty backlog returned 0x%08lX events 0x%lX\n", TEST_NAME,
               (unsigned long)(ULONG)st, out.Handles[0].Events);
        return 1;
    }

    /* Create a pending connection in the backlog. */
    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c == INVALID_SOCKET || connect(c, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        printf("FAIL %s: connect to listener failed (WSA %d)\n", TEST_NAME, WSAGetLastError());
        return 1;
    }

    memset(&out, 0, sizeof(out));
    st = afd_poll(afd, socks, events, 1, -20000000LL, 10000, &out);
    if (st == T_STATUS_HELPER_WAIT_EXPIRED) {
        printf("FAIL %s: poll #2 did not complete\n", TEST_NAME);
        return 1;
    }
    if (st != T_STATUS_SUCCESS || out.Handles[0].Status != T_STATUS_SUCCESS ||
        (out.Handles[0].Events & AFD_POLL_ACCEPT) == 0) {
        printf("FAIL %s: poll #2 with pending connection returned 0x%08lX events 0x%lX\n",
               TEST_NAME, (unsigned long)(ULONG)st, out.Handles[0].Events);
        return 1;
    }

    a = accept(l, NULL, NULL);
    if (a == INVALID_SOCKET) {
        printf("FAIL %s: accept() failed (WSA %d)\n", TEST_NAME, WSAGetLastError());
        return 1;
    }

    /* Poll #3: backlog drained, ACCEPT must clear. */
    memset(&out, 0, sizeof(out));
    st = afd_poll(afd, socks, events, 1, -1000000LL, 5000, &out);
    if (st == T_STATUS_HELPER_WAIT_EXPIRED) {
        printf("FAIL %s: poll #3 did not complete\n", TEST_NAME);
        return 1;
    }
    if (st != T_STATUS_TIMEOUT && !(st == T_STATUS_SUCCESS && (out.Handles[0].Status != T_STATUS_SUCCESS || (out.Handles[0].Events & AFD_POLL_ACCEPT) == 0))) {
        printf("FAIL %s: poll #3 after accept still reports ACCEPT (0x%08lX, events 0x%lX)\n",
               TEST_NAME, (unsigned long)(ULONG)st, out.Handles[0].Events);
        return 1;
    }

    closesocket(a);
    closesocket(c);
    closesocket(l);
    p_NtClose(afd);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
