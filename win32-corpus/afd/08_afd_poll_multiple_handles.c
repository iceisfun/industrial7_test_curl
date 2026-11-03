/*
 * Test: 08_afd_poll_multiple_handles
 *
 * Purpose:
 *   Multi-socket wait through a single IOCTL_AFD_POLL with NumberOfHandles=2.
 *   Two loopback pairs are polled together for AFD_POLL_RECEIVE. Only one
 *   pair receives data. The completion must identify the ready socket by its
 *   Handle field and must NOT report readiness on the idle one. This is the
 *   shape of the poll set that a multi-transfer poll loop submits.
 *
 * APIs used:
 *   ntdll!NtCreateFile, NtDeviceIoControlFile, NtClose (GetProcAddress),
 *   IOCTL_AFD_POLL (0x12024) with a two-entry handle array,
 *   ws2_32 socket/bind/listen/connect/accept/send/closesocket.
 *   AFD_POLL_INFO / AFD_POLL_HANDLE_INFO are undocumented; layout is
 *   reverse-engineered (wepoll).
 *
 * Success means:
 *   Poll returns STATUS_SUCCESS. Handles[0] (socket A, which got data) has
 *   Events with AFD_POLL_RECEIVE and Handles[1] (socket B, idle) does not.
 *   The Handle fields echo the submitted sockets in order.
 *
 * Source reference: lib/multi.c:1389 calls WSAEventSelect once per transfer
 *   socket, and Curl_poll (lib/select.c:199) waits on the whole set at once;
 *   this test models that multi-socket wait with a single AFD poll.
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

#define TEST_NAME "08_afd_poll_multiple_handles"

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

int main(void)
{
    HANDLE afd = NULL;
    T_NTSTATUS st;
    SOCKET ca = INVALID_SOCKET, sa_ = INVALID_SOCKET, cb = INVALID_SOCKET, sb = INVALID_SOCKET;
    SOCKET socks[2];
    ULONG events[2];
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
    if (!wsa_start() || !loopback_pair(&ca, &sa_) || !loopback_pair(&cb, &sb)) {
        printf("FAIL %s: socket setup failed (WSA %d)\n", TEST_NAME, WSAGetLastError());
        return 1;
    }

    /* Only pair A receives data. */
    if (send(sa_, "A", 1, 0) != 1) {
        printf("FAIL %s: send() failed (WSA %d)\n", TEST_NAME, WSAGetLastError());
        return 1;
    }

    socks[0] = ca;
    socks[1] = cb;
    events[0] = AFD_POLL_RECEIVE;
    events[1] = AFD_POLL_RECEIVE;
    memset(&out, 0, sizeof(out));
    st = afd_poll(afd, socks, events, 2, -20000000LL, 10000, &out);
    if (st == T_STATUS_HELPER_WAIT_EXPIRED) {
        printf("FAIL %s: multi-handle poll did not complete within 10 s\n", TEST_NAME);
        return 1;
    }
    if (st != T_STATUS_SUCCESS) {
        printf("FAIL %s: multi-handle poll returned 0x%08lX, expected SUCCESS\n", TEST_NAME,
               (unsigned long)(ULONG)st);
        return 1;
    }
    if (out.Handles[0].Handle != (HANDLE)(ULONG_PTR)ca) {
        printf("FAIL %s: Handles[0] does not echo the submitted socket A\n", TEST_NAME);
        return 1;
    }
    if (out.Handles[1].Handle != (HANDLE)(ULONG_PTR)cb) {
        printf("FAIL %s: Handles[1] does not echo the submitted socket B\n", TEST_NAME);
        return 1;
    }
    if (out.Handles[0].Status != T_STATUS_SUCCESS || (out.Handles[0].Events & AFD_POLL_RECEIVE) == 0) {
        printf("FAIL %s: socket A with data not reported readable (events 0x%lX)\n", TEST_NAME,
               out.Handles[0].Events);
        return 1;
    }
    if (out.Handles[1].Status == T_STATUS_SUCCESS && (out.Handles[1].Events & AFD_POLL_RECEIVE) != 0) {
        printf("FAIL %s: idle socket B reported readable (events 0x%lX)\n", TEST_NAME,
               out.Handles[1].Events);
        return 1;
    }

    closesocket(ca);
    closesocket(sa_);
    closesocket(cb);
    closesocket(sb);
    p_NtClose(afd);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
