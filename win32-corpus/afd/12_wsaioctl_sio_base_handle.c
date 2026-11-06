/*
 * Test: 12_wsaioctl_sio_base_handle
 *
 * Purpose:
 *   Obtain the base socket with WSAIoctl(SIO_BASE_HANDLE), which bypasses any
 *   layered service provider (LSP) and returns the handle that the AFD driver
 *   actually owns. Verify that:
 *     - the call succeeds and returns a SOCKET-sized result,
 *     - a closed socket is rejected with WSAENOTSOCK,
 *     - the base handle is directly usable with IOCTL_AFD_POLL: the idle
 *       connected socket must report AFD_POLL_WRITE through it.
 *   Win10 22H2 opens \Device\Afd for a standard user and supports
 *   SIO_BASE_HANDLE, so any failure there is a FAIL.
 *
 * APIs used:
 *   ws2_32!WSAIoctl with SIO_BASE_HANDLE (_WSAIOR(IOC_WS2,34)), socket/
 *   bind/listen/connect/accept/closesocket, WSAGetLastError,
 *   ntdll!NtCreateFile, NtDeviceIoControlFile, NtClose (GetProcAddress),
 *   IOCTL_AFD_POLL (0x12024). AFD_POLL_INFO layout is reverse-engineered.
 *
 * Success means:
 *   WSAIoctl returns 0 with bytes == sizeof(SOCKET) and a valid base handle;
 *   a closed socket gives WSAENOTSOCK; the poll on the base handle returns
 *   STATUS_SUCCESS with AFD_POLL_WRITE set.
 *
 * Source reference: lib/cf-socket.c:265 (WSAIoctl(sockfd, SIO_KEEPALIVE_VALS))
 *   shows curl's existing WSAIoctl usage on the connected socket; the same
 *   call shape is used here with SIO_BASE_HANDLE.
 *
 * Exit: 0 PASS, 1 FAIL.
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

#define TEST_NAME "12_wsaioctl_sio_base_handle"

#ifndef SIO_BASE_HANDLE
#define SIO_BASE_HANDLE _WSAIOR(IOC_WS2, 34)
#endif

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

#define AFD_POLL_WRITE 0x0004UL

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
    SOCKET c = INVALID_SOCKET, s = INVALID_SOCKET, base = INVALID_SOCKET, dead;
    SOCKET socks[1];
    ULONG events[1];
    AFD_POLL_INFO out;
    DWORD bytes = 0;
    int rc;
    int err;

    if (!load_ntdll()) {
        printf("FAIL %s: ntdll does not export NtCreateFile/NtClose/NtDeviceIoControlFile\n",
               TEST_NAME);
        return 1;
    }
    st = open_afd(&afd);
    if (st < 0 || afd == NULL) {
        printf("FAIL %s: cannot open \\Device\\Afd (NTSTATUS 0x%08lX)\n", TEST_NAME,
               (unsigned long)(ULONG)st);
        return 1;
    }
    if (!wsa_start() || !loopback_pair(&c, &s)) {
        printf("FAIL %s: socket setup failed (WSA %d)\n", TEST_NAME, WSAGetLastError());
        return 1;
    }

    rc = WSAIoctl(c, SIO_BASE_HANDLE, NULL, 0, &base, sizeof(base), &bytes, NULL, NULL);
    if (rc != 0) {
        err = WSAGetLastError();
        printf("FAIL %s: WSAIoctl(SIO_BASE_HANDLE) failed (WSA %d)\n", TEST_NAME, err);
        return 1;
    }
    if (bytes != sizeof(SOCKET) || base == INVALID_SOCKET) {
        printf("FAIL %s: WSAIoctl returned %lu bytes, base=%p\n", TEST_NAME,
               (unsigned long)bytes, (void *)(ULONG_PTR)base);
        return 1;
    }

    /* A closed socket must be rejected with WSAENOTSOCK. */
    dead = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (dead == INVALID_SOCKET) {
        printf("FAIL %s: socket() failed (WSA %d)\n", TEST_NAME, WSAGetLastError());
        return 1;
    }
    closesocket(dead);
    bytes = 0;
    rc = WSAIoctl(dead, SIO_BASE_HANDLE, NULL, 0, &base, sizeof(base), &bytes, NULL, NULL);
    err = WSAGetLastError();
    if (rc != SOCKET_ERROR || err != WSAENOTSOCK) {
        printf("FAIL %s: WSAIoctl on closed socket returned %d (WSA %d), expected WSAENOTSOCK\n",
               TEST_NAME, rc, err);
        return 1;
    }

    /* The base handle must be usable by AFD: idle connected socket is writable. */
    socks[0] = base;
    events[0] = AFD_POLL_WRITE;
    memset(&out, 0, sizeof(out));
    st = afd_poll(afd, socks, events, 1, -10000000LL, 5000, &out);
    if (st == T_STATUS_HELPER_WAIT_EXPIRED) {
        printf("FAIL %s: poll on base handle did not complete\n", TEST_NAME);
        return 1;
    }
    if (st != T_STATUS_SUCCESS || out.Handles[0].Status != T_STATUS_SUCCESS ||
        (out.Handles[0].Events & AFD_POLL_WRITE) == 0) {
        printf("FAIL %s: poll on base handle returned 0x%08lX events 0x%lX, expected WRITE\n",
               TEST_NAME, (unsigned long)(ULONG)st, out.Handles[0].Events);
        return 1;
    }

    closesocket(c);
    closesocket(s);
    p_NtClose(afd);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
