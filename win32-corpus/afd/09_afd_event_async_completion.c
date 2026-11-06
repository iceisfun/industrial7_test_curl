/*
 * Test: 09_afd_event_async_completion
 *
 * Purpose:
 *   Asynchronous completion of NtDeviceIoControlFile(IOCTL_AFD_POLL) using an
 *   event handle. A poll for AFD_POLL_RECEIVE with a 5 s timeout is issued on
 *   an idle socket. It must return STATUS_PENDING immediately, the event must
 *   stay unsignaled and the IO_STATUS_BLOCK must still read STATUS_PENDING.
 *   After the peer writes data, the event must become signaled within 5 s,
 *   and the IO_STATUS_BLOCK must hold STATUS_SUCCESS with RECEIVE set.
 *   This is the completion model that the wait/event based poll path uses.
 *
 * APIs used:
 *   ntdll!NtCreateFile, NtDeviceIoControlFile, NtClose (GetProcAddress),
 *   IOCTL_AFD_POLL (0x12024), kernel32!CreateEventW, WaitForSingleObject,
 *   CloseHandle, ws2_32 socket/bind/listen/connect/accept/send.
 *   IO_STATUS_BLOCK is locally defined (NT ABI, stable). AFD_POLL_INFO layout
 *   is reverse-engineered (wepoll).
 *
 * Success means:
 *   Initial call returns STATUS_PENDING. WaitForSingleObject(event, 100 ms)
 *   returns WAIT_TIMEOUT before data is sent. After send, the event is
 *   signaled (WAIT_OBJECT_0), IOSB.Status == STATUS_SUCCESS and
 *   Handles[0].Events has AFD_POLL_RECEIVE.
 *
 * Source reference: lib/multi.c:311 creates the wake-up event with
 *   WSACreateEvent and lib/multi.c:1389 relies on the event being signaled
 *   when the socket becomes readable; this test checks the same
 *   event-on-readiness contract at the AFD level.
 *
 * Exit: 0 PASS, 1 FAIL (every API used exists on Win10 22H2: no SKIP).
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

#define TEST_NAME "09_afd_event_async_completion"

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
    HANDLE ev;
    T_NTSTATUS st;
    SOCKET c = INVALID_SOCKET, s = INVALID_SOCKET;
    /* Heap allocated: the kernel owns these until the request completes. */
    AFD_POLL_INFO *info = (AFD_POLL_INFO *)calloc(1, sizeof(AFD_POLL_INFO));
    T_IO_STATUS_BLOCK *iosb = (T_IO_STATUS_BLOCK *)calloc(1, sizeof(T_IO_STATUS_BLOCK));
    DWORD w;

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
    if (!wsa_start() || !loopback_pair(&c, &s) || !info || !iosb) {
        printf("FAIL %s: setup failed (WSA %d)\n", TEST_NAME, WSAGetLastError());
        return 1;
    }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ev) {
        printf("FAIL %s: CreateEventW failed (GetLastError %lu)\n", TEST_NAME, GetLastError());
        return 1;
    }

    info->Timeout.QuadPart = -50000000LL; /* 5 s relative */
    info->NumberOfHandles = 1;
    info->Exclusive = 0;
    info->Handles[0].Handle = (HANDLE)(ULONG_PTR)c;
    info->Handles[0].Events = AFD_POLL_RECEIVE;
    iosb->u.Status = T_STATUS_PENDING;

    st = p_NtDeviceIoControlFile(afd, ev, NULL, NULL, iosb, (ULONG)T_IOCTL_AFD_POLL, info,
                                 sizeof(*info), info, sizeof(*info));
    if (st != T_STATUS_PENDING) {
        printf("FAIL %s: idle poll returned 0x%08lX synchronously, expected STATUS_PENDING\n",
               TEST_NAME, (unsigned long)(ULONG)st);
        return 1;
    }

    w = WaitForSingleObject(ev, 100);
    if (w != WAIT_TIMEOUT) {
        printf("FAIL %s: event signaled before data was sent (wait=%lu)\n", TEST_NAME, w);
        return 1;
    }
    if (iosb->u.Status != T_STATUS_PENDING) {
        printf("FAIL %s: IOSB changed to 0x%08lX before completion\n", TEST_NAME,
               (unsigned long)(ULONG)iosb->u.Status);
        return 1;
    }

    if (send(s, "go", 2, 0) != 2) {
        printf("FAIL %s: send() failed (WSA %d)\n", TEST_NAME, WSAGetLastError());
        return 1;
    }

    w = WaitForSingleObject(ev, 5000);
    if (w != WAIT_OBJECT_0) {
        printf("FAIL %s: event not signaled after data arrived (wait=%lu)\n", TEST_NAME, w);
        return 1;
    }
    if (iosb->u.Status != T_STATUS_SUCCESS) {
        printf("FAIL %s: IOSB.Status is 0x%08lX after completion, expected SUCCESS\n", TEST_NAME,
               (unsigned long)(ULONG)iosb->u.Status);
        return 1;
    }
    if (info->Handles[0].Status != T_STATUS_SUCCESS ||
        (info->Handles[0].Events & AFD_POLL_RECEIVE) == 0) {
        printf("FAIL %s: completion events 0x%lX lack AFD_POLL_RECEIVE\n", TEST_NAME,
               info->Handles[0].Events);
        return 1;
    }

    CloseHandle(ev);
    closesocket(c);
    closesocket(s);
    p_NtClose(afd);
    free(info);
    free(iosb);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
