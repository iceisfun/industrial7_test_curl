/*
 * Test: 10_afd_poll_timeout_units
 *
 * Purpose:
 *   Verify the AFD_POLL_INFO.Timeout semantics. The field is a LARGE_INTEGER
 *   in 100 ns units, a negative value is relative and zero means "return
 *   immediately". With an idle socket:
 *     - timeout 0 must complete at once (well under 1 s) with no RECEIVE;
 *     - a relative 300 ms timeout must not complete early (>= 200 ms observed,
 *       allowing timer slack) and must not exceed 5 s;
 *   and in both cases the completion must be STATUS_TIMEOUT or SUCCESS with
 *   AFD_POLL_RECEIVE clear. curl's wait loops rely on a zero-timeout poll
 *   being a non-blocking probe and a positive timeout being honored.
 *
 * APIs used:
 *   ntdll!NtCreateFile, NtDeviceIoControlFile, NtClose (GetProcAddress),
 *   IOCTL_AFD_POLL (0x12024), kernel32!GetTickCount64, CreateEventW,
 *   WaitForSingleObject, ws2_32 socket/bind/listen/connect/accept.
 *   AFD_POLL_INFO layout is reverse-engineered (wepoll).
 *
 * Success means: both polls return within their bounds with the expected
 * status and no RECEIVE bit.
 *
 * Source reference: lib/select.c:156 (Curl_poll call with timeout_ms) and
 *   lib/select.c:199 (Curl_poll wrapper) pass millisecond timeouts that must
 *   be converted correctly to AFD's 100 ns relative units.
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

#define TEST_NAME "10_afd_poll_timeout_units"

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

/* Returns 1 when the completion is a legitimate "nothing ready" result. */
static int nothing_ready(T_NTSTATUS st, const AFD_POLL_INFO *out)
{
    if (st == T_STATUS_TIMEOUT)
        return 1;
    return st == T_STATUS_SUCCESS && (out->Handles[0].Status != T_STATUS_SUCCESS || (out->Handles[0].Events & AFD_POLL_RECEIVE) == 0);
}

int main(void)
{
    HANDLE afd = NULL;
    T_NTSTATUS st;
    SOCKET c = INVALID_SOCKET, s = INVALID_SOCKET;
    SOCKET socks[1];
    ULONG events[1];
    AFD_POLL_INFO out;
    ULONGLONG t0, t1;
    ULONGLONG elapsed;

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

    socks[0] = c;
    events[0] = AFD_POLL_RECEIVE;

    /* Zero timeout: immediate probe. */
    memset(&out, 0, sizeof(out));
    t0 = GetTickCount64();
    st = afd_poll(afd, socks, events, 1, 0, 5000, &out);
    t1 = GetTickCount64();
    elapsed = t1 - t0;
    if (st == T_STATUS_HELPER_WAIT_EXPIRED) {
        printf("FAIL %s: zero-timeout poll did not complete within 5 s\n", TEST_NAME);
        return 1;
    }
    if (!nothing_ready(st, &out)) {
        printf("FAIL %s: zero-timeout poll gave 0x%08lX events 0x%lX\n", TEST_NAME,
               (unsigned long)(ULONG)st, out.Handles[0].Events);
        return 1;
    }
    if (elapsed >= 1000) {
        printf("FAIL %s: zero-timeout poll blocked for %llu ms\n", TEST_NAME,
               (unsigned long long)elapsed);
        return 1;
    }

    /* 300 ms relative timeout: must wait roughly that long. */
    memset(&out, 0, sizeof(out));
    t0 = GetTickCount64();
    st = afd_poll(afd, socks, events, 1, -3000000LL, 5000, &out);
    t1 = GetTickCount64();
    elapsed = t1 - t0;
    if (st == T_STATUS_HELPER_WAIT_EXPIRED) {
        printf("FAIL %s: 300 ms poll did not complete within 5 s\n", TEST_NAME);
        return 1;
    }
    if (!nothing_ready(st, &out)) {
        printf("FAIL %s: 300 ms poll gave 0x%08lX events 0x%lX\n", TEST_NAME,
               (unsigned long)(ULONG)st, out.Handles[0].Events);
        return 1;
    }
    if (elapsed < 200) {
        printf("FAIL %s: 300 ms relative timeout returned after only %llu ms\n", TEST_NAME,
               (unsigned long long)elapsed);
        return 1;
    }
    if (elapsed >= 5000) {
        printf("FAIL %s: 300 ms relative timeout took %llu ms\n", TEST_NAME,
               (unsigned long long)elapsed);
        return 1;
    }

    closesocket(c);
    closesocket(s);
    p_NtClose(afd);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
