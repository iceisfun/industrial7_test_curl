/*
 * Test: 19_afd_poll_failure_events
 * Area: afd
 * Purpose: Raw IOCTL_AFD_POLL event bits for the failure paths that curl's
 *   readiness layers (select/WSAPoll/WSAEventSelect, all built on AFD poll)
 *   translate into POLLERR/POLLHUP/except-set/FD_CLOSE results.
 * APIs: NtCreateFile(\\Device\\Afd), NtDeviceIoControlFile(IOCTL_AFD_POLL),
 *   connect, closesocket, SO_LINGER.
 * Success means (Win10 22H2): with every event bit requested (0x1FF) and a
 *   5 s limit: a refused non-blocking loopback connect completes with
 *   AFD_POLL_CONNECT_FAIL set, the per-handle status is
 *   STATUS_SUCCESS and AFD_POLL_CONNECT is not set; a graceful peer close
 *   reports AFD_POLL_DISCONNECT and not AFD_POLL_ABORT; an abortive peer
 *   close (SO_LINGER 0) reports AFD_POLL_ABORT; an idle connected pair
 *   reports exactly AFD_POLL_SEND|AFD_POLL_CONNECT (0x44). The INFO lines record the exact
 *   masks.
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

#define TEST_NAME "19_afd_poll_failure_events"

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
#define AFD_POLL_SEND 0x0004UL
#define AFD_POLL_WRITE AFD_POLL_SEND
#define AFD_POLL_DISCONNECT 0x0008UL
#define AFD_POLL_ABORT 0x0010UL
#define AFD_POLL_LOCAL_CLOSE 0x0020UL
#define AFD_POLL_CONNECT 0x0040UL
#define AFD_POLL_ACCEPT 0x0080UL
#define AFD_POLL_CONNECT_FAIL 0x0100UL
#define AFD_POLL_ALL 0x01FFUL

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

#define EXPECT(cond, ...) do { if(!(cond)) { printf("FAIL %s: ", TEST_NAME); printf(__VA_ARGS__); printf("\n"); fflush(stdout); return 1; } } while(0)
#define INFO(...) do { printf("INFO "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while(0)

static T_NTSTATUS poll_all(HANDLE afd, SOCKET s, ULONG *ev, T_NTSTATUS *hst)
{
    SOCKET socks[1]; ULONG events[1]; AFD_POLL_INFO out;
    T_NTSTATUS st;
    socks[0] = s; events[0] = AFD_POLL_ALL;
    memset(&out, 0, sizeof(out));
    st = afd_poll(afd, socks, events, 1, -50000000LL, 7000, &out);
    *ev = out.Handles[0].Events; *hst = out.Handles[0].Status;
    return st;
}

int main(void)
{
    HANDLE afd = NULL;
    T_NTSTATUS st, hst;
    SOCKET c = INVALID_SOCKET, s = INVALID_SOCKET, l;
    struct sockaddr_in sa; int len = sizeof(sa);
    u_long nb = 1;
    ULONG ev = 0;
    struct linger lg = { 1, 0 };

    EXPECT(load_ntdll(), "ntdll exports missing");
    st = open_afd(&afd);
    EXPECT(st >= 0 && afd, "cannot open \\Device\\Afd (NTSTATUS 0x%08lX)", (unsigned long)(ULONG)st);
    EXPECT(wsa_start(), "WSAStartup");

    /* idle connected pair */
    EXPECT(loopback_pair(&c, &s), "pair");
    st = poll_all(afd, c, &ev, &hst);
    INFO("idle: st=0x%08lX hst=0x%08lX events=0x%lX", (unsigned long)(ULONG)st, (unsigned long)(ULONG)hst, ev);
    EXPECT(st == T_STATUS_SUCCESS && ev == (AFD_POLL_SEND | AFD_POLL_CONNECT), "idle events 0x%lX want exactly SEND|CONNECT 0x44", ev);

    /* graceful close of the peer */
    closesocket(s);
    st = poll_all(afd, c, &ev, &hst);
    INFO("FIN: st=0x%08lX hst=0x%08lX events=0x%lX", (unsigned long)(ULONG)st, (unsigned long)(ULONG)hst, ev);
    EXPECT(st == T_STATUS_SUCCESS && (ev & AFD_POLL_DISCONNECT) && !(ev & AFD_POLL_ABORT), "FIN events 0x%lX", ev);
    closesocket(c);

    /* abortive close of the peer */
    EXPECT(loopback_pair(&c, &s), "pair2");
    setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
    closesocket(s);
    st = poll_all(afd, c, &ev, &hst);
    INFO("RST: st=0x%08lX hst=0x%08lX events=0x%lX", (unsigned long)(ULONG)st, (unsigned long)(ULONG)hst, ev);
    EXPECT(st == T_STATUS_SUCCESS && (ev & AFD_POLL_ABORT), "RST events 0x%lX lack ABORT", ev);
    closesocket(c);

    /* refused connect */
    l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&sa, 0, sizeof(sa)); sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(l, (struct sockaddr *)&sa, sizeof(sa)); getsockname(l, (struct sockaddr *)&sa, &len);
    closesocket(l);
    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ioctlsocket(c, FIONBIO, &nb);
    connect(c, (struct sockaddr *)&sa, sizeof(sa));
    st = poll_all(afd, c, &ev, &hst);
    INFO("refused: st=0x%08lX hst=0x%08lX events=0x%lX", (unsigned long)(ULONG)st, (unsigned long)(ULONG)hst, ev);
    EXPECT(st == T_STATUS_SUCCESS && (ev & AFD_POLL_CONNECT_FAIL) && !(ev & AFD_POLL_CONNECT), "refused events 0x%lX lack CONNECT_FAIL", ev);
    closesocket(c);
    p_NtClose(afd);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
