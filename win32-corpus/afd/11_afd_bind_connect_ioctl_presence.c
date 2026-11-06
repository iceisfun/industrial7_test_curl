/*
 * Test: 11_afd_bind_connect_ioctl_presence
 *
 * Purpose:
 *   Probe that the AFD dispatcher recognizes the socket-state IOCTLs that the
 *   Winsock kernel path uses to bind and connect sockets: IOCTL_AFD_BIND
 *   (0x12003) and IOCTL_AFD_CONNECT (0x12007). The codes are sent with empty
 *   (deliberately invalid) buffers on a bare AFD handle that has no socket
 *   attached. The AFD must not answer them with STATUS_INVALID_DEVICE_REQUEST or
 *   STATUS_NOT_IMPLEMENTED, which would mean
 *   the code is not dispatched at all. Because the structures are undocumented,
 *   we do not attempt a real bind/connect here: we only test presence.
 *   Win10 22H2 dispatches both, so a non-dispatched code is a FAIL.
 *
 * APIs used:
 *   ntdll!NtCreateFile, NtDeviceIoControlFile, NtClose (GetProcAddress),
 *   IOCTL_AFD_BIND (0x12003), IOCTL_AFD_CONNECT (0x12007),
 *   kernel32!CreateEventW, WaitForSingleObject.
 *   The control codes are reverse-engineered (wepoll / ReactOS afd.h) and
 *   may change between Windows versions.
 *
 * Success means: NtDeviceIoControlFile for both codes completes with a status
 *   that is neither STATUS_INVALID_DEVICE_REQUEST (0xC0000010) nor
 *   STATUS_NOT_IMPLEMENTED (0xC0000002).
 *
 * Source reference: lib/cf-socket.c:898 calls bind() on the socket curl
 *   creates; connect() is issued by the same socket setup. The AFD-level
 *   IOCTLs are what ws2_32 issues underneath those calls.
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
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define TEST_NAME "11_afd_bind_connect_ioctl_presence"

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

#define T_STATUS_SUCCESS ((T_NTSTATUS)0x00000000L)
#define T_STATUS_PENDING ((T_NTSTATUS)0x00000103L)
#define T_STATUS_NOT_IMPLEMENTED ((T_NTSTATUS)0xC0000002L)
#define T_STATUS_INVALID_DEVICE_REQUEST ((T_NTSTATUS)0xC0000010L)
#define T_STATUS_HELPER_WAIT_EXPIRED ((T_NTSTATUS)0xE0000001L)
#define T_OBJ_CASE_INSENSITIVE 0x00000040UL
#define T_FILE_OPEN 0x00000001UL
#define T_IOCTL_AFD_BIND 0x00012003UL
#define T_IOCTL_AFD_CONNECT 0x00012007UL

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

/*
 * Issue one device control with an event and wait for completion. Returns the
 * final status, or T_STATUS_HELPER_WAIT_EXPIRED if the wait expired (in that
 * case the request still owns its buffers, which are leaked on purpose).
 */
static T_NTSTATUS ioctl_sync(HANDLE afd, ULONG code, void *in, ULONG inlen, void *out,
                             ULONG outlen)
{
    T_IO_STATUS_BLOCK *iosb = (T_IO_STATUS_BLOCK *)calloc(1, sizeof(*iosb));
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    T_NTSTATUS st;

    if (!iosb || !ev)
        return (T_NTSTATUS)0xC000009AL;
    iosb->u.Status = T_STATUS_PENDING;
    st = p_NtDeviceIoControlFile(afd, ev, NULL, NULL, iosb, code, in, inlen, out, outlen);
    if (st == T_STATUS_PENDING) {
        if (WaitForSingleObject(ev, 5000) != WAIT_OBJECT_0)
            return T_STATUS_HELPER_WAIT_EXPIRED;
        st = iosb->u.Status;
    }
    CloseHandle(ev);
    free(iosb);
    return st;
}

int main(void)
{
    HANDLE afd = NULL;
    T_NTSTATUS st_bind, st_connect;
    T_NTSTATUS st;
    unsigned char zero[8];

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

    memset(zero, 0, sizeof(zero));
    st_bind = ioctl_sync(afd, T_IOCTL_AFD_BIND, zero, 0, zero, 0);
    if (st_bind == T_STATUS_HELPER_WAIT_EXPIRED) {
        printf("FAIL %s: IOCTL_AFD_BIND did not complete within 5 s\n", TEST_NAME);
        return 1;
    }
    st_connect = ioctl_sync(afd, T_IOCTL_AFD_CONNECT, zero, 0, zero, 0);
    if (st_connect == T_STATUS_HELPER_WAIT_EXPIRED) {
        printf("FAIL %s: IOCTL_AFD_CONNECT did not complete within 5 s\n", TEST_NAME);
        return 1;
    }

    if (st_bind == T_STATUS_INVALID_DEVICE_REQUEST || st_bind == T_STATUS_NOT_IMPLEMENTED) {
        printf("FAIL %s: IOCTL_AFD_BIND not dispatched by this AFD (0x%08lX)\n", TEST_NAME,
               (unsigned long)(ULONG)st_bind);
        p_NtClose(afd);
        return 1;
    }
    if (st_connect == T_STATUS_INVALID_DEVICE_REQUEST || st_connect == T_STATUS_NOT_IMPLEMENTED) {
        printf("FAIL %s: IOCTL_AFD_CONNECT not dispatched by this AFD (0x%08lX)\n", TEST_NAME,
               (unsigned long)(ULONG)st_connect);
        p_NtClose(afd);
        return 1;
    }

    /* Negative control: an unknown function code must not succeed. */
    st = ioctl_sync(afd, 0x00012FFCUL, zero, 0, zero, 0);
    if (st == T_STATUS_HELPER_WAIT_EXPIRED) {
        printf("FAIL %s: unknown control code did not complete within 5 s\n", TEST_NAME);
        return 1;
    }
    if (st == T_STATUS_SUCCESS) {
        printf("FAIL %s: unknown AFD control code 0x12FFFC reported success\n", TEST_NAME);
        return 1;
    }

    p_NtClose(afd);
    printf("PASS %s\n", TEST_NAME);
    return 0;
}
