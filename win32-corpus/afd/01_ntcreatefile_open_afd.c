/*
 * Test: 01_ntcreatefile_open_afd
 *
 * Purpose:
 *   Open the AFD (Ancillary Function Driver) device "\Device\Afd" through the
 *   native NT API NtCreateFile, which is resolved at run time from ntdll.dll
 *   with GetProcAddress (it is not in any mingw import library). Verify that
 *   the open succeeds, that two independent opens yield distinct handles, that
 *   NtClose accepts them, and that a bogus device name is rejected.
 *
 * APIs used:
 *   ntdll!NtCreateFile, ntdll!NtClose (via GetProcAddress),
 *   kernel32!GetModuleHandleW, LoadLibraryW, GetProcAddress.
 *   Undocumented structures T_UNICODE_STRING / T_OBJECT_ATTRIBUTES /
 *   T_IO_STATUS_BLOCK are defined locally. They mirror the public ntdef.h
 *   layouts that have been stable since NT 4 (reverse-engineered, may vary
 *   by Windows version only in reserved fields, which we never touch).
 *
 * Success means:
 *   NtCreateFile("\\Device\\Afd") returns STATUS_SUCCESS with a non-NULL
 *   handle, a second open returns a different handle, NtClose returns
 *   STATUS_SUCCESS for both, and "\\Device\\AfdNoSuchDevice" fails with a
 *   status that is not success.
 *
 * Source reference: curl does not open \Device\Afd directly; the AFD code
 *   path is reached through WSAEventSelect/WSAPoll in lib/multi.c:1389
 *   (WSAEventSelect on the socket handle), which AFD services underneath.
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
#include <string.h>
#include <wchar.h>

#define TEST_NAME "01_ntcreatefile_open_afd"

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
#define T_STATUS_OBJECT_NAME_NOT_FOUND ((T_NTSTATUS)0xC0000034L)
#define T_OBJ_CASE_INSENSITIVE 0x00000040UL
#define T_FILE_OPEN 0x00000001UL

typedef T_NTSTATUS(NTAPI *fn_NtCreateFile)(PHANDLE, ACCESS_MASK, T_OBJECT_ATTRIBUTES *,
                                           T_IO_STATUS_BLOCK *, PLARGE_INTEGER, ULONG,
                                           ULONG, ULONG, ULONG, PVOID, ULONG);
typedef T_NTSTATUS(NTAPI *fn_NtClose)(HANDLE);

static fn_NtCreateFile p_NtCreateFile;
static fn_NtClose p_NtClose;

static int load_ntdll(void)
{
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h)
        h = LoadLibraryW(L"ntdll.dll");
    if (!h)
        return 0;
    p_NtCreateFile = (fn_NtCreateFile)(void *)GetProcAddress(h, "NtCreateFile");
    p_NtClose = (fn_NtClose)(void *)GetProcAddress(h, "NtClose");
    return p_NtCreateFile != NULL && p_NtClose != NULL;
}

static T_NTSTATUS open_device(const wchar_t *devname, HANDLE *out)
{
    wchar_t buf[256];
    T_UNICODE_STRING us;
    T_OBJECT_ATTRIBUTES oa;
    T_IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    T_NTSTATUS st;

    wcscpy(buf, devname);
    us.Length = (USHORT)(wcslen(buf) * sizeof(wchar_t));
    us.MaximumLength = (USHORT)(us.Length + sizeof(wchar_t));
    us.Buffer = buf;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = T_OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    memset(&iosb, 0, sizeof(iosb));
    st = p_NtCreateFile(&h, SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE, &oa, &iosb, NULL,
                        0, FILE_SHARE_READ | FILE_SHARE_WRITE, T_FILE_OPEN, 0, NULL, 0);
    if (out)
        *out = (st >= 0) ? h : NULL;
    return st;
}

int main(void)
{
    T_NTSTATUS st;
    HANDLE a = NULL, b = NULL;
    T_NTSTATUS st_bad;
    HANDLE bogus = NULL;

    if (!load_ntdll()) {
        printf("FAIL %s: ntdll does not export NtCreateFile/NtClose\n", TEST_NAME);
        return 1;
    }

    st = open_device(L"\\Device\\Afd", &a);
    if (st < 0 || a == NULL) {
        printf("FAIL %s: cannot open \\Device\\Afd (NTSTATUS 0x%08lX)\n", TEST_NAME,
               (unsigned long)(ULONG)st);
        return 1;
    }

    st = open_device(L"\\Device\\Afd", &b);
    if (st != T_STATUS_SUCCESS || b == NULL) {
        printf("FAIL %s: second open of \\Device\\Afd returned 0x%08lX (GetLastError=%lu)\n",
               TEST_NAME, (unsigned long)(ULONG)st, GetLastError());
        p_NtClose(a);
        return 1;
    }
    if (a == b) {
        printf("FAIL %s: two opens returned the same handle %p\n", TEST_NAME, a);
        p_NtClose(a);
        p_NtClose(b);
        return 1;
    }

    st_bad = open_device(L"\\Device\\AfdNoSuchDevice", &bogus);
    if (st_bad == T_STATUS_SUCCESS || bogus != NULL) {
        printf("FAIL %s: bogus device name unexpectedly opened (0x%08lX)\n", TEST_NAME,
               (unsigned long)(ULONG)st_bad);
        p_NtClose(a);
        p_NtClose(b);
        if (bogus)
            p_NtClose(bogus);
        return 1;
    }

    st = p_NtClose(a);
    if (st != T_STATUS_SUCCESS) {
        printf("FAIL %s: NtClose(a) returned 0x%08lX\n", TEST_NAME, (unsigned long)(ULONG)st);
        p_NtClose(b);
        return 1;
    }
    st = p_NtClose(b);
    if (st != T_STATUS_SUCCESS) {
        printf("FAIL %s: NtClose(b) returned 0x%08lX\n", TEST_NAME, (unsigned long)(ULONG)st);
        return 1;
    }

    printf("PASS %s\n", TEST_NAME);
    return 0;
}
