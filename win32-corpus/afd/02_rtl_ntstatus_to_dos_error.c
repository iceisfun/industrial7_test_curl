/*
 * Test: 02_rtl_ntstatus_to_dos_error
 *
 * Purpose:
 *   Resolve ntdll!RtlNtStatusToDosError with GetProcAddress and verify the
 *   NTSTATUS -> Win32 error mapping that curl's error paths depend on when an
 *   AFD or NT I/O call fails (the NTSTATUS from NtDeviceIoControlFile is
 *   converted to a Win32 error for logging). AFD must be openable first,
 *   otherwise the test SKIPs.
 *
 * APIs used:
 *   ntdll!NtCreateFile, ntdll!NtClose, ntdll!RtlNtStatusToDosError
 *   (all via GetProcAddress), kernel32!GetModuleHandleW, LoadLibraryW.
 *
 * Success means:
 *   The mapping returns the documented Win32 codes:
 *     STATUS_SUCCESS                 (0x00000000) -> ERROR_SUCCESS (0)
 *     STATUS_INVALID_HANDLE          (0xC0000008) -> ERROR_INVALID_HANDLE (6)
 *     STATUS_OBJECT_NAME_NOT_FOUND   (0xC0000034) -> ERROR_FILE_NOT_FOUND (2)
 *     STATUS_INVALID_PARAMETER       (0xC000000D) -> ERROR_INVALID_PARAMETER (87)
 *     STATUS_PENDING                 (0x00000103) -> ERROR_IO_PENDING (997)
 *     STATUS_INSUFFICIENT_RESOURCES  (0xC000009A) -> ERROR_NO_SYSTEM_RESOURCES (1450)
 *
 * Source reference: no direct call site in curl. The WSAEventSelect failure
 *   check at lib/multi.c:1389 maps any error to CURLM_OUT_OF_MEMORY without
 *   reading the Win32 code, so this mapping is not on that path; it is a
 *   building block for AFD error reporting only.
 *
 * Exit: 0 PASS, 77 SKIP (AFD or ntdll exports missing), 1 FAIL.
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

#define TEST_NAME "02_rtl_ntstatus_to_dos_error"

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
#define T_OBJ_CASE_INSENSITIVE 0x00000040UL
#define T_FILE_OPEN 0x00000001UL

typedef T_NTSTATUS(NTAPI *fn_NtCreateFile)(PHANDLE, ACCESS_MASK, T_OBJECT_ATTRIBUTES *,
                                           T_IO_STATUS_BLOCK *, PLARGE_INTEGER, ULONG,
                                           ULONG, ULONG, ULONG, PVOID, ULONG);
typedef T_NTSTATUS(NTAPI *fn_NtClose)(HANDLE);
typedef ULONG(NTAPI *fn_RtlNtStatusToDosError)(T_NTSTATUS);

static fn_NtCreateFile p_NtCreateFile;
static fn_NtClose p_NtClose;
static fn_RtlNtStatusToDosError p_RtlNtStatusToDosError;

static int load_ntdll(void)
{
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h)
        h = LoadLibraryW(L"ntdll.dll");
    if (!h)
        return 0;
    p_NtCreateFile = (fn_NtCreateFile)(void *)GetProcAddress(h, "NtCreateFile");
    p_NtClose = (fn_NtClose)(void *)GetProcAddress(h, "NtClose");
    p_RtlNtStatusToDosError =
        (fn_RtlNtStatusToDosError)(void *)GetProcAddress(h, "RtlNtStatusToDosError");
    return p_NtCreateFile && p_NtClose && p_RtlNtStatusToDosError;
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

static int check_map(const char *label, T_NTSTATUS in, ULONG expect)
{
    ULONG got = p_RtlNtStatusToDosError(in);
    if (got != expect) {
        printf("FAIL %s: RtlNtStatusToDosError(%s = 0x%08lX) = %lu, expected %lu\n",
               TEST_NAME, label, (unsigned long)(ULONG)in, got, expect);
        return 0;
    }
    return 1;
}

int main(void)
{
    HANDLE afd = NULL;
    T_NTSTATUS st;

    if (!load_ntdll()) {
        printf("SKIP %s: ntdll does not export required Nt/Rtl functions\n", TEST_NAME);
        return 77;
    }
    st = open_afd(&afd);
    if (st < 0 || afd == NULL) {
        printf("SKIP %s: cannot open \\Device\\Afd (NTSTATUS 0x%08lX)\n", TEST_NAME,
               (unsigned long)(ULONG)st);
        return 77;
    }
    p_NtClose(afd);

    if (!check_map("STATUS_SUCCESS", 0x00000000L, 0))
        return 1;
    if (!check_map("STATUS_INVALID_HANDLE", (T_NTSTATUS)0xC0000008L, ERROR_INVALID_HANDLE))
        return 1;
    if (!check_map("STATUS_OBJECT_NAME_NOT_FOUND", (T_NTSTATUS)0xC0000034L,
                   ERROR_FILE_NOT_FOUND))
        return 1;
    if (!check_map("STATUS_INVALID_PARAMETER", (T_NTSTATUS)0xC000000DL,
                   ERROR_INVALID_PARAMETER))
        return 1;
    if (!check_map("STATUS_PENDING", (T_NTSTATUS)0x00000103L, ERROR_IO_PENDING))
        return 1;
    if (!check_map("STATUS_INSUFFICIENT_RESOURCES", (T_NTSTATUS)0xC000009AL,
                   ERROR_NO_SYSTEM_RESOURCES))
        return 1;

    printf("PASS %s\n", TEST_NAME);
    return 0;
}
