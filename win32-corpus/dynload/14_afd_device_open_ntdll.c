/*
 * Test: 14_afd_device_open_ntdll
 *
 * Purpose: Open an AFD (Ancillary Function Driver) endpoint the way
 *   wepoll-style and other Winsock-internal code does, without linking to any
 *   undocumented API. ntdll is loaded with LoadLibraryExW, NtCreateFile and
 *   NtClose are resolved with GetProcAddress, and an endpoint is opened under
 *   \Device\Afd\ with SYNCHRONIZE access. The handle is then closed with
 *   NtClose. AFD is the kernel driver behind Winsock sockets and
 *   WSAPoll/select, so this is the device curl's socket layer ultimately uses.
 *
 * APIs: LoadLibraryExW (LOAD_LIBRARY_SEARCH_SYSTEM32), GetProcAddress,
 *   FreeLibrary, NtCreateFile, NtClose (via pointers), RtlInitUnicodeString
 *   is not used; the UNICODE_STRING is filled by hand. Structures from winternl.h.
 *
 * Success:
 *   - ntdll resolves and exports NtCreateFile and NtClose.
 *   - NtCreateFile(\Device\Afd\Tc14Probe, SYNCHRONIZE, FILE_OPEN) returns
 *     STATUS_SUCCESS (0) and a non-NULL handle, and IO_STATUS_BLOCK.Information
 *     is FILE_OPENED (1) or FILE_CREATED (2).
 *   - NtClose(handle) returns STATUS_SUCCESS.
 *   - If the device is absent (STATUS_OBJECT_NAME_NOT_FOUND, STATUS_NO_SUCH_DEVICE
 *     or STATUS_OBJECT_PATH_NOT_FOUND) the test SKIPs; any other status is FAIL.
 *
 * Source reference: none direct in curl. curl reaches AFD indirectly through
 *   Winsock; see lib/curlx/version_win32.c:58 for the same ntdll
 *   GetProcAddress pattern used for a non-linked ntdll export.
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
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define NAME "afd_device_open_ntdll"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)
#define SKIPF(...) do { printf("SKIP " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 77; } while (0)

#define TC_STATUS_SUCCESS ((LONG)0x00000000UL)
#define TC_STATUS_OBJECT_NAME_NOT_FOUND ((LONG)0xC0000034UL)
#define TC_STATUS_OBJECT_PATH_NOT_FOUND ((LONG)0xC000003AUL)
#define TC_STATUS_NO_SUCH_DEVICE ((LONG)0xC000000EUL)
#define TC_FILE_OPENED 1UL
#define TC_FILE_CREATED 2UL
#define TC_FILE_OPEN 1UL
#define TC_OBJ_CASE_INSENSITIVE 0x00000040UL
#define TC_SYNCHRONIZE 0x00100000UL

typedef LONG (NTAPI *nt_create_file_fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG,
                                        ULONG, ULONG, ULONG, PVOID, ULONG);
typedef LONG (NTAPI *nt_close_fn)(HANDLE);

int main(void)
{
    HMODULE ntdll;
    nt_create_file_fn create_file;
    nt_close_fn close_fn;
    wchar_t name[64];
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    LONG status;
    size_t len;

    ntdll = LoadLibraryExW(L"ntdll.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!ntdll)
        FAILF("LoadLibraryExW(ntdll.dll) err=%lu", (unsigned long)GetLastError());

    create_file = (nt_create_file_fn)(void *)GetProcAddress(ntdll, "NtCreateFile");
    close_fn = (nt_close_fn)(void *)GetProcAddress(ntdll, "NtClose");
    if (!create_file || !close_fn)
        SKIPF("ntdll NtCreateFile/NtClose not resolvable (err=%lu)", (unsigned long)GetLastError());

    wcscpy(name, L"\\Device\\Afd\\Tc14Probe");
    len = wcslen(name);
    us.Buffer = name;
    us.Length = (USHORT)(len * sizeof(wchar_t));
    us.MaximumLength = (USHORT)((len + 1) * sizeof(wchar_t));

    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = TC_OBJ_CASE_INSENSITIVE;

    memset(&iosb, 0, sizeof iosb);
    status = create_file(&h, TC_SYNCHRONIZE, &oa, &iosb, NULL, 0,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, TC_FILE_OPEN, 0, NULL, 0);
    if (status == TC_STATUS_OBJECT_NAME_NOT_FOUND ||
        status == TC_STATUS_OBJECT_PATH_NOT_FOUND ||
        status == TC_STATUS_NO_SUCH_DEVICE)
        SKIPF("AFD device not present (NTSTATUS 0x%08lx)", (unsigned long)(ULONG)status);
    if (status != TC_STATUS_SUCCESS)
        FAILF("NtCreateFile(\\Device\\Afd\\Tc14Probe) NTSTATUS=0x%08lx",
              (unsigned long)(ULONG)status);
    if (h == NULL)
        FAILF("NtCreateFile succeeded but returned NULL handle");

    if (iosb.Information != TC_FILE_OPENED && iosb.Information != TC_FILE_CREATED)
        FAILF("IO_STATUS_BLOCK.Information=%lu, expected FILE_OPENED or FILE_CREATED",
              (unsigned long)iosb.Information);

    status = close_fn(h);
    if (status != TC_STATUS_SUCCESS)
        FAILF("NtClose(AFD handle) NTSTATUS=0x%08lx", (unsigned long)(ULONG)status);

    FreeLibrary(ntdll);
    printf("PASS " NAME "\n");
    return 0;
}
