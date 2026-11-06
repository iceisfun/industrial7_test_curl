/*
 * Test: 17_curl_import_surface
 *
 * Purpose: the Windows exports curl resolves at run time (or links) are all
 *   present on Win10 22H2, and the wine-only marker export is absent. This is
 *   the check behind curl's "probe a newer export, fall back to an older one"
 *   pattern: on Win10 the newer export must be found, so the fallback path is
 *   not silently the only path taken.
 *
 * Success: every symbol below resolves with GetProcAddress in its DLL
 *   (loaded with LOAD_LIBRARY_SEARCH_SYSTEM32) and ntdll does not export
 *   wine_get_version. InitSecurityInterfaceW returns a non-NULL table whose
 *   dwVersion is non-zero. GetTickCount64 advances over a 60 ms Sleep by
 *   at least 45 ms and less than 500 ms.
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
#include <stdio.h>
#include <wchar.h>

#define SECURITY_WIN32
#include <security.h>
#define NAME "curl_import_surface"
#define FAILF(...) do { printf("FAIL " NAME ": "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

struct imp { const wchar_t *dll; const char *sym; };

int main(void)
{
    static const struct imp imps[] = {
        { L"kernel32.dll", "GetTickCount64" }, { L"kernel32.dll", "QueryPerformanceCounter" },
        { L"kernel32.dll", "QueryPerformanceFrequency" },
        { L"kernel32.dll", "GetSystemTimePreciseAsFileTime" },
        { L"kernel32.dll", "SetFileCompletionNotificationModes" },
        { L"kernel32.dll", "GetModuleHandleExW" }, { L"kernel32.dll", "AddDllDirectory" },
        { L"kernel32.dll", "SetDefaultDllDirectories" }, { L"kernel32.dll", "CancelIoEx" },
        { L"kernel32.dll", "InitializeConditionVariable" },
        { L"kernel32.dll", "SleepConditionVariableCS" },
        { L"kernel32.dll", "IsWow64Process2" }, { L"kernel32.dll", "SetThreadDescription" },
        { L"ws2_32.dll", "GetAddrInfoExW" }, { L"ws2_32.dll", "GetAddrInfoExCancel" },
        { L"ws2_32.dll", "GetAddrInfoExOverlappedResult" }, { L"ws2_32.dll", "FreeAddrInfoExW" },
        { L"ws2_32.dll", "WSAPoll" }, { L"ws2_32.dll", "inet_ntop" }, { L"ws2_32.dll", "inet_pton" },
        { L"ws2_32.dll", "getaddrinfo" }, { L"ws2_32.dll", "WSAConnectByNameW" },
        { L"iphlpapi.dll", "if_nametoindex" }, { L"iphlpapi.dll", "if_indextoname" },
        { L"iphlpapi.dll", "GetAdaptersAddresses" }, { L"iphlpapi.dll", "GetBestInterfaceEx" },
        { L"ntdll.dll", "RtlVerifyVersionInfo" }, { L"ntdll.dll", "RtlGetVersion" },
        { L"ntdll.dll", "NtQueryInformationProcess" },
        { L"secur32.dll", "InitSecurityInterfaceW" }, { L"secur32.dll", "InitSecurityInterfaceA" },
        { L"bcrypt.dll", "BCryptGenRandom" },
    };
    unsigned i;
    HMODULE nt;
    typedef PSecurityFunctionTableW (SEC_ENTRY *init_fn)(void);
    init_fn init;
    PSecurityFunctionTableW tbl;
    ULONGLONG t0;

    for (i = 0; i < sizeof imps / sizeof imps[0]; i++) {
        HMODULE h = LoadLibraryExW(imps[i].dll, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!h)
            FAILF("%ls did not load err=%lu", imps[i].dll, (unsigned long)GetLastError());
        if (!GetProcAddress(h, imps[i].sym))
            FAILF("%ls!%s not exported", imps[i].dll, imps[i].sym);
    }

    nt = GetModuleHandleW(L"ntdll.dll");
    if (GetProcAddress(nt, "wine_get_version") != NULL)
        FAILF("ntdll exports wine_get_version: this is not Windows");

    init = (init_fn)(void *)GetProcAddress(GetModuleHandleW(L"secur32.dll"), "InitSecurityInterfaceW");
    tbl = init();
    if (!tbl || tbl->dwVersion == 0)
        FAILF("InitSecurityInterfaceW returned %p", (void *)tbl);

    t0 = GetTickCount64();
    Sleep(60);
    t0 = GetTickCount64() - t0;
    if (t0 < 45 || t0 >= 500)
        FAILF("GetTickCount64 advanced %llu ms over Sleep(60)", (unsigned long long)t0);

    printf("PASS " NAME "\n");
    return 0;
}
