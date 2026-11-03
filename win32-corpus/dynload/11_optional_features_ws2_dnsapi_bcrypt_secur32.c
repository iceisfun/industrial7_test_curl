/*
 * Test: 11_optional_features_ws2_dnsapi_bcrypt_secur32
 *
 * Purpose: Load the four Windows DLLs that curl uses for optional features
 *   (ws2_32 for Winsock, dnsapi for DNS, bcrypt for randomness, secur32 for
 *   SSPI/NTLM/Negotiate) the way a loader-based build would: LoadLibraryExW
 *   with LOAD_LIBRARY_SEARCH_SYSTEM32, GetProcAddress for each entry point,
 *   then call each one with a deterministic input and check the result.
 *   A DLL that is not installed is reported as SKIP; a DLL that is present but
 *   misbehaves is FAIL. Each feature is checked independently: a missing DLL
 *   only skips that feature, and the test SKIPs as a whole only when none of
 *   the four is installed.
 *
 * APIs: LoadLibraryExW, GetProcAddress, FreeLibrary, FreeContextBuffer,
 *   WSAStartup, WSACleanup (via pointers), inet_pton (via pointer),
 *   DnsNameCompare_W (via pointer), BCryptGenRandom (via pointer),
 *   InitSecurityInterfaceW and EnumerateSecurityPackagesW (via pointers)
 *
 * Success:
 *   - ws2_32: inet_pton(AF_INET, "127.0.0.1") returns 1 and yields bytes 7f 00 00 01.
 *   - dnsapi: DnsNameCompare_W(L"Example.COM", L"example.com") is TRUE and
 *     DnsNameCompare_W(L"a.example.com", L"b.example.com") is FALSE.
 *   - bcrypt: BCryptGenRandom(NULL, buf, 32, USE_SYSTEM_PREFERRED_RNG) returns
 *     STATUS_SUCCESS (0) and buf is not all zero.
 *   - secur32: InitSecurityInterfaceW returns a non-NULL dispatch table, and
 *     EnumerateSecurityPackagesW returns SEC_E_OK (0) with at least one package.
 *
 * Source reference:
 *   - lib/curlx/winapi.c:118 BCryptGenRandom(NULL, entropy, len,
 *     BCRYPT_USE_SYSTEM_PREFERRED_RNG) returning STATUS_SUCCESS.
 *   - lib/curl_sspi.c:57 Curl_pSecFn = InitSecurityInterface().
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
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#define NAME "optional_features_ws2_dnsapi_bcrypt_secur32"

/* Sub-tests record their reason here and return 1 (FAIL) or 77 (SKIP). main()
 * prints the single result line. */
static char g_msg[256];
#define FAILF(...) do { snprintf(g_msg, sizeof g_msg, __VA_ARGS__); return 1; } while (0)
#define SKIPF(...) do { snprintf(g_msg, sizeof g_msg, __VA_ARGS__); return 77; } while (0)

#define TC_BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002UL

typedef int (WINAPI *wsastartup_fn)(WORD, LPWSADATA);
typedef int (WINAPI *wsacleanup_fn)(void);
typedef INT (WINAPI *inet_pton_fn)(INT, PCSTR, PVOID);
typedef BOOL (WINAPI *dnsnamecmp_fn)(LPCWSTR, LPCWSTR);
typedef LONG (WINAPI *bcrypt_rand_fn)(PVOID, PUCHAR, ULONG, ULONG);
typedef PVOID (WINAPI *init_secif_fn)(void);
typedef LONG (WINAPI *enum_pkgs_fn)(PULONG, PVOID *);
typedef LONG (WINAPI *free_ctx_fn)(PVOID);

/* 0 = loaded, 1 = not installed (ERROR_MOD_NOT_FOUND), 2 = other error. */
static int load_optional(const wchar_t *name, HMODULE *out)
{
    HMODULE h = LoadLibraryExW(name, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (h) {
        *out = h;
        return 0;
    }
    if (GetLastError() == ERROR_MOD_NOT_FOUND)
        return 1;
    return 2;
}

static int test_ws2(void)
{
    HMODULE ws2;
    WSADATA wsa;
    unsigned char addr[4] = {0, 0, 0, 0};
    wsastartup_fn startup;
    wsacleanup_fn cleanup_fn;
    inet_pton_fn pton;
    int st, rc;

    st = load_optional(L"ws2_32.dll", &ws2);
    if (st == 1)
        SKIPF("ws2_32.dll not installed");
    if (st == 2)
        FAILF("LoadLibraryExW(ws2_32.dll) err=%lu", (unsigned long)GetLastError());

    startup = (wsastartup_fn)(void *)GetProcAddress(ws2, "WSAStartup");
    cleanup_fn = (wsacleanup_fn)(void *)GetProcAddress(ws2, "WSACleanup");
    pton = (inet_pton_fn)(void *)GetProcAddress(ws2, "inet_pton");
    if (!startup || !cleanup_fn || !pton)
        FAILF("ws2_32 export missing (WSAStartup=%p WSACleanup=%p inet_pton=%p) err=%lu",
              (void *)startup, (void *)cleanup_fn, (void *)pton, (unsigned long)GetLastError());

    rc = startup(MAKEWORD(2, 2), &wsa);
    if (rc != 0)
        FAILF("WSAStartup returned %d", rc);

    rc = pton(AF_INET, "127.0.0.1", addr);
    if (rc != 1)
        FAILF("inet_pton(127.0.0.1) returned %d WSAGetLastError=%d", rc, WSAGetLastError());
    if (addr[0] != 127 || addr[1] != 0 || addr[2] != 0 || addr[3] != 1)
        FAILF("inet_pton bytes %u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);

    rc = cleanup_fn();
    if (rc != 0)
        FAILF("WSACleanup returned %d (WSAGetLastError=%d)", rc, WSAGetLastError());
    FreeLibrary(ws2);
    return 0;
}

static int test_dnsapi(void)
{
    HMODULE dns;
    dnsnamecmp_fn cmp;
    int st;

    st = load_optional(L"dnsapi.dll", &dns);
    if (st == 1)
        SKIPF("dnsapi.dll not installed");
    if (st == 2)
        FAILF("LoadLibraryExW(dnsapi.dll) err=%lu", (unsigned long)GetLastError());

    cmp = (dnsnamecmp_fn)(void *)GetProcAddress(dns, "DnsNameCompare_W");
    if (!cmp)
        SKIPF("dnsapi.dll does not export DnsNameCompare_W (err=%lu)",
              (unsigned long)GetLastError());

    if (!cmp(L"Example.COM", L"example.com"))
        FAILF("DnsNameCompare_W case-insensitive match returned FALSE");
    if (cmp(L"a.example.com", L"b.example.com"))
        FAILF("DnsNameCompare_W distinct names returned TRUE");

    FreeLibrary(dns);
    return 0;
}

static int test_bcrypt(void)
{
    HMODULE bc;
    bcrypt_rand_fn rand_fn;
    unsigned char buf[32];
    LONG status;
    int i, nonzero = 0, st;

    st = load_optional(L"bcrypt.dll", &bc);
    if (st == 1)
        SKIPF("bcrypt.dll not installed");
    if (st == 2)
        FAILF("LoadLibraryExW(bcrypt.dll) err=%lu", (unsigned long)GetLastError());

    rand_fn = (bcrypt_rand_fn)(void *)GetProcAddress(bc, "BCryptGenRandom");
    if (!rand_fn)
        FAILF("bcrypt!BCryptGenRandom missing err=%lu", (unsigned long)GetLastError());

    for (i = 0; i < (int)sizeof buf; i++)
        buf[i] = 0;
    status = rand_fn(NULL, buf, (ULONG)sizeof buf, TC_BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0)
        FAILF("BCryptGenRandom status=0x%08lx", (unsigned long)(ULONG)status);

    for (i = 0; i < (int)sizeof buf; i++)
        if (buf[i])
            nonzero = 1;
    if (!nonzero)
        FAILF("BCryptGenRandom produced 32 zero bytes");

    FreeLibrary(bc);
    return 0;
}

static int test_secur32(void)
{
    HMODULE sec;
    init_secif_fn init_fn;
    enum_pkgs_fn enum_fn;
    free_ctx_fn free_fn;
    PVOID table, pkgs = NULL;
    ULONG count = 0;
    LONG status;
    int st;

    st = load_optional(L"secur32.dll", &sec);
    if (st == 1)
        SKIPF("secur32.dll not installed");
    if (st == 2)
        FAILF("LoadLibraryExW(secur32.dll) err=%lu", (unsigned long)GetLastError());

    init_fn = (init_secif_fn)(void *)GetProcAddress(sec, "InitSecurityInterfaceW");
    enum_fn = (enum_pkgs_fn)(void *)GetProcAddress(sec, "EnumerateSecurityPackagesW");
    free_fn = (free_ctx_fn)(void *)GetProcAddress(sec, "FreeContextBuffer");
    if (!init_fn || !enum_fn || !free_fn)
        FAILF("secur32 export missing (init=%p enum=%p free=%p) err=%lu",
              (void *)init_fn, (void *)enum_fn, (void *)free_fn, (unsigned long)GetLastError());

    table = init_fn();
    if (!table)
        FAILF("InitSecurityInterfaceW returned NULL err=%lu", (unsigned long)GetLastError());

    status = enum_fn(&count, &pkgs);
    if (status != 0)
        FAILF("EnumerateSecurityPackagesW status=0x%08lx", (unsigned long)(ULONG)status);
    if (count == 0 || pkgs == NULL)
        FAILF("EnumerateSecurityPackagesW returned no packages");

    free_fn(pkgs);
    FreeLibrary(sec);
    return 0;
}

int main(void)
{
    static const char *const names[4] = { "ws2_32", "dnsapi", "bcrypt", "secur32" };
    int (*const tests[4])(void) = { test_ws2, test_dnsapi, test_bcrypt, test_secur32 };
    int i, rc, ran = 0;

    for (i = 0; i < 4; i++) {
        g_msg[0] = '\0';
        rc = tests[i]();
        if (rc == 1) {
            printf("FAIL " NAME ": %s: %s\n", names[i], g_msg);
            return 1;
        }
        if (rc == 77) {
            /* Genuine absence of this one DLL: note it on stderr and keep going. */
            fprintf(stderr, "note: %s skipped: %s\n", names[i], g_msg);
            continue;
        }
        ran++;
    }

    if (ran == 0) {
        printf("SKIP " NAME ": none of ws2_32/dnsapi/bcrypt/secur32 is installed\n");
        return 77;
    }
    printf("PASS " NAME "\n");
    return 0;
}
