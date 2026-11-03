/*
 * schannel_11_server_garbage_token_error
 *
 * Purpose: Failure path of the client handshake loop. After the ClientHello,
 * curl feeds the bytes received from the server into InitializeSecurityContextW
 * (SECBUFFER_TOKEN input). If those bytes are a complete record that is not
 * valid TLS (here a record with the unknown content type 0x99 and a 2-byte body,
 * e.g. an HTTP peer or corruption), Schannel must reject them rather than
 * report progress. An HTTP status line was tried first but is not a complete
 * record (its length field reads as ~20 KB), so Schannel correctly reports
 * SEC_E_INCOMPLETE_MESSAGE for it; that case is covered by test 12.
 * curl's default branch then fails the connection (lib/vtls/schannel.c:1354-1410
 * and the error switch around :1365-1395).
 *
 * APIs: LoadLibraryW(secur32.dll), GetProcAddress, AcquireCredentialsHandleW,
 *       InitializeSecurityContextW (second call with SECBUFFER_TOKEN input),
 *       FreeContextBuffer, DeleteSecurityContext, FreeCredentialsHandle.
 *
 * Success: the second InitializeSecurityContextW returns SEC_E_ILLEGAL_MESSAGE
 *   (0x80090326) or SEC_E_INVALID_TOKEN (0x80090308), never SEC_I_CONTINUE_NEEDED
 *   or SEC_E_OK. Any alert token written to the output is freed and the
 *   context and credential are deleted with SEC_E_OK.
 *
 * Source reference: lib/vtls/schannel.c:1354-1410 (server-data
 *   InitializeSecurityContext in the handshake loop and its failure branch),
 *   lib/vtls/schannel.c:1365 (SEC_E_INCOMPLETE_MESSAGE handled separately, see
 *   test 12).
 */
#define TEST_NAME "schannel_11_server_garbage_token_error"
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define SECURITY_WIN32
#define ISSP_MODE 1
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sspi.h>
#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>
#include <security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifndef SECBUFFER_APPLICATION_PROTOCOLS
#define SECBUFFER_APPLICATION_PROTOCOLS 18
#endif
#ifndef SCHANNEL_CRED_VERSION
#define SCHANNEL_CRED_VERSION 0x00000004
#endif
#ifndef SCH_CREDENTIALS_VERSION
#define SCH_CREDENTIALS_VERSION 0x00000005
#endif
#ifndef SecApplicationProtocolNegotiationExt_ALPN
#define SecApplicationProtocolNegotiationExt_ALPN 2
#endif

/* Same request flags curl passes to InitializeSecurityContext
   (lib/vtls/schannel.c:978-981, without the optional supplied-creds bit). */
#define CURL_ISC_REQ_FLAGS (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | \
                            ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | \
                            ISC_REQ_STREAM)

/* Function table shape used by curl (Curl_pSecFn) plus the enumerate call. */
typedef struct sspi_fns {
  ACQUIRE_CREDENTIALS_HANDLE_FN_W AcquireCredentialsHandleW;
  FREE_CREDENTIALS_HANDLE_FN FreeCredentialsHandle;
  INITIALIZE_SECURITY_CONTEXT_FN_W InitializeSecurityContextW;
  DELETE_SECURITY_CONTEXT_FN DeleteSecurityContext;
  QUERY_CONTEXT_ATTRIBUTES_FN_W QueryContextAttributesW;
  FREE_CONTEXT_BUFFER_FN FreeContextBuffer;
  ENCRYPT_MESSAGE_FN EncryptMessage;
  DECRYPT_MESSAGE_FN DecryptMessage;
  ENUMERATE_SECURITY_PACKAGES_FN_W EnumerateSecurityPackagesW;
} sspi_fns;

#define RESOLVE_FN(field, type, name) \
  (f->field = (type)(void *)GetProcAddress(m, (name)))

/* LoadLibrary secur32.dll (fallback sspicli.dll) and GetProcAddress every
   SSPI export used by curl's Schannel backend. Returns NULL when the module
   or any export is missing, which callers turn into SKIP. */
static inline HMODULE load_sspi(sspi_fns *f) {
  HMODULE m = LoadLibraryW(L"secur32.dll");
  if (!m)
    m = LoadLibraryW(L"sspicli.dll");
  if (!m)
    return NULL;
  RESOLVE_FN(AcquireCredentialsHandleW, ACQUIRE_CREDENTIALS_HANDLE_FN_W,
             "AcquireCredentialsHandleW");
  RESOLVE_FN(FreeCredentialsHandle, FREE_CREDENTIALS_HANDLE_FN,
             "FreeCredentialsHandle");
  RESOLVE_FN(InitializeSecurityContextW, INITIALIZE_SECURITY_CONTEXT_FN_W,
             "InitializeSecurityContextW");
  RESOLVE_FN(DeleteSecurityContext, DELETE_SECURITY_CONTEXT_FN,
             "DeleteSecurityContext");
  RESOLVE_FN(QueryContextAttributesW, QUERY_CONTEXT_ATTRIBUTES_FN_W,
             "QueryContextAttributesW");
  RESOLVE_FN(FreeContextBuffer, FREE_CONTEXT_BUFFER_FN, "FreeContextBuffer");
  RESOLVE_FN(EncryptMessage, ENCRYPT_MESSAGE_FN, "EncryptMessage");
  RESOLVE_FN(DecryptMessage, DECRYPT_MESSAGE_FN, "DecryptMessage");
  RESOLVE_FN(EnumerateSecurityPackagesW, ENUMERATE_SECURITY_PACKAGES_FN_W,
             "EnumerateSecurityPackagesW");
  if (!f->AcquireCredentialsHandleW || !f->FreeCredentialsHandle ||
      !f->InitializeSecurityContextW || !f->DeleteSecurityContext ||
      !f->QueryContextAttributesW || !f->FreeContextBuffer ||
      !f->EncryptMessage || !f->DecryptMessage ||
      !f->EnumerateSecurityPackagesW)
    return NULL;
  return m;
}

static inline int fail_msg(const char *name, const char *msg) {
  printf("FAIL %s: %s (GetLastError=%lu)\n", name, msg,
         (unsigned long)GetLastError());
  return 1;
}

static inline int fail_status(const char *name, const char *what,
                              SECURITY_STATUS s) {
  char b[256];
  snprintf(b, sizeof(b), "%s returned 0x%08lx", what, (unsigned long)(ULONG)s);
  return fail_msg(name, b);
}

static inline int skip_msg(const char *name, const char *msg) {
  printf("SKIP %s: %s\n", name, msg);
  return 77;
}

static inline int pass_msg(const char *name) {
  printf("PASS %s\n", name);
  return 0;
}

/* True when the handle is not the SSPI "invalid" sentinel (~0/~0). */
static inline int cred_handle_valid(const CredHandle *h) {
  return !(h->dwLower == ~(ULONG_PTR)0 && h->dwUpper == ~(ULONG_PTR)0);
}

static inline int ctxt_handle_valid(const CtxtHandle *h) {
  return !(h->dwLower == ~(ULONG_PTR)0 && h->dwUpper == ~(ULONG_PTR)0);
}

/* AcquireCredentialsHandleW for outbound Schannel, as curl does for
   TLS 1.2 (lib/vtls/schannel.c:668-699). */
static inline SECURITY_STATUS acquire_client_cred(const sspi_fns *f,
                                                  CredHandle *cred) {
  SCHANNEL_CRED sc;
  TimeStamp exp;
  memset(&sc, 0, sizeof(sc));
  sc.dwVersion = SCHANNEL_CRED_VERSION;
  sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION |
               SCH_USE_STRONG_CRYPTO;
  sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
  return f->AcquireCredentialsHandleW(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND,
                                      NULL, &sc, NULL, NULL, cred, &exp);
}

/* InitializeSecurityContextW wrapper using curl's argument order
   (lib/vtls/schannel.c:998). have_ctx == 0 means the first call. */
static inline SECURITY_STATUS client_isc(const sspi_fns *f, CredHandle *cred,
                                         CtxtHandle *ctx, int have_ctx,
                                         const WCHAR *target, ULONG flags,
                                         PSecBufferDesc in, PSecBufferDesc out,
                                         ULONG *ret_flags) {
  TimeStamp exp;
  return f->InitializeSecurityContextW(
    cred, have_ctx ? ctx : NULL, (SEC_WCHAR *)target, flags, 0, 0, in, 0, ctx,
    out, ret_flags, &exp);
}

static inline void init_out_desc(SecBufferDesc *d, SecBuffer *b) {
  b->BufferType = SECBUFFER_TOKEN;
  b->cbBuffer = 0;
  b->pvBuffer = NULL;
  d->ulVersion = SECBUFFER_VERSION;
  d->cBuffers = 1;
  d->pBuffers = b;
}

/* Validates the first TLS record of a client flight (ClientHello). Returns NULL
   when the bytes are a consistent ClientHello record, else a reason string. */
static inline const char *check_client_hello(const unsigned char *b, ULONG n) {
  unsigned long rec_len, hs_len;
  if (n < 9)
    return "token shorter than record header plus handshake header";
  if (b[0] != 0x16)
    return "first byte is not TLS handshake content type 0x16";
  if (b[1] != 0x03)
    return "record major version is not 0x03";
  rec_len = ((unsigned long)b[3] << 8) | b[4];
  if (rec_len + 5 != n)
    return "record length field does not match token size";
  if (b[5] != 0x01)
    return "handshake type is not ClientHello (1)";
  hs_len = ((unsigned long)b[6] << 16) | ((unsigned long)b[7] << 8) | b[8];
  if (hs_len + 4 != rec_len)
    return "handshake length inconsistent with record length";
  return NULL;
}

static inline const unsigned char *find_bytes(const unsigned char *h, size_t hn,
                                              const unsigned char *nd,
                                              size_t nn) {
  size_t i;
  if (nn == 0 || hn < nn)
    return NULL;
  for (i = 0; i + nn <= hn; i++) {
    if (memcmp(h + i, nd, nn) == 0)
      return h + i;
  }
  return NULL;
}

int main(void) {
  sspi_fns f;
  HMODULE m;
  CredHandle cred;
  CtxtHandle ctx;
  SecBuffer ob;
  SecBufferDesc od;
  SecBuffer ib;
  SecBufferDesc id;
  SecBuffer ob2;
  SecBufferDesc od2;
  ULONG rf = 0;
  SECURITY_STATUS st;
  static unsigned char junk[] = { 0x99, 0x03, 0x03, 0x00, 0x02, 0xAB, 0xCD };

  memset(&f, 0, sizeof(f));
  m = load_sspi(&f);
  if (!m)
    return skip_msg(TEST_NAME, "secur32.dll SSPI exports unavailable");

  memset(&cred, 0, sizeof(cred));
  memset(&ctx, 0, sizeof(ctx));
  st = acquire_client_cred(&f, &cred);
  if (st != SEC_E_OK)
    return fail_status(TEST_NAME, "AcquireCredentialsHandleW", st);

  init_out_desc(&od, &ob);
  st = client_isc(&f, &cred, &ctx, 0, L"localhost", CURL_ISC_REQ_FLAGS, NULL, &od,
                  &rf);
  if (st != SEC_I_CONTINUE_NEEDED)
    return fail_status(TEST_NAME, "first InitializeSecurityContextW", st);
  if (f.FreeContextBuffer(ob.pvBuffer) != SEC_E_OK)
    return fail_msg(TEST_NAME, "FreeContextBuffer(first token) failed");

  ib.BufferType = SECBUFFER_TOKEN;
  ib.cbBuffer = (ULONG)sizeof(junk);
  ib.pvBuffer = junk;
  id.ulVersion = SECBUFFER_VERSION;
  id.cBuffers = 1;
  id.pBuffers = &ib;

  init_out_desc(&od2, &ob2);
  st = client_isc(&f, &cred, &ctx, 1, L"localhost", CURL_ISC_REQ_FLAGS, &id, &od2,
                  &rf);
  if (ob2.pvBuffer && f.FreeContextBuffer(ob2.pvBuffer) != SEC_E_OK)
    return fail_msg(TEST_NAME, "FreeContextBuffer(alert token) failed");

  if (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK)
    return fail_status(TEST_NAME,
                       "non-TLS server bytes were accepted by InitializeSecurityContextW",
                       st);
  if (st != SEC_E_ILLEGAL_MESSAGE && st != SEC_E_INVALID_TOKEN)
    return fail_status(TEST_NAME,
                       "non-TLS server bytes did not fail with ILLEGAL_MESSAGE/INVALID_TOKEN",
                       st);

  st = f.DeleteSecurityContext(&ctx);
  if (st != SEC_E_OK)
    return fail_status(TEST_NAME, "DeleteSecurityContext", st);
  st = f.FreeCredentialsHandle(&cred);
  if (st != SEC_E_OK)
    return fail_status(TEST_NAME, "FreeCredentialsHandle", st);

  return pass_msg(TEST_NAME);
}
