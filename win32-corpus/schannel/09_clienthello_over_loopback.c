/*
 * schannel_09_clienthello_over_loopback
 *
 * Purpose: Send the Schannel ClientHello token over a real TCP connection on
 * 127.0.0.1, the way curl's send path does (Curl_conn_cf_send of
 * outbuf.pvBuffer with outbuf.cbBuffer, then FreeContextBuffer). A listening
 * socket plays the server: it reads the TLS record header, reads exactly the
 * number of bytes the header announces, and checks that the bytes arriving on
 * the wire are identical to the token Schannel produced.
 *
 * APIs: LoadLibraryW(secur32.dll), GetProcAddress, AcquireCredentialsHandleW,
 *       InitializeSecurityContextW, FreeContextBuffer, DeleteSecurityContext,
 *       FreeCredentialsHandle, WSAStartup, socket, bind, listen,
 *       getsockname, connect, accept, send, recv, closesocket, WSACleanup.
 *
 * Success: connect succeeds on loopback, send transmits all cbBuffer bytes,
 *   the reader receives a record whose length field matches the byte count and
 *   the bytes are identical to the token, and all SSPI cleanup returns SEC_E_OK.
 * SKIP: the loopback interface or socket support is absent: socket() failing
 *   with WSAENETDOWN, WSAEAFNOSUPPORT or WSAEPROTONOSUPPORT, or bind() failing
 *   with WSAEADDRNOTAVAIL or WSAENETDOWN.
 *
 * Source reference: lib/vtls/schannel.c:1040-1048 (send of the initial token
 *   with Curl_conn_cf_send, FreeContextBuffer, short-write check).
 */
#define TEST_NAME "schannel_09_clienthello_over_loopback"
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

static int send_all(SOCKET s, const unsigned char *p, int n) {
  while (n > 0) {
    int w = send(s, (const char *)p, n, 0);
    if (w == SOCKET_ERROR)
      return -1;
    p += w;
    n -= w;
  }
  return 0;
}

static int recv_exact(SOCKET s, unsigned char *p, int n) {
  while (n > 0) {
    int r = recv(s, (char *)p, n, 0);
    if (r <= 0)
      return -1;
    p += r;
    n -= r;
  }
  return 0;
}

int main(void) {
  sspi_fns f;
  HMODULE m;
  WSADATA wsa;
  SOCKET ls = INVALID_SOCKET;
  SOCKET cs = INVALID_SOCKET;
  SOCKET as = INVALID_SOCKET;
  struct sockaddr_in sa;
  int salen = (int)sizeof(sa);
  unsigned short port;
  CredHandle cred;
  CtxtHandle ctx;
  SecBuffer ob;
  SecBufferDesc od;
  ULONG rf = 0;
  SECURITY_STATUS st;
  unsigned char hdr[5];
  unsigned char *rx = NULL;
  unsigned long rec_len;
  int wsa_rc;
  int rc = 1;
  const char *why;
  int wsa_started = 0;

  memset(&f, 0, sizeof(f));
  m = load_sspi(&f);
  if (!m)
    return skip_msg(TEST_NAME, "secur32.dll SSPI exports unavailable");

  wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa);
  if (wsa_rc != 0)
    return fail_msg(TEST_NAME, "WSAStartup failed");
  wsa_started = 1;

  memset(&cred, 0, sizeof(cred));
  memset(&ctx, 0, sizeof(ctx));
  st = acquire_client_cred(&f, &cred);
  if (st != SEC_E_OK) {
    rc = fail_status(TEST_NAME, "AcquireCredentialsHandleW", st);
    goto out;
  }

  init_out_desc(&od, &ob);
  st = client_isc(&f, &cred, &ctx, 0, L"localhost", CURL_ISC_REQ_FLAGS, NULL, &od,
                  &rf);
  if (st != SEC_I_CONTINUE_NEEDED) {
    rc = fail_status(TEST_NAME, "InitializeSecurityContextW", st);
    goto out_cred;
  }
  why = check_client_hello((const unsigned char *)ob.pvBuffer, ob.cbBuffer);
  if (why) {
    rc = fail_msg(TEST_NAME, why);
    goto out_tok;
  }

  ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ls == INVALID_SOCKET) {
    int e = WSAGetLastError();
    if (e == WSAENETDOWN || e == WSAEAFNOSUPPORT || e == WSAEPROTONOSUPPORT) {
      rc = skip_msg(TEST_NAME, "no IPv4 socket support");
    } else {
      char b[128];
      snprintf(b, sizeof(b), "socket() failed, WSAGetLastError=%d", e);
      rc = fail_msg(TEST_NAME, b);
    }
    goto out_tok;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;
  if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
    int e = WSAGetLastError();
    if (e == WSAEADDRNOTAVAIL || e == WSAENETDOWN) {
      rc = skip_msg(TEST_NAME, "loopback address not available");
    } else {
      char b[128];
      snprintf(b, sizeof(b), "bind(127.0.0.1:0) failed, WSAGetLastError=%d", e);
      rc = fail_msg(TEST_NAME, b);
    }
    goto out_tok;
  }
  if (listen(ls, 1) == SOCKET_ERROR) {
    rc = fail_msg(TEST_NAME, "listen failed");
    goto out_tok;
  }
  if (getsockname(ls, (struct sockaddr *)&sa, &salen) == SOCKET_ERROR) {
    rc = fail_msg(TEST_NAME, "getsockname failed");
    goto out_tok;
  }
  port = ntohs(sa.sin_port);
  if (port == 0) {
    rc = fail_msg(TEST_NAME, "getsockname returned port 0");
    goto out_tok;
  }

  cs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (cs == INVALID_SOCKET) {
    rc = fail_msg(TEST_NAME, "client socket() failed");
    goto out_tok;
  }
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(port);
  if (connect(cs, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
    char b[128];
    snprintf(b, sizeof(b), "connect to loopback failed, WSAGetLastError=%d",
             WSAGetLastError());
    rc = fail_msg(TEST_NAME, b);
    goto out_tok;
  }
  as = accept(ls, NULL, NULL);
  if (as == INVALID_SOCKET) {
    rc = fail_msg(TEST_NAME, "accept failed");
    goto out_tok;
  }

  /* curl sends the whole initial token with the connected socket. */
  if (send_all(cs, (const unsigned char *)ob.pvBuffer, (int)ob.cbBuffer) != 0) {
    char b[128];
    snprintf(b, sizeof(b), "send of ClientHello failed, WSAGetLastError=%d",
             WSAGetLastError());
    rc = fail_msg(TEST_NAME, b);
    goto out_tok;
  }

  if (recv_exact(as, hdr, 5) != 0) {
    rc = fail_msg(TEST_NAME, "server could not read TLS record header");
    goto out_tok;
  }
  rec_len = ((unsigned long)hdr[3] << 8) | hdr[4];
  if (rec_len + 5 != ob.cbBuffer) {
    rc = fail_msg(TEST_NAME, "record length on the wire does not match cbBuffer");
    goto out_tok;
  }
  rx = (unsigned char *)malloc(ob.cbBuffer);
  if (!rx) {
    rc = fail_msg(TEST_NAME, "malloc failed");
    goto out_tok;
  }
  memcpy(rx, hdr, 5);
  if (recv_exact(as, rx + 5, (int)rec_len) != 0) {
    rc = fail_msg(TEST_NAME, "server could not read full ClientHello body");
    goto out_tok;
  }
  if (memcmp(rx, ob.pvBuffer, ob.cbBuffer) != 0) {
    rc = fail_msg(TEST_NAME, "bytes received differ from the Schannel token");
    goto out_tok;
  }

  rc = 0;
  /* falls through to cleanup */
out_tok:
  if (rx)
    free(rx);
  if (as != INVALID_SOCKET)
    closesocket(as);
  if (cs != INVALID_SOCKET)
    closesocket(cs);
  if (ls != INVALID_SOCKET)
    closesocket(ls);
  if (ob.pvBuffer) {
    st = f.FreeContextBuffer(ob.pvBuffer);
    if (rc == 0 && st != SEC_E_OK)
      rc = fail_status(TEST_NAME, "FreeContextBuffer", st);
  }
  st = f.DeleteSecurityContext(&ctx);
  if (rc == 0 && st != SEC_E_OK)
    rc = fail_status(TEST_NAME, "DeleteSecurityContext", st);
out_cred:
  st = f.FreeCredentialsHandle(&cred);
  if (rc == 0 && st != SEC_E_OK)
    rc = fail_status(TEST_NAME, "FreeCredentialsHandle", st);
out:
  if (wsa_started)
    WSACleanup();
  if (rc == 0)
    return pass_msg(TEST_NAME);
  return rc;
}
