/*
 * schannel_19_record_layer_edge_cases
 *
 * Purpose: the DecryptMessage / EncryptMessage contract curl's receive loop
 * depends on (lib/vtls/schannel.c schannel_recv_decrypt: SEC_E_INCOMPLETE_MESSAGE
 * means "read more", SECBUFFER_EXTRA means "another record follows",
 * SEC_I_CONTEXT_EXPIRED means close_notify, anything else is a hard error), on a
 * real established TLS 1.2 session between two in-process Schannel contexts.
 *
 * Success (probed on Win10 22H2, std and adm identical):
 *   - a record cut after 3, 5 and n-1 bytes: SEC_E_INCOMPLETE_MESSAGE
 *     (0x80090318) with SECBUFFER_MISSING = 10, 8 and 1 (record header size 13
 *     minus the bytes present, then the bytes still missing);
 *   - the full record then decrypts;
 *   - two records back to back: the first decrypts with a SECBUFFER_EXTRA equal
 *     to the second record's size (35), which then decrypts;
 *   - an empty message encrypts to a 29 byte record (13 + 0 + 16);
 *   - a message of cbMaximumMessage (16384) bytes encrypts to 16413 bytes, and
 *     16385 bytes fail with SEC_E_ENCRYPT_FAILURE (0x80090329);
 *   - a bit flipped in a record: SEC_E_DECRYPT_FAILURE (0x80090330), and the
 *     context stays unusable (the next valid record also fails 0x80090330);
 *   - a replayed record fails with SEC_E_DECRYPT_FAILURE.
 */
#define TEST_NAME "schannel_19_record_layer_edge_cases"
/* ---- shared in-process Schannel client+server harness (generated into each test) ---- */
#define SECURITY_WIN32
#define ISSP_MODE 1
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <sspi.h>
#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>
#include <security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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
#ifndef SP_PROT_TLS1_3_CLIENT
#define SP_PROT_TLS1_3_SERVER 0x00001000
#define SP_PROT_TLS1_3_CLIENT 0x00002000
#endif
#ifndef SECPKG_ATTR_APPLICATION_PROTOCOL
#define SECPKG_ATTR_APPLICATION_PROTOCOL 35
#endif
#ifndef SCHANNEL_SHUTDOWN
#define SCHANNEL_SHUTDOWN 1
#endif

typedef struct H_t {
  HMODULE m;
  ACQUIRE_CREDENTIALS_HANDLE_FN_W Acq;
  FREE_CREDENTIALS_HANDLE_FN FreeCred;
  INITIALIZE_SECURITY_CONTEXT_FN_W ISC;
  ACCEPT_SECURITY_CONTEXT_FN ASC;
  DELETE_SECURITY_CONTEXT_FN Del;
  QUERY_CONTEXT_ATTRIBUTES_FN_W Query;
  FREE_CONTEXT_BUFFER_FN FreeBuf;
  ENCRYPT_MESSAGE_FN Enc;
  DECRYPT_MESSAGE_FN Dec;
  APPLY_CONTROL_TOKEN_FN Apply;
} H_t;
static __attribute__((unused)) H_t H;

static __attribute__((unused)) int load_h(void) {
  HMODULE m = LoadLibraryW(L"secur32.dll");
  if (!m) return 0;
  H.m = m;
  H.Acq = (ACQUIRE_CREDENTIALS_HANDLE_FN_W)(void *)GetProcAddress(m, "AcquireCredentialsHandleW");
  H.FreeCred = (FREE_CREDENTIALS_HANDLE_FN)(void *)GetProcAddress(m, "FreeCredentialsHandle");
  H.ISC = (INITIALIZE_SECURITY_CONTEXT_FN_W)(void *)GetProcAddress(m, "InitializeSecurityContextW");
  H.ASC = (ACCEPT_SECURITY_CONTEXT_FN)(void *)GetProcAddress(m, "AcceptSecurityContext");
  H.Del = (DELETE_SECURITY_CONTEXT_FN)(void *)GetProcAddress(m, "DeleteSecurityContext");
  H.Query = (QUERY_CONTEXT_ATTRIBUTES_FN_W)(void *)GetProcAddress(m, "QueryContextAttributesW");
  H.FreeBuf = (FREE_CONTEXT_BUFFER_FN)(void *)GetProcAddress(m, "FreeContextBuffer");
  H.Enc = (ENCRYPT_MESSAGE_FN)(void *)GetProcAddress(m, "EncryptMessage");
  H.Dec = (DECRYPT_MESSAGE_FN)(void *)GetProcAddress(m, "DecryptMessage");
  H.Apply = (APPLY_CONTROL_TOKEN_FN)(void *)GetProcAddress(m, "ApplyControlToken");
  return H.Acq && H.FreeCred && H.ISC && H.ASC && H.Del && H.Query && H.FreeBuf && H.Enc && H.Dec && H.Apply;
}

/* ---- growable byte queue ---- */
typedef struct { unsigned char *p; size_t n, cap; } bq;
static __attribute__((unused)) void bq_add(bq *q, const void *d, size_t n) {
  if (q->n + n > q->cap) {
    q->cap = (q->n + n) * 2 + 64;
    q->p = (unsigned char *)realloc(q->p, q->cap);
  }
  memcpy(q->p + q->n, d, n);
  q->n += n;
}
static __attribute__((unused)) void bq_drop(bq *q, size_t n) {
  if (n >= q->n) { q->n = 0; return; }
  memmove(q->p, q->p + n, q->n - n);
  q->n -= n;
}

/* ---- self-signed server certificate with a private key in a temporary CAPI container ---- */
typedef struct {
  HCRYPTPROV prov;
  WCHAR container[64];
  PCCERT_CONTEXT cert;
} servercert;

static __attribute__((unused)) int make_cert2(servercert *sc, const WCHAR *cn, const WCHAR *dns_san, SYSTEMTIME *nb_t, SYSTEMTIME *na_t) {
  CRYPT_KEY_PROV_INFO kpi;
  CRYPT_ALGORITHM_IDENTIFIER alg;
  CERT_NAME_BLOB nb;
  CERT_EXTENSIONS exts;
  CERT_EXTENSION ext;
  CERT_ALT_NAME_ENTRY ane;
  CERT_ALT_NAME_INFO ani;
  DWORD n = 0;
  HCRYPTKEY key = 0;
  BYTE *san = NULL;
  WCHAR dn[128];

  memset(sc, 0, sizeof(*sc));
  swprintf(sc->container, 64, L"i7curl-%lu-%lu", (unsigned long)GetCurrentProcessId(),
           (unsigned long)GetTickCount());
  CryptAcquireContextW(&sc->prov, sc->container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
  sc->prov = 0;
  if (!CryptAcquireContextW(&sc->prov, sc->container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET))
    return 0;
  if (!CryptGenKey(sc->prov, AT_KEYEXCHANGE, (2048u << 16) | CRYPT_EXPORTABLE, &key))
    return 0;
  CryptDestroyKey(key);
  swprintf(dn, 128, L"CN=%ls", cn);
  memset(&nb, 0, sizeof(nb));
  if (!CertStrToNameW(X509_ASN_ENCODING, dn, CERT_X500_NAME_STR, NULL, NULL, &n, NULL))
    return 0;
  nb.pbData = (BYTE *)malloc(n);
  nb.cbData = n;
  if (!CertStrToNameW(X509_ASN_ENCODING, dn, CERT_X500_NAME_STR, NULL, nb.pbData, &n, NULL))
    return 0;
  memset(&exts, 0, sizeof(exts));
  if (dns_san) {
    memset(&ane, 0, sizeof(ane));
    ane.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
    ane.pwszDNSName = (LPWSTR)dns_san;
    ani.cAltEntry = 1;
    ani.rgAltEntry = &ane;
    n = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, szOID_SUBJECT_ALT_NAME2, &ani, CRYPT_ENCODE_ALLOC_FLAG, NULL, &san, &n))
      return 0;
    memset(&ext, 0, sizeof(ext));
    ext.pszObjId = (LPSTR)szOID_SUBJECT_ALT_NAME2;
    ext.fCritical = FALSE;
    ext.Value.cbData = n;
    ext.Value.pbData = san;
    exts.cExtension = 1;
    exts.rgExtension = &ext;
  }
  memset(&kpi, 0, sizeof(kpi));
  kpi.pwszContainerName = sc->container;
  kpi.pwszProvName = (LPWSTR)MS_ENH_RSA_AES_PROV_W;
  kpi.dwProvType = PROV_RSA_AES;
  kpi.dwKeySpec = AT_KEYEXCHANGE;
  memset(&alg, 0, sizeof(alg));
  alg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
  sc->cert = CertCreateSelfSignCertificate(sc->prov, &nb, 0, &kpi, &alg, nb_t, na_t, dns_san ? &exts : NULL);
  free(nb.pbData);
  if (san) LocalFree(san);
  return sc->cert != NULL;
}

static __attribute__((unused)) int make_cert(servercert *sc, const WCHAR *cn, const WCHAR *dns_san) {
  return make_cert2(sc, cn, dns_san, NULL, NULL);
}

static __attribute__((unused)) void free_cert(servercert *sc) {
  if (sc->cert) CertFreeCertificateContext(sc->cert);
  if (sc->prov) CryptReleaseContext(sc->prov, 0);
  {
    HCRYPTPROV p = 0;
    CryptAcquireContextW(&p, sc->container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
  }
  memset(sc, 0, sizeof(*sc));
}

/* ---- credentials ---- */
/* v4 SCHANNEL_CRED client, optional manual validation. */
static __attribute__((unused)) SECURITY_STATUS cred_client_v4(CredHandle *c, DWORD protos, DWORD flags) {
  SCHANNEL_CRED sc;
  TimeStamp exp;
  memset(&sc, 0, sizeof(sc));
  sc.dwVersion = SCHANNEL_CRED_VERSION;
  sc.dwFlags = flags;
  sc.grbitEnabledProtocols = protos;
  return H.Acq(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &sc, NULL, NULL, c, &exp);
}
static __attribute__((unused)) SECURITY_STATUS cred_server_v4(CredHandle *c, PCCERT_CONTEXT cert, DWORD protos) {
  SCHANNEL_CRED sc;
  TimeStamp exp;
  memset(&sc, 0, sizeof(sc));
  sc.dwVersion = SCHANNEL_CRED_VERSION;
  sc.cCreds = 1;
  sc.paCred = &cert;
  sc.grbitEnabledProtocols = protos;
  sc.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;
  return H.Acq(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_INBOUND, NULL, &sc, NULL, NULL, c, &exp);
}
/* v5 SCH_CREDENTIALS; enabled = SP_PROT_* bitmask of ENABLED protocols (as curl). */
static __attribute__((unused)) SECURITY_STATUS cred_v5(CredHandle *c, int server, PCCERT_CONTEXT cert, DWORD enabled, DWORD flags) {
  SCH_CREDENTIALS sc;
  TLS_PARAMETERS tp;
  TimeStamp exp;
  memset(&sc, 0, sizeof(sc));
  memset(&tp, 0, sizeof(tp));
  tp.grbitDisabledProtocols = (DWORD)~enabled;
  sc.dwVersion = SCH_CREDENTIALS_VERSION;
  sc.dwFlags = flags;
  sc.cTlsParameters = 1;
  sc.pTlsParameters = &tp;
  if (server) {
    sc.cCreds = 1;
    sc.paCred = &cert;
  }
  return H.Acq(NULL, (SEC_WCHAR *)UNISP_NAME_W, server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, NULL, &sc, NULL,
               NULL, c, &exp);
}

/* Build a SEC_APPLICATION_PROTOCOLS blob holding one ALPN list. protos is the wire list
   (length-prefixed names). Returns total byte length written to out (>= 12 + n). */
static __attribute__((unused)) ULONG build_alpn(unsigned char *out, const unsigned char *protos, unsigned short n) {
  /* layout: ULONG ProtocolListsSize; { ULONG ProtoNegoExt; USHORT ProtocolListSize; BYTE list[n] } */
  ULONG lists = 4 + 2 + n;
  ULONG ext = SecApplicationProtocolNegotiationExt_ALPN;
  memcpy(out, &lists, 4);
  memcpy(out + 4, &ext, 4);
  memcpy(out + 8, &n, 2);
  memcpy(out + 10, protos, n);
  return 4 + lists;
}

/* ---- handshake pump ---- */
typedef struct {
  CredHandle ccred, scred;
  CtxtHandle cctx, sctx;
  int have_c, have_s;
  bq c2s, s2c;               /* bytes in flight */
  SECURITY_STATUS cst, sst;  /* last statuses */
  int cdone, sdone;
  const WCHAR *target;
  ULONG creq, sreq;
  unsigned char *alpn;       /* client ALPN buffer (SEC_APPLICATION_PROTOCOLS blob), or NULL */
  ULONG alpn_len;
  unsigned char *salpn;      /* server ALPN buffer, or NULL */
  ULONG salpn_len;
  int log;
  char trace[512];
  char seq[512];
  size_t cchunk, schunk;     /* 0 = offer everything; else offer at most this many more bytes per step */
  size_t coff, soff;         /* bytes already offered (after SEC_E_INCOMPLETE_MESSAGE) */
  int cincomplete, sincomplete;
  int cinc_total, sinc_total; /* number of SEC_E_INCOMPLETE_MESSAGE results seen */
} hs;

static __attribute__((unused)) void hs_trace(hs *h, const char *who, SECURITY_STATUS st, size_t out) {
  size_t l = strlen(h->trace);
  size_t l2 = strlen(h->seq);
  if (l < sizeof(h->trace) - 40)
    snprintf(h->trace + l, sizeof(h->trace) - l, "%s=0x%08lx/%lu ", who, (unsigned long)(ULONG)st, (unsigned long)out);
  if (l2 < sizeof(h->seq) - 20 && st != SEC_E_INCOMPLETE_MESSAGE)
    snprintf(h->seq + l2, sizeof(h->seq) - l2, "%s=0x%08lx ", who, (unsigned long)(ULONG)st);
}

/* One client InitializeSecurityContext step consuming s2c. Returns status. */
static __attribute__((unused)) SECURITY_STATUS client_step(hs *h) {
  SecBuffer ib[3], ob[2];
  SecBufferDesc id, od;
  ULONG rf = 0;
  TimeStamp exp;
  int first = !h->have_c;
  SECURITY_STATUS st;
  size_t outn = 0;
  size_t offer = h->s2c.n;
  if (h->cchunk && offer > h->coff + h->cchunk) offer = h->coff + h->cchunk;
  ib[0].BufferType = SECBUFFER_TOKEN;
  ib[0].pvBuffer = h->s2c.p;
  ib[0].cbBuffer = (ULONG)offer;
  ib[1].BufferType = SECBUFFER_EMPTY; ib[1].pvBuffer = NULL; ib[1].cbBuffer = 0;
  ib[2].BufferType = SECBUFFER_EMPTY; ib[2].pvBuffer = NULL; ib[2].cbBuffer = 0;
  id.ulVersion = SECBUFFER_VERSION; id.cBuffers = 3; id.pBuffers = ib;
  ob[0].BufferType = SECBUFFER_TOKEN; ob[0].pvBuffer = NULL; ob[0].cbBuffer = 0;
  ob[1].BufferType = SECBUFFER_ALERT; ob[1].pvBuffer = NULL; ob[1].cbBuffer = 0;
  od.ulVersion = SECBUFFER_VERSION; od.cBuffers = 2; od.pBuffers = ob;
  if (first && h->alpn) {
    ib[0].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
    ib[0].pvBuffer = h->alpn;
    ib[0].cbBuffer = h->alpn_len;
    id.cBuffers = 1;
  }
  st = H.ISC(&h->ccred, first ? NULL : &h->cctx, (SEC_WCHAR *)h->target, h->creq, 0, 0,
             (first && !h->alpn) ? NULL : &id, 0, &h->cctx, &od, &rf, &exp);
  h->have_c = 1;
  if (ob[0].pvBuffer) {
    if (ob[0].cbBuffer) { bq_add(&h->c2s, ob[0].pvBuffer, ob[0].cbBuffer); outn = ob[0].cbBuffer; }
    H.FreeBuf(ob[0].pvBuffer);
  }
  if (ob[1].pvBuffer) H.FreeBuf(ob[1].pvBuffer);
  h->cincomplete = (st == SEC_E_INCOMPLETE_MESSAGE);
  h->cinc_total += h->cincomplete;
  if (!first && st != SEC_E_INCOMPLETE_MESSAGE) {
    /* consumed input: drop everything offered except SECBUFFER_EXTRA */
    if (ib[1].BufferType == SECBUFFER_EXTRA) bq_drop(&h->s2c, offer - ib[1].cbBuffer);
    else bq_drop(&h->s2c, offer);
    h->coff = 0;
  } else if (!first) {
    h->coff = offer;
  }
  hs_trace(h, "C", st, outn);
  h->cst = st;
  if (st == SEC_E_OK) h->cdone = 1;
  return st;
}

static __attribute__((unused)) SECURITY_STATUS server_step(hs *h) {
  SecBuffer ib[2], ob[2];
  SecBufferDesc id, od;
  ULONG rf = 0;
  TimeStamp exp;
  int first = !h->have_s;
  SECURITY_STATUS st;
  size_t outn = 0;
  size_t offer = h->c2s.n;
  if (h->schunk && offer > h->soff + h->schunk) offer = h->soff + h->schunk;
  ib[0].BufferType = SECBUFFER_TOKEN; ib[0].pvBuffer = h->c2s.p; ib[0].cbBuffer = (ULONG)offer;
  ib[1].BufferType = SECBUFFER_EMPTY; ib[1].pvBuffer = NULL; ib[1].cbBuffer = 0;
  id.ulVersion = SECBUFFER_VERSION; id.cBuffers = 2; id.pBuffers = ib;
  if (first && h->salpn) {
    ib[1].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
    ib[1].pvBuffer = h->salpn;
    ib[1].cbBuffer = h->salpn_len;
  }
  ob[0].BufferType = SECBUFFER_TOKEN; ob[0].pvBuffer = NULL; ob[0].cbBuffer = 0;
  ob[1].BufferType = SECBUFFER_ALERT; ob[1].pvBuffer = NULL; ob[1].cbBuffer = 0;
  od.ulVersion = SECBUFFER_VERSION; od.cBuffers = 2; od.pBuffers = ob;
  st = H.ASC(&h->scred, first ? NULL : &h->sctx, &id, h->sreq, 0, &h->sctx, &od, &rf, &exp);
  if (!(first && st == SEC_E_INCOMPLETE_MESSAGE)) h->have_s = 1; /* no context exists yet after an incomplete first call */
  if (ob[0].pvBuffer) {
    if (ob[0].cbBuffer) { bq_add(&h->s2c, ob[0].pvBuffer, ob[0].cbBuffer); outn = ob[0].cbBuffer; }
    H.FreeBuf(ob[0].pvBuffer);
  }
  if (ob[1].pvBuffer) H.FreeBuf(ob[1].pvBuffer);
  h->sincomplete = (st == SEC_E_INCOMPLETE_MESSAGE);
  h->sinc_total += h->sincomplete;
  if (st != SEC_E_INCOMPLETE_MESSAGE) {
    if (ib[1].BufferType == SECBUFFER_EXTRA) bq_drop(&h->c2s, offer - ib[1].cbBuffer);
    else bq_drop(&h->c2s, offer);
    h->soff = 0;
  } else {
    h->soff = offer;
  }
  hs_trace(h, "S", st, outn);
  h->sst = st;
  if (st == SEC_E_OK) h->sdone = 1;
  return st;
}

static __attribute__((unused)) int is_hs_continue(SECURITY_STATUS st) {
  return st == SEC_I_CONTINUE_NEEDED || st == SEC_E_INCOMPLETE_MESSAGE || st == SEC_I_INCOMPLETE_CREDENTIALS;
}

/* Run both sides to completion. Returns 0 when both reached SEC_E_OK, else the first
   non-continue failing status (client first), stored in *bad (and which side in *side). */
static __attribute__((unused)) int hs_run(hs *h, SECURITY_STATUS *bad, char *side) {
  int i;
  for (i = 0; i < 40000; i++) {
    int progressed = 0;
    if (!h->cdone && (!h->have_c || h->s2c.n > (h->cincomplete ? h->coff : 0))) {
      SECURITY_STATUS st = client_step(h);
      if (st != SEC_E_OK && !is_hs_continue(st)) { *bad = st; *side = 'C'; return 1; }
      if (!(st == SEC_E_INCOMPLETE_MESSAGE && h->coff >= h->s2c.n)) progressed = 1;
    }
    if (!h->sdone && h->c2s.n > (h->sincomplete ? h->soff : 0)) {
      SECURITY_STATUS st = server_step(h);
      if (st != SEC_E_OK && !is_hs_continue(st)) { *bad = st; *side = 'S'; return 1; }
      if (!(st == SEC_E_INCOMPLETE_MESSAGE && h->soff >= h->c2s.n)) progressed = 1;
    }
    if (h->cdone && h->sdone) return 0;
    if (!progressed) break;
  }
  *bad = h->cst; *side = '?';
  return 2;
}

static __attribute__((unused)) void hs_init(hs *h) {
  memset(h, 0, sizeof(*h));
  h->creq = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
            ISC_REQ_STREAM;
  h->sreq = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_ALLOCATE_MEMORY |
            ASC_REQ_STREAM;
  h->target = L"localhost";
}

static __attribute__((unused)) void hs_free(hs *h) {
  if (h->have_c) H.Del(&h->cctx);
  if (h->have_s) H.Del(&h->sctx);
  H.FreeCred(&h->ccred);
  H.FreeCred(&h->scred);
  free(h->c2s.p);
  free(h->s2c.p);
}

/* ---- record layer helpers ---- */
/* Encrypt msg with ctx; appends the record to out. Returns status. */
static __attribute__((unused)) SECURITY_STATUS enc_msg(CtxtHandle *ctx, const void *msg, ULONG n, bq *out) {
  SecPkgContext_StreamSizes ss;
  SecBuffer b[4];
  SecBufferDesc d;
  SECURITY_STATUS st;
  unsigned char *buf;
  st = H.Query(ctx, SECPKG_ATTR_STREAM_SIZES, &ss);
  if (st != SEC_E_OK) return st;
  buf = (unsigned char *)malloc(ss.cbHeader + n + ss.cbTrailer);
  memcpy(buf + ss.cbHeader, msg, n);
  b[0].BufferType = SECBUFFER_STREAM_HEADER; b[0].pvBuffer = buf; b[0].cbBuffer = ss.cbHeader;
  b[1].BufferType = SECBUFFER_DATA; b[1].pvBuffer = buf + ss.cbHeader; b[1].cbBuffer = n;
  b[2].BufferType = SECBUFFER_STREAM_TRAILER; b[2].pvBuffer = buf + ss.cbHeader + n; b[2].cbBuffer = ss.cbTrailer;
  b[3].BufferType = SECBUFFER_EMPTY; b[3].pvBuffer = NULL; b[3].cbBuffer = 0;
  d.ulVersion = SECBUFFER_VERSION; d.cBuffers = 4; d.pBuffers = b;
  st = H.Enc(ctx, 0, &d, 0);
  if (st == SEC_E_OK) bq_add(out, buf, b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer);
  free(buf);
  return st;
}

/* Decrypt first record in q. On success pt and ptn point inside q->p (valid until q modified) and *extra is
   the number of bytes not consumed. */
static __attribute__((unused)) SECURITY_STATUS dec_msg(CtxtHandle *ctx, bq *q, unsigned char **pt, ULONG *ptn, ULONG *extra, ULONG *need) {
  SecBuffer b[4];
  SecBufferDesc d;
  SECURITY_STATUS st;
  int i;
  b[0].BufferType = SECBUFFER_DATA; b[0].pvBuffer = q->p; b[0].cbBuffer = (ULONG)q->n;
  for (i = 1; i < 4; i++) { b[i].BufferType = SECBUFFER_EMPTY; b[i].pvBuffer = NULL; b[i].cbBuffer = 0; }
  d.ulVersion = SECBUFFER_VERSION; d.cBuffers = 4; d.pBuffers = b;
  st = H.Dec(ctx, &d, 0, NULL);
  *pt = NULL; *ptn = 0; *extra = 0; *need = 0;
  for (i = 0; i < 4; i++) {
    if (b[i].BufferType == SECBUFFER_DATA && st == SEC_E_OK) { *pt = (unsigned char *)b[i].pvBuffer; *ptn = b[i].cbBuffer; }
    if (b[i].BufferType == SECBUFFER_EXTRA) *extra = b[i].cbBuffer;
    if (b[i].BufferType == SECBUFFER_MISSING) *need = b[i].cbBuffer;
  }
  return st;
}

static __attribute__((unused)) int bad(const char *name, const char *msg) {
  printf("FAIL %s: %s (GetLastError=%lu)\n", name, msg, (unsigned long)GetLastError());
  return 1;
}
static __attribute__((unused)) int badst(const char *name, const char *what, SECURITY_STATUS st) {
  printf("FAIL %s: %s = 0x%08lx\n", name, what, (unsigned long)(ULONG)st);
  return 1;
}

/* Exact status codes (probed on Win10 22H2) as signed SECURITY_STATUS values. */
#define X_INVALID_HANDLE ((SECURITY_STATUS)0x80090301u)
#define X_NO_CREDENTIALS ((SECURITY_STATUS)0x8009030eu)
#define X_INCOMPLETE_MESSAGE ((SECURITY_STATUS)0x80090318u)
#define X_UNTRUSTED_ROOT ((SECURITY_STATUS)0x80090325u)
#define X_ALGORITHM_MISMATCH ((SECURITY_STATUS)0x80090331u)
#define X_DECRYPT_FAILURE ((SECURITY_STATUS)0x80090330u)
#define X_ENCRYPT_FAILURE ((SECURITY_STATUS)0x80090329u)
#define X_NO_APPLICATION_PROTOCOL ((SECURITY_STATUS)0x80090367u)
#define X_CONTINUE_NEEDED ((SECURITY_STATUS)0x00090312)
#define X_CONTEXT_EXPIRED ((SECURITY_STATUS)0x00090317)

#define CHECK(c, m) do { if (!(c)) { printf("FAIL %s: %s\n", TEST_NAME, (m)); return 1; } } while (0)
#define CHECKST(c, what, st) do { if (!(c)) return badst(TEST_NAME, (what), (st)); } while (0)
#define MANUAL_FLAGS (SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION)


static servercert SC;

static int session(hs *h) {
  SECURITY_STATUS st, bd = 0;
  char side;
  hs_init(h);
  st = cred_client_v4(&h->ccred, SP_PROT_TLS1_2_CLIENT, MANUAL_FLAGS);
  CHECKST(st == SEC_E_OK, "client cred", st);
  st = cred_server_v4(&h->scred, SC.cert, SP_PROT_TLS1_2_SERVER);
  CHECKST(st == SEC_E_OK, "server cred", st);
  if (hs_run(h, &bd, &side) != 0) return badst(TEST_NAME, "handshake", bd);
  return 0;
}

static int partial(hs *h, const bq *rec, size_t cut, ULONG want_missing) {
  bq r;
  unsigned char *pt;
  ULONG n, ex, need;
  SECURITY_STATUS st;
  memset(&r, 0, sizeof(r));
  bq_add(&r, rec->p, cut);
  st = dec_msg(&h->sctx, &r, &pt, &n, &ex, &need);
  if (st != X_INCOMPLETE_MESSAGE || need != want_missing) {
    printf("FAIL %s: %lu of %lu bytes: status 0x%08lx missing=%lu, expected 0x80090318 / %lu\n", TEST_NAME, (unsigned long)cut, (unsigned long)rec->n,
           (unsigned long)(ULONG)st, (unsigned long)need, (unsigned long)want_missing);
    return 1;
  }
  free(r.p);
  return 0;
}

int main(void) {
  hs h;
  bq w, r, w2;
  unsigned char *pt;
  ULONG n, ex, need;
  SECURITY_STATUS st;
  unsigned char *big;
  if (!load_h()) {
    printf("SKIP %s: secur32.dll SSPI exports unavailable\n", TEST_NAME);
    return 77;
  }
  if (!make_cert(&SC, L"localhost", L"localhost"))
    return bad(TEST_NAME, "creating the self-signed server certificate failed");

  /* partial and multi-record */
  if (session(&h)) return 1;
  memset(&w, 0, sizeof(w));
  st = enc_msg(&h.cctx, "abcdefghij", 10, &w);
  CHECKST(st == SEC_E_OK && w.n == 39, "EncryptMessage(10 bytes) is not a 39 byte record", st);
  if (partial(&h, &w, 3, 10) || partial(&h, &w, 5, 8) || partial(&h, &w, w.n - 1, 1)) return 1;
  memset(&r, 0, sizeof(r));
  bq_add(&r, w.p, w.n);
  st = dec_msg(&h.sctx, &r, &pt, &n, &ex, &need);
  CHECKST(st == SEC_E_OK, "full record after the partial attempts", st);
  CHECK(n == 10 && memcmp(pt, "abcdefghij", 10) == 0, "payload differs after partial attempts");

  memset(&w2, 0, sizeof(w2));
  enc_msg(&h.cctx, "one", 3, &w2);
  enc_msg(&h.cctx, "twotwo", 6, &w2);
  CHECK(w2.n == (13 + 3 + 16) + (13 + 6 + 16), "two record sizes");
  memset(&r, 0, sizeof(r));
  bq_add(&r, w2.p, w2.n);
  st = dec_msg(&h.sctx, &r, &pt, &n, &ex, &need);
  CHECKST(st == SEC_E_OK && n == 3 && memcmp(pt, "one", 3) == 0, "first of two records", st);
  CHECK(ex == 35, "SECBUFFER_EXTRA after the first record is not the second record (35 bytes)");
  bq_drop(&r, r.n - ex);
  st = dec_msg(&h.sctx, &r, &pt, &n, &ex, &need);
  CHECKST(st == SEC_E_OK && n == 6 && ex == 0 && memcmp(pt, "twotwo", 6) == 0, "second record", st);

  memset(&w, 0, sizeof(w));
  st = enc_msg(&h.cctx, "", 0, &w);
  CHECKST(st == SEC_E_OK && w.n == 29, "empty message encrypts to 29 bytes", st);
  big = (unsigned char *)calloc(1, 16385);
  memset(&w, 0, sizeof(w));
  st = enc_msg(&h.cctx, big, 16384, &w);
  CHECKST(st == SEC_E_OK && w.n == 16413, "maximum message (16384) encrypts to 16413 bytes", st);
  memset(&w, 0, sizeof(w));
  st = enc_msg(&h.cctx, big, 16385, &w);
  CHECKST(st == X_ENCRYPT_FAILURE, "EncryptMessage(16385 bytes) is SEC_E_ENCRYPT_FAILURE", st);
  free(big);
  hs_free(&h);

  /* tampered record */
  if (session(&h)) return 1;
  memset(&w, 0, sizeof(w));
  enc_msg(&h.cctx, "tamper", 6, &w);
  w.p[w.n / 2] ^= 0x40;
  st = dec_msg(&h.sctx, &w, &pt, &n, &ex, &need);
  CHECKST(st == X_DECRYPT_FAILURE, "tampered record is SEC_E_DECRYPT_FAILURE", st);
  memset(&w, 0, sizeof(w));
  enc_msg(&h.cctx, "after", 5, &w);
  st = dec_msg(&h.sctx, &w, &pt, &n, &ex, &need);
  CHECKST(st == X_DECRYPT_FAILURE, "valid record after a tampered one still fails 0x80090330", st);
  hs_free(&h);

  /* replay */
  if (session(&h)) return 1;
  memset(&w, 0, sizeof(w));
  enc_msg(&h.cctx, "replay", 6, &w);
  memset(&r, 0, sizeof(r));
  bq_add(&r, w.p, w.n);
  memset(&w2, 0, sizeof(w2));
  bq_add(&w2, w.p, w.n);
  st = dec_msg(&h.sctx, &r, &pt, &n, &ex, &need);
  CHECKST(st == SEC_E_OK, "first delivery of a record", st);
  st = dec_msg(&h.sctx, &w2, &pt, &n, &ex, &need);
  CHECKST(st == X_DECRYPT_FAILURE, "replayed record is SEC_E_DECRYPT_FAILURE", st);
  hs_free(&h);

  free_cert(&SC);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
