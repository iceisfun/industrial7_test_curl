/*
 * schannel_23_cert_names_der_pem
 *
 * Purpose: the certificate parsing helpers curl's Schannel backend relies on:
 * PEM bundle decoding with CryptStringToBinaryA (lib/vtls/schannel_verify.c
 * add_certs_data_to_store), CertCreateCertificateContext on the DER,
 * CertFindExtension(szOID_SUBJECT_ALT_NAME2) + CryptDecodeObjectEx(X509_ALTERNATE_NAME)
 * and CertGetNameStringW for the host name check (Curl_verify_host), and the
 * certificate hash properties used for pinning and info. The certificate is a
 * throwaway self-signed one made at run time (CN=localhost, SAN DNS=localhost).
 *
 * Success (probed on Win10 22H2, std and adm identical):
 *   - CertGetNameStringW: CERT_NAME_DNS_TYPE, CERT_NAME_ATTR_TYPE with
 *     szOID_COMMON_NAME and CERT_NAME_SIMPLE_DISPLAY_TYPE all return
 *     "localhost" (10 characters including the NUL); the issuer name too;
 *   - the SAN extension is found, is not critical, and decodes to one entry of
 *     type CERT_ALT_NAME_DNS_NAME (3) = "localhost";
 *   - the subject public key is RSA (1.2.840.113549.1.1.1) with a 270 byte key
 *     blob, the signature algorithm is sha256RSA (1.2.840.113549.1.1.11), the
 *     certificate is v3 (dwVersion 2) and the subject equals the issuer;
 *   - CERT_SHA1_HASH_PROP_ID is 20 bytes and CERT_SHA256_HASH_PROP_ID 32 bytes;
 *   - CertVerifyTimeValidity returns 0 for now;
 *   - the DER round-trips through a PEM encoding (CRYPT_STRING_BASE64HEADER,
 *     starts with "-----BEGIN CERTIFICATE-----") and back, byte for byte;
 *   - a PEM block without its END line fails CryptStringToBinaryA with
 *     ERROR_INVALID_DATA (13);
 *   - a DER cut by 5 bytes fails CertCreateCertificateContext with
 *     CRYPT_E_ASN1_EOD (0x80093102).
 */
#define TEST_NAME "schannel_23_cert_names_der_pem"
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


int main(void) {
  servercert sc;
  WCHAR nm[128];
  DWORD n, l = 0, bl = 0, dl = 0, skip = 0, flg = 0;
  PCERT_EXTENSION ex;
  PCERT_ALT_NAME_INFO ai = NULL;
  BYTE hash[32];
  char *pem;
  BYTE *der;
  PCCERT_CONTEXT c2;
  PCERT_INFO ci;

  if (!make_cert(&sc, L"localhost", L"localhost"))
    return bad(TEST_NAME, "creating the self-signed certificate failed");
  ci = sc.cert->pCertInfo;

  n = CertGetNameStringW(sc.cert, CERT_NAME_DNS_TYPE, 0, NULL, nm, 128);
  CHECK(n == 10 && wcscmp(nm, L"localhost") == 0, "CERT_NAME_DNS_TYPE is not \"localhost\" / 10");
  n = CertGetNameStringW(sc.cert, CERT_NAME_ATTR_TYPE, 0, (void *)szOID_COMMON_NAME, nm, 128);
  CHECK(n == 10 && wcscmp(nm, L"localhost") == 0, "CERT_NAME_ATTR_TYPE(CN) is not \"localhost\" / 10");
  n = CertGetNameStringW(sc.cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nm, 128);
  CHECK(n == 10 && wcscmp(nm, L"localhost") == 0, "CERT_NAME_SIMPLE_DISPLAY_TYPE is not \"localhost\" / 10");
  n = CertGetNameStringW(sc.cert, CERT_NAME_DNS_TYPE, CERT_NAME_ISSUER_FLAG, NULL, nm, 128);
  CHECK(n == 10 && wcscmp(nm, L"localhost") == 0, "issuer CERT_NAME_DNS_TYPE is not \"localhost\" / 10");

  ex = CertFindExtension(szOID_SUBJECT_ALT_NAME2, ci->cExtension, ci->rgExtension);
  CHECK(ex != NULL && !ex->fCritical, "subject alternative name extension missing or critical");
  CHECK(CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, ex->Value.pbData, ex->Value.cbData,
                            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL, &ai, &l),
        "CryptDecodeObjectEx(X509_ALTERNATE_NAME) failed");
  CHECK(ai->cAltEntry == 1 && ai->rgAltEntry[0].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME &&
          wcscmp(ai->rgAltEntry[0].pwszDNSName, L"localhost") == 0,
        "SAN does not decode to a single DNS name \"localhost\"");
  LocalFree(ai);

  CHECK(strcmp(ci->SubjectPublicKeyInfo.Algorithm.pszObjId, "1.2.840.113549.1.1.1") == 0, "public key is not RSA");
  CHECK(ci->SubjectPublicKeyInfo.PublicKey.cbData == 270, "RSA-2048 public key blob is not 270 bytes");
  CHECK(strcmp(ci->SignatureAlgorithm.pszObjId, "1.2.840.113549.1.1.11") == 0, "signature algorithm is not sha256RSA");
  CHECK(ci->dwVersion == 2, "certificate is not v3");
  CHECK(CertCompareCertificateName(X509_ASN_ENCODING, &ci->Subject, &ci->Issuer), "subject != issuer");
  l = 20;
  CHECK(CertGetCertificateContextProperty(sc.cert, CERT_SHA1_HASH_PROP_ID, hash, &l) && l == 20, "SHA1 hash property");
  l = 32;
  CHECK(CertGetCertificateContextProperty(sc.cert, CERT_SHA256_HASH_PROP_ID, hash, &l) && l == 32, "SHA256 hash property");
  CHECK(CertVerifyTimeValidity(NULL, ci) == 0, "CertVerifyTimeValidity(now) != 0");

  CHECK(CryptBinaryToStringA(sc.cert->pbCertEncoded, sc.cert->cbCertEncoded, CRYPT_STRING_BASE64HEADER | CRYPT_STRING_NOCR,
                             NULL, &bl),
        "CryptBinaryToStringA size query failed");
  pem = (char *)malloc(bl + 1);
  CHECK(CryptBinaryToStringA(sc.cert->pbCertEncoded, sc.cert->cbCertEncoded, CRYPT_STRING_BASE64HEADER | CRYPT_STRING_NOCR,
                             pem, &bl),
        "CryptBinaryToStringA failed");
  CHECK(strncmp(pem, "-----BEGIN CERTIFICATE-----", 27) == 0, "PEM does not start with the BEGIN CERTIFICATE line");
  CHECK(CryptStringToBinaryA(pem, 0, CRYPT_STRING_BASE64HEADER, NULL, &dl, &skip, &flg) && dl == sc.cert->cbCertEncoded,
        "CryptStringToBinaryA size does not match the DER");
  der = (BYTE *)malloc(dl);
  CHECK(CryptStringToBinaryA(pem, 0, CRYPT_STRING_BASE64HEADER, der, &dl, &skip, &flg) &&
          memcmp(der, sc.cert->pbCertEncoded, dl) == 0,
        "PEM did not round trip to the original DER");
  c2 = CertCreateCertificateContext(X509_ASN_ENCODING, der, dl);
  CHECK(c2 != NULL, "CertCreateCertificateContext(DER) failed");
  CertFreeCertificateContext(c2);
  SetLastError(0);
  c2 = CertCreateCertificateContext(X509_ASN_ENCODING, der, dl - 5);
  CHECK(c2 == NULL && GetLastError() == 0x80093102u, "truncated DER did not fail with CRYPT_E_ASN1_EOD");
  SetLastError(0);
  CHECK(!CryptStringToBinaryA("-----BEGIN CERTIFICATE-----\nAAAA\n", 0, CRYPT_STRING_BASE64HEADER, NULL, &dl, &skip, &flg) &&
          GetLastError() == ERROR_INVALID_DATA,
        "PEM without END line did not fail with ERROR_INVALID_DATA");
  free(pem);
  free(der);
  free_cert(&sc);
  printf("PASS %s\n", TEST_NAME);
  return 0;
}
