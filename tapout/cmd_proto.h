/*
 * cmd_proto.h -- Tapout remote-command wire format (parse + ECDSA verify).
 * -------------------------------------------------------------------------
 * Pure C, no Arduino String / heap-owned objects, so it compiles unchanged on
 * the device (mbedtls) AND on a dev host (OpenSSL) for tools/test_cmd_proto.cpp.
 * tools/tapout (the CLI) is the only producer.
 *
 * Authentication mirrors the signed OTA pipeline: ASYMMETRIC. Commands are
 * signed with an ECDSA P-256 PRIVATE key that never leaves the operator's
 * machine (~/.config/tapout/cmd_private_key.pem); the device only holds the
 * matching PUBLIC key, compiled in from tapout/cmd_public_key.h (committed, not
 * secret). So nothing secret is ever provisioned to / stored on the device,
 * a dumped device can't be used to forge commands, and changing who may
 * command the unit needs a signed firmware release.
 *
 * A command is ONE line of URL-safe ASCII, posted as the body of an ntfy
 * message to the private command topic:
 *
 *   T2;ts=<unix ms>;id=<hex nonce>;c=<cmd>[;to=<status|call|auto|url>][;m=<n>]
 *     [;p=<priority>][;w=<token>][;u=<pct-encoded url>]
 *     [;ti=<pct-encoded title>][;b=<pct-encoded body>];sig=<base64url DER sig>
 *
 * sig = ECDSA-P256 over SHA-256(every byte BEFORE ";sig="), DER-encoded, then
 * base64url without padding. Free text (ti, b, u) is percent-encoded by the
 * CLI, so the whole line is [A-Za-z0-9;=%._~-] and survives ntfy's JSON
 * wrapping with no escaping. The signature covers the destination (`to`), so a
 * message can't be re-routed to the crew topic. Freshness / replay rules are
 * enforced by the caller (tapout.ino); this layer only answers "is this
 * well-formed and signed by the operator's key?".
 * -------------------------------------------------------------------------
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#if defined(ARDUINO)
  #include <mbedtls/pk.h>
  #include <mbedtls/sha256.h>
#else
  #include <openssl/evp.h>
  #include <openssl/pem.h>
#endif

#define CMD_MAX_LINE   1024   // longest raw command line accepted
#define CMD_SIG_B64MAX 100    // base64url of a <= 72-byte DER ECDSA-P256 signature is <= 96 chars

struct CmdMsg {
  uint64_t ts;          // sender's unix time in ms (freshness + monotonic replay floor)
  char     id[24];      // sender nonce, echoed in the STATUS ack so the CLI can match it
  char     c[16];       // command name
  char     to[8];       // "status" | "call" | "auto" | "url" | "" (absent)
  uint32_t m;           // number (maint-start minutes, ring-mode ms); 0 = absent
  char     p[8];        // ntfy priority for announce; "" = absent
  char     ti[72];      // decoded title
  char     b[260];      // decoded body
  char     w[8];        // which/mode token (set-topic: call|status|cmd; ring-mode: single|pattern)
  char     u[200];      // decoded ntfy URL (test/send --url, set-topic)
};

enum CmdErr {
  CMD_OK = 0,
  CMD_ERR_FORMAT,       // not a T2 line / malformed field
  CMD_ERR_TOO_LONG,     // a field overflowed its buffer
  CMD_ERR_NO_SIG,       // missing / malformed sig
  CMD_ERR_BAD_SIG,      // signature doesn't verify (wrong key or tampered)
  CMD_ERR_MISSING,      // ts / id / c missing
  CMD_ERR_NO_KEY        // no usable public key (placeholder / unparsable)
};

static inline const char* cmdErrStr(int e) {
  switch (e) {
    case CMD_OK:           return "ok";
    case CMD_ERR_FORMAT:   return "malformed";
    case CMD_ERR_TOO_LONG: return "field too long";
    case CMD_ERR_NO_SIG:   return "no signature";
    case CMD_ERR_BAD_SIG:  return "bad signature";
    case CMD_ERR_MISSING:  return "missing ts/id/c";
    case CMD_ERR_NO_KEY:   return "no key";
    default:               return "unknown";
  }
}

// base64url (RFC 4648 sec. 5, no padding) -> bytes. Returns length, or -1.
static inline int cmdB64urlDecode(const char* in, size_t n, uint8_t* out, size_t cap) {
  uint32_t acc = 0;
  int bits = 0;
  size_t o = 0;
  for (size_t i = 0; i < n; i++) {
    char c = in[i];
    int v;
    if (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
    else if (c >= '0' && c <= '9') v = c - '0' + 52;
    else if (c == '-') v = 62;
    else if (c == '_') v = 63;
    else return -1;
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= cap) return -1;
      out[o++] = (uint8_t)(acc >> bits);
    }
  }
  return (int)o;
}

// ECDSA-P256 / SHA-256 verify of msg against a PEM public key. 1 ok, 0 bad sig,
// -1 key unusable.
static inline int cmdEcdsaVerify(const char* pubPem, const uint8_t* msg, size_t len,
                                 const uint8_t* sig, size_t sigLen) {
#if defined(ARDUINO)
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  if (mbedtls_pk_parse_public_key(&pk, (const unsigned char*)pubPem, strlen(pubPem) + 1) != 0
      || mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY
      || mbedtls_pk_ec(pk)->MBEDTLS_PRIVATE(grp).id != MBEDTLS_ECP_DP_SECP256R1) {   // P-256 only
    mbedtls_pk_free(&pk);
    return -1;
  }
  uint8_t hash[32];
  int r = -1;
  if (mbedtls_sha256(msg, len, hash, 0) == 0)
    r = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sigLen) == 0 ? 1 : 0;
  mbedtls_pk_free(&pk);
  return r;
#else
  BIO* bio = BIO_new_mem_buf(pubPem, -1);
  EVP_PKEY* pk = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
  if (bio) BIO_free(bio);
  char grp[32] = {0};
  if (!pk || EVP_PKEY_base_id(pk) != EVP_PKEY_EC
      || !EVP_PKEY_get_group_name(pk, grp, sizeof(grp), NULL) || strcmp(grp, "prime256v1") != 0) {
    if (pk) EVP_PKEY_free(pk);
    return -1;                                         // P-256 only
  }
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  int r = (ctx && EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pk) == 1
           && EVP_DigestVerify(ctx, sig, sigLen, msg, len) == 1) ? 1 : 0;
  if (ctx) EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pk);
  return r;
#endif
}

static inline int cmdHexVal(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

// Percent-decode src[0..n) into dst (NUL-terminated). Rejects bad escapes,
// overflow, and control characters. Newline is allowed ONLY where the value
// becomes an HTTP body (b); anything that becomes a header (title) or a URL must
// be single-line, or a "\nPriority: max" could be smuggled into the request.
static inline bool cmdPctDecode(const char* src, size_t n, char* dst, size_t cap, bool allowNewline) {
  size_t o = 0;
  for (size_t i = 0; i < n; i++) {
    unsigned char ch = (unsigned char)src[i];
    if (ch == '%') {
      if (i + 2 >= n) return false;                // need two hex digits after '%'
      int hi = cmdHexVal(src[i + 1]), lo = cmdHexVal(src[i + 2]);
      if (hi < 0 || lo < 0) return false;
      ch = (unsigned char)((hi << 4) | lo);
      i += 2;
    }
    if (ch < 0x20 && !(allowNewline && ch == '\n')) return false;
    if (ch == 0x7f) return false;
    if (o + 1 >= cap) return false;
    dst[o++] = (char)ch;
  }
  dst[o] = '\0';
  return true;
}

// Copy a raw (non-encoded) token into a fixed buffer; only [A-Za-z0-9_-] allowed.
static inline bool cmdCopyToken(const char* src, size_t n, char* dst, size_t cap) {
  if (n == 0 || n + 1 > cap) return false;
  for (size_t i = 0; i < n; i++) {
    char ch = src[i];
    bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
    if (!ok) return false;
    dst[i] = ch;
  }
  dst[n] = '\0';
  return true;
}

static inline bool cmdParseU64(const char* s, size_t n, uint64_t* out) {
  if (n == 0 || n > 19) return false;
  uint64_t v = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') return false;
    v = v * 10 + (uint64_t)(s[i] - '0');
  }
  *out = v;
  return true;
}

// Parse + authenticate one raw command line against the operator's PUBLIC key.
// On CMD_OK, *out is fully populated.
static inline int cmdParseVerify(const char* raw, size_t len, const char* pubPem, CmdMsg* out) {
  if (!pubPem || !strstr(pubPem, "BEGIN PUBLIC KEY") || strstr(pubPem, "CHANGE-ME")) return CMD_ERR_NO_KEY;
  if (len > CMD_MAX_LINE) return CMD_ERR_TOO_LONG;
  if (len < 3 || memcmp(raw, "T2;", 3) != 0) return CMD_ERR_FORMAT;

  // Signature: the LAST field, ";sig=" + base64url, running to end of line.
  static const char SIGK[] = ";sig=";
  const size_t SIGKL = sizeof(SIGK) - 1;
  size_t sigAt = 0;
  for (size_t i = len; i-- > 3;) {
    if (i + SIGKL <= len && memcmp(raw + i, SIGK, SIGKL) == 0) { sigAt = i; break; }
  }
  if (sigAt == 0) return CMD_ERR_NO_SIG;
  const char* sigB64 = raw + sigAt + SIGKL;
  size_t sigB64Len = len - sigAt - SIGKL;
  if (sigB64Len == 0 || sigB64Len > CMD_SIG_B64MAX) return CMD_ERR_NO_SIG;
  uint8_t sig[80];
  int sigLen = cmdB64urlDecode(sigB64, sigB64Len, sig, sizeof(sig));
  if (sigLen < 8) return CMD_ERR_NO_SIG;

  int v = cmdEcdsaVerify(pubPem, (const uint8_t*)raw, sigAt, sig, (size_t)sigLen);
  if (v < 0) return CMD_ERR_NO_KEY;
  if (v == 0) return CMD_ERR_BAD_SIG;

  // Authentic. Now split the signed part (after "T2;") into k=v fields.
  memset(out, 0, sizeof(*out));
  bool haveTs = false, haveId = false, haveC = false;
  size_t i = 3;
  while (i < sigAt) {
    size_t j = i;
    while (j < sigAt && raw[j] != ';') j++;
    const char* f = raw + i;
    size_t fl = j - i;
    const char* eq = (const char*)memchr(f, '=', fl);
    if (!eq) return CMD_ERR_FORMAT;
    size_t kl = (size_t)(eq - f);
    const char* val = eq + 1;
    size_t vl = fl - kl - 1;

    #define CMD_KEY(s) (kl == sizeof(s) - 1 && memcmp(f, s, kl) == 0)
    if (CMD_KEY("ts")) {
      if (!cmdParseU64(val, vl, &out->ts)) return CMD_ERR_FORMAT;
      haveTs = true;
    } else if (CMD_KEY("id")) {
      if (!cmdCopyToken(val, vl, out->id, sizeof(out->id))) return CMD_ERR_TOO_LONG;
      haveId = true;
    } else if (CMD_KEY("c")) {
      if (!cmdCopyToken(val, vl, out->c, sizeof(out->c))) return CMD_ERR_TOO_LONG;
      haveC = true;
    } else if (CMD_KEY("to")) {
      if (!cmdCopyToken(val, vl, out->to, sizeof(out->to))) return CMD_ERR_TOO_LONG;
    } else if (CMD_KEY("p")) {
      if (!cmdCopyToken(val, vl, out->p, sizeof(out->p))) return CMD_ERR_TOO_LONG;
    } else if (CMD_KEY("m")) {
      uint64_t mm;
      if (!cmdParseU64(val, vl, &mm) || mm > 100000) return CMD_ERR_FORMAT;
      out->m = (uint32_t)mm;
    } else if (CMD_KEY("ti")) {
      if (!cmdPctDecode(val, vl, out->ti, sizeof(out->ti), false)) return CMD_ERR_TOO_LONG;
    } else if (CMD_KEY("b")) {
      if (!cmdPctDecode(val, vl, out->b, sizeof(out->b), true)) return CMD_ERR_TOO_LONG;
    } else if (CMD_KEY("w")) {
      if (!cmdCopyToken(val, vl, out->w, sizeof(out->w))) return CMD_ERR_TOO_LONG;
    } else if (CMD_KEY("u")) {
      if (!cmdPctDecode(val, vl, out->u, sizeof(out->u), false)) return CMD_ERR_TOO_LONG;
    }
    // Unknown keys are ignored (they are still covered by the signature), so a
    // newer CLI can add optional fields without breaking an older device.
    #undef CMD_KEY
    i = j + 1;
  }
  if (!haveTs || !haveId || !haveC) return CMD_ERR_MISSING;
  return CMD_OK;
}

// ---------------------------------------------------------------------------
// Topic-URL helpers (used by tapout.ino; pure C so tools/test_cmd_proto.cpp can
// exercise them on the host).
//
// Strict shape for any URL a command supplies: https://<host>/<topic>, host of
// [A-Za-z0-9.-] with a dot (<= 63 chars), topic of [A-Za-z0-9_-]{1,64}, and
// NOTHING else (no port, extra path, ?query, #fragment or user@). ntfy treats
// host case, ?query and a trailing slash as the same topic, so a looser check
// would let "https://NTFY.sh/<crew>?x" slip past the "is this the crew?" guards.
static inline bool cmdUrlLooksOk(const char* u) {
  if (strncmp(u, "https://", 8) != 0) return false;
  const char* h = u + 8;
  const char* slash = strchr(h, '/');
  if (!slash) return false;
  size_t hl = (size_t)(slash - h);
  if (hl < 3 || hl > 63) return false;
  bool dot = false;
  for (size_t i = 0; i < hl; i++) {
    char c = h[i];
    if (c == '.') dot = true;
    else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) return false;
  }
  if (!dot) return false;
  const char* t = slash + 1;
  size_t tl = strlen(t);
  if (tl < 1 || tl > 64) return false;
  for (size_t i = 0; i < tl; i++) {
    char c = t[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
  }
  return true;
}

// Loose canonical form for COMPARING topic URLs (stored values may predate the
// strict check): trimmed, lower-cased, no ?query/#fragment, no ":443", no
// trailing slash. Folding the topic's case too is deliberately conservative: it
// can only make two URLs compare EQUAL, i.e. make a guard refuse more, never less.
static inline void cmdCanonTopic(const char* in, char* out, size_t cap) {
  while (*in == ' ' || *in == '\t') in++;
  size_t o = 0;
  for (; *in && *in != '?' && *in != '#' && o + 1 < cap; in++) {
    char c = *in;
    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    out[o++] = c;
  }
  while (o && (out[o - 1] == ' ' || out[o - 1] == '\t' || out[o - 1] == '\r' || out[o - 1] == '\n')) o--;
  out[o] = '\0';
  char* p = strstr(out, ":443/");                  // https default port
  if (p) memmove(p, p + 4, strlen(p + 4) + 1);
  o = strlen(out);
  while (o && out[o - 1] == '/') out[--o] = '\0';
}

// "Is this the same ntfy topic?" compares ONLY the topic name (last path
// segment of the canonical form), ignoring the host entirely. The same server
// answers to other names -- its IP (which the firewall already pins), a
// trailing-dot FQDN, a www. alias -- so comparing hosts would let
// https://159.203.148.75/<crew> slip past the crew guard. Ignoring the host can
// only make a guard refuse MORE (a same-named topic on another server), never less.
static inline const char* cmdTopicName(const char* canon) {
  const char* slash = strrchr(canon, '/');
  return slash ? slash + 1 : canon;
}

static inline bool cmdSameTopic(const char* a, const char* b) {
  if (!a || !b || !a[0] || !b[0]) return false;
  char ca[256], cb[256];
  cmdCanonTopic(a, ca, sizeof(ca));
  cmdCanonTopic(b, cb, sizeof(cb));
  const char* ta = cmdTopicName(ca);
  const char* tb = cmdTopicName(cb);
  return ta[0] && strcmp(ta, tb) == 0;
}
