// Online Patcher for Magisk - single autonomous ARM64 binary, no external
// tools required at runtime.
//
// Fetches a JSON config over HTTPS describing which APK(s) and/or plain
// file(s) to patch and which (mask, pattern, replacement) rules to apply,
// extracts/patches/re-signs (APK v1 / JAR scheme, embedded identity) and
// repacks APK targets, or just copies+patches plain file targets, then
// bind-mounts the result over the original - no pm install, no separate
// shell orchestration needed beyond one invocation at boot.
//
// Caching: skips the (slow) rebuild of a target when neither its source
// content nor its own slice of the config has changed since last run.
//
// Build (Android NDK aarch64):
//   aarch64-linux-android24-clang -O2 -o patcher patcher.c puff.c
//
// Usage:
//   patcher [boot|daemon|revert]
//   patcher <work_dir> <log_file> <cache_index_file> <patched_out> [mode]
//
// With no (or one) argument, every path is derived from the directory the
// binary itself lives in (see get_module_dir()) - nothing is hardcoded to
// any particular device, app, or install location. The config URL is read
// from a "config_url" text file next to the binary (or from persisted
// state if the server has since redirected it) - not compiled in either.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <fnmatch.h>
#include <sys/system_properties.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <ftw.h>

/* bionic's sched.h does not expose setns() even though the syscall is
   available on the Android API level used by this binary. */
static int enter_mount_namespace(int nsfd) {
    return (int)syscall(__NR_setns, nsfd, CLONE_NEWNS);
}

#include "sha1.h"
#include "bignum.h"
#include "signing_identity.h"
#include "puff.h"
#include "http_fetch.h"
#include "rules_json.h"
#include "cache_index.h"
#include "patcher_state.h"
#include "safety.h"

static FILE *g_log = NULL;
static char g_log_path[600];

/* The log is capped at LOG_MAX_BYTES: once it grows past that, everything
   but the newest LOG_KEEP_BYTES (10%) is dropped, cut at a line boundary.
   Truncated in place rather than rename()d, so another instance that has
   the same file open with O_APPEND keeps writing into it. */
#define LOG_MAX_BYTES (2L * 1024 * 1024)
#define LOG_KEEP_BYTES (LOG_MAX_BYTES / 10)

static void log_trim_if_needed(void) {
    if (!g_log || !g_log_path[0]) return;
    struct stat st;
    if (fstat(fileno(g_log), &st) != 0 || st.st_size <= LOG_MAX_BYTES) return;

    FILE *r = fopen(g_log_path, "rb");
    if (!r) return;
    char *buf = (char *)malloc(LOG_KEEP_BYTES);
    size_t n = 0;
    if (buf && fseek(r, -LOG_KEEP_BYTES, SEEK_END) == 0) n = fread(buf, 1, LOG_KEEP_BYTES, r);
    fclose(r);
    if (!buf) return;

    /* Skip the (probably partial) first line. */
    char *nl = (char *)memchr(buf, '\n', n);
    size_t off = nl ? (size_t)(nl - buf) + 1 : n;

    FILE *w = fopen(g_log_path, "wb");
    if (w) {
        fwrite(buf + off, 1, n - off, w);
        fclose(w);
    }
    free(buf);
}

static void logmsg(const char *fmt, ...) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    va_list ap;
    char buf[2048];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    fprintf(stdout, "[%s] %s\n", ts, buf);
    if (g_log) {
        fprintf(g_log, "[%s] %s\n", ts, buf);
        fflush(g_log);
        log_trim_if_needed();
    }
}

static int mkdir_p(const char *path) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return -1;
    if (tmp[len - 1] == '/') tmp[len - 1] = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755);
}

static unsigned char *read_whole_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char *)malloc(len > 0 ? len : 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, len, f);
    fclose(f);
    if ((long)rd != len) { free(buf); return NULL; }
    *out_len = len;
    return buf;
}

/* The target APK can be 300+ MB; hashing it in full just to check "did
   anything change" is wasteful I/O - and now that callers only invoke this
   at all when there's actually a reason to (a new/changed config, or the
   one-time post-boot check), it's worth spending a bit more per call for a
   thorough answer: fold the file size plus a 128 KB sample every 16 MB
   (plus the tail) into one SHA1 instead of reading the whole thing. For a
   ~350 MB APK that's ~2.9 MB of I/O instead of 350 MB, while still covering
   the file far more evenly than a handful of fixed head/mid/tail samples.
   Returns 0 and fills hex_out (41 bytes) on success. */
#define FASTFP_CHUNK (128 * 1024)
#define FASTFP_STRIDE (16 * 1024 * 1024)
static int fast_fingerprint_sampled(const char *path, char *hex_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    if (size < 0) { fclose(f); return -1; }

    SHA1_CTX ctx;
    sha1_init(&ctx);

    char sizebuf[32];
    int slen = snprintf(sizebuf, sizeof(sizebuf), "%ld", size);
    sha1_update(&ctx, (const unsigned char *)sizebuf, (size_t)slen);

    static unsigned char buf[FASTFP_CHUNK];
    for (long off = 0; off < size; off += FASTFP_STRIDE) {
        if (fseek(f, off, SEEK_SET) != 0) break;
        size_t rd = fread(buf, 1, FASTFP_CHUNK, f);
        if (rd == 0) break;
        sha1_update(&ctx, buf, rd);
    }
    if (size > FASTFP_CHUNK) {
        /* make sure the very end is covered even when size isn't a clean
           multiple of the stride */
        fseek(f, size - FASTFP_CHUNK, SEEK_SET);
        size_t rd = fread(buf, 1, FASTFP_CHUNK, f);
        sha1_update(&ctx, buf, rd);
    }
    fclose(f);

    unsigned char digest[20];
    sha1_final(&ctx, digest);
    for (int i = 0; i < 20; i++) snprintf(hex_out + i * 2, 3, "%02x", digest[i]);
    return 0;
}

/* Below this size, hashing the whole file is cheap enough that there's no
   reason to settle for a sampled fingerprint - an exact SHA1 is strictly
   better and these are typically small config/policy files (a few KB to a
   few MB), not the 300+ MB APKs the sampled path exists for. */
#define FULL_HASH_THRESHOLD (8 * 1024 * 1024)

static int content_fingerprint(const char *path, char *hex_out) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    if (st.st_size < FULL_HASH_THRESHOLD) {
        long len;
        unsigned char *buf = read_whole_file(path, &len);
        if (!buf) return -1;
        unsigned char digest[20];
        sha1_buf(buf, len, digest);
        free(buf);
        for (int i = 0; i < 20; i++) snprintf(hex_out + i * 2, 3, "%02x", digest[i]);
        return 0;
    }
    return fast_fingerprint_sampled(path, hex_out);
}

static int write_whole_file(const char *path, const unsigned char *data, long len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t wr = fwrite(data, 1, len, f);
    fclose(f);
    return (long)wr == len ? 0 : -1;
}

/* A freshly-written patched file carries the daemon's uid/gid, a default
   0666-ish mode, and a generic SELinux label - but it is then bind-mounted
   over the original, so every stat()/getxattr() of the target path suddenly
   reports *this* file's identity, not the pristine file's. Apps that rely on
   ownership (private per-user data files) or SELinux (wrong label on a
   datadir file gets the app's read/write denied in enforcing mode) then
   break. Copy uid/gid/mode and the security.selinux label from the pristine
   original onto the patched build so the mount is transparent. Best-effort:
   logs failures but never fails the caller. chmod must come after chown -
   chown clears setuid/setgid bits. */
static void copy_file_attrs(const char *src, const char *dst) {
    struct stat st;
    if (stat(src, &st) != 0) {
        logmsg("cannot stat %s to copy attrs: %s", src, strerror(errno));
        return;
    }

    char sctx[512];
    ssize_t sclen = lgetxattr(src, "security.selinux", sctx, sizeof(sctx) - 1);

    if (chown(dst, st.st_uid, st.st_gid) != 0) {
        logmsg("chown %s -> %d:%d failed: %s", dst, (int)st.st_uid, (int)st.st_gid, strerror(errno));
    }
    if (chmod(dst, st.st_mode & 07777) != 0) {
        logmsg("chmod %s -> %o failed: %s", dst, st.st_mode & 07777, strerror(errno));
    }

    if (sclen >= 0) {
        sctx[sclen] = 0;
        if (lsetxattr(dst, "security.selinux", sctx, (size_t)sclen, 0) != 0) {
            logmsg("setfilecon %s -> %s failed: %s", dst, sctx, strerror(errno));
        } else {
            logmsg("attrs copied %s -> %s (uid=%d gid=%d mode=%o scontext=%s)",
                   src, dst, (int)st.st_uid, (int)st.st_gid, st.st_mode & 07777, sctx);
        }
    } else {
        logmsg("attrs copied %s -> %s (uid=%d gid=%d mode=%o, no scontext on source)",
               src, dst, (int)st.st_uid, (int)st.st_gid, st.st_mode & 07777);
    }
}

/* ---------------- CRC32 ---------------- */
static uint32_t crc32_table[256];
static void crc32_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
}
static uint32_t crc32_buf(const unsigned char *buf, size_t len) {
    uint32_t c = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) c = crc32_table[(c ^ buf[i]) & 0xff] ^ (c >> 8);
    return c ^ 0xFFFFFFFF;
}

/* ---------------- little-endian read helpers ---------------- */
static uint16_t rd16(const unsigned char *p) { return p[0] | (p[1] << 8); }
static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr16(unsigned char *p, uint16_t v) { p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; }
static void wr32(unsigned char *p, uint32_t v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}

/* ---------------- ZIP extraction (central directory driven) ---------------- */

typedef struct {
    char name[512];
    uint16_t method;
    uint32_t comp_size;
    uint32_t uncomp_size;
    uint32_t local_header_offset;
} zip_entry_t;

static int extract_zip(const char *zip_path, const char *dest_dir) {
    long zlen;
    unsigned char *z = read_whole_file(zip_path, &zlen);
    if (!z) { logmsg("read_whole_file failed for %s", zip_path); return -1; }

    /* find EOCD (search from end, signature 0x06054b50) */
    long eocd = -1;
    for (long i = zlen - 22; i >= 0 && i >= zlen - 22 - 65536; i--) {
        if (rd32(z + i) == 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) { logmsg("EOCD not found"); free(z); return -1; }

    uint16_t total_entries = rd16(z + eocd + 10);
    uint32_t cd_offset = rd32(z + eocd + 16);

    const unsigned char *cd = z + cd_offset;
    for (int i = 0; i < total_entries; i++) {
        if (rd32(cd) != 0x02014b50) { logmsg("bad central dir signature at entry %d", i); break; }

        uint16_t method = rd16(cd + 10);
        uint32_t comp_size = rd32(cd + 20);
        uint32_t uncomp_size = rd32(cd + 24);
        uint16_t name_len = rd16(cd + 28);
        uint16_t extra_len = rd16(cd + 30);
        uint16_t comment_len = rd16(cd + 32);
        uint32_t local_offset = rd32(cd + 42);

        char name[512];
        int nlen = name_len < 511 ? name_len : 511;
        memcpy(name, cd + 46, nlen);
        name[nlen] = 0;

        const unsigned char *lh = z + local_offset;
        if (rd32(lh) != 0x04034b50) { logmsg("bad local header for %s", name); cd += 46 + name_len + extra_len + comment_len; continue; }
        uint16_t lh_name_len = rd16(lh + 26);
        uint16_t lh_extra_len = rd16(lh + 28);
        const unsigned char *data = lh + 30 + lh_name_len + lh_extra_len;

        /* build dest path, skip directory entries (trailing slash) */
        if (nlen > 0 && name[nlen - 1] != '/') {
            char destpath[1024];
            snprintf(destpath, sizeof(destpath), "%s/%s", dest_dir, name);

            /* ensure parent dir exists */
            char parent[1024];
            snprintf(parent, sizeof(parent), "%s", destpath);
            char *slash = strrchr(parent, '/');
            if (slash) { *slash = 0; mkdir_p(parent); }

            unsigned char *outbuf = NULL;
            long outlen = 0;

            if (method == 0) {
                outbuf = (unsigned char *)data;
                outlen = comp_size;
                write_whole_file(destpath, outbuf, outlen);
            } else if (method == 8) {
                unsigned char *decomp = (unsigned char *)malloc(uncomp_size > 0 ? uncomp_size : 1);
                unsigned long destlen = uncomp_size;
                unsigned long srclen = comp_size;
                int pr = puff(decomp, &destlen, data, &srclen);
                if (pr != 0) {
                    logmsg("puff() failed for %s (code %d)", name, pr);
                    free(decomp);
                    cd += 46 + name_len + extra_len + comment_len;
                    continue;
                }
                write_whole_file(destpath, decomp, destlen);
                free(decomp);
            } else {
                logmsg("unsupported compression method %d for %s, skipping", method, name);
            }
        }

        cd += 46 + name_len + extra_len + comment_len;
    }

    free(z);
    return 0;
}

/* ---------------- directory walk (for repack + manifest) ---------------- */

typedef struct file_list {
    char relpath[512];
    struct file_list *next;
} file_list_t;

static void walk_dir(const char *base, const char *rel, file_list_t **head) {
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", base, rel);
    DIR *d = opendir(full);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
        char childrel[512];
        if (rel[0]) snprintf(childrel, sizeof(childrel), "%s/%s", rel, ent->d_name);
        else snprintf(childrel, sizeof(childrel), "%s", ent->d_name);

        char childfull[1024];
        snprintf(childfull, sizeof(childfull), "%s/%s", base, childrel);
        struct stat st;
        if (stat(childfull, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            walk_dir(base, childrel, head);
        } else {
            file_list_t *node = (file_list_t *)malloc(sizeof(file_list_t));
            snprintf(node->relpath, sizeof(node->relpath), "%s", childrel);
            node->next = *head;
            *head = node;
        }
    }
    closedir(d);
}

static int cmp_relpath(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

/* ---------------- base64 ---------------- */
static const char b64tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void base64_encode(const unsigned char *data, int len, char *out) {
    int i, j;
    for (i = 0, j = 0; i + 2 < len + 2 && i < len; i += 3) {
        uint32_t v = data[i] << 16;
        if (i + 1 < len) v |= data[i + 1] << 8;
        if (i + 2 < len) v |= data[i + 2];
        out[j++] = b64tab[(v >> 18) & 0x3f];
        out[j++] = b64tab[(v >> 12) & 0x3f];
        out[j++] = (i + 1 < len) ? b64tab[(v >> 6) & 0x3f] : '=';
        out[j++] = (i + 2 < len) ? b64tab[v & 0x3f] : '=';
    }
    out[j] = 0;
}

/* ---------------- DER / PKCS7 helpers ---------------- */

typedef struct { unsigned char *buf; int len; int cap; } bytebuf_t;
static void bb_init(bytebuf_t *b) { b->cap = 4096; b->len = 0; b->buf = (unsigned char *)malloc(b->cap); }
static void bb_ensure(bytebuf_t *b, int extra) {
    if (b->len + extra > b->cap) {
        while (b->len + extra > b->cap) b->cap *= 2;
        b->buf = (unsigned char *)realloc(b->buf, b->cap);
    }
}
static void bb_append(bytebuf_t *b, const unsigned char *data, int len) {
    bb_ensure(b, len);
    memcpy(b->buf + b->len, data, len);
    b->len += len;
}
static void bb_append_str(bytebuf_t *b, const char *s) { bb_append(b, (const unsigned char *)s, (int)strlen(s)); }
static void bb_append_byte(bytebuf_t *b, unsigned char c) { bb_append(b, &c, 1); }

static int der_length_bytes(int n, unsigned char *out) {
    if (n < 0x80) { out[0] = (unsigned char)n; return 1; }
    unsigned char tmp[8]; int tl = 0;
    int nn = n;
    while (nn > 0) { tmp[tl++] = nn & 0xff; nn >>= 8; }
    out[0] = (unsigned char)(0x80 | tl);
    for (int i = 0; i < tl; i++) out[1 + i] = tmp[tl - 1 - i];
    return 1 + tl;
}

static void der_tlv(bytebuf_t *out, unsigned char tag, const unsigned char *content, int clen) {
    unsigned char lb[16];
    int ll = der_length_bytes(clen, lb);
    bb_append_byte(out, tag);
    bb_append(out, lb, ll);
    bb_append(out, content, clen);
}

static void der_sequence(bytebuf_t *out, const bytebuf_t *inner) { der_tlv(out, 0x30, inner->buf, inner->len); }
static void der_set(bytebuf_t *out, const bytebuf_t *inner) { der_tlv(out, 0x31, inner->buf, inner->len); }
static void der_context(bytebuf_t *out, int tagnum, const unsigned char *content, int clen) {
    der_tlv(out, (unsigned char)(0xA0 | tagnum), content, clen);
}

static void der_oid_raw(bytebuf_t *out, const unsigned char *encoded_oid, int len) {
    /* encoded_oid already full DER TLV for an OID (tag 0x06 ...), just append */
    bb_append(out, encoded_oid, len);
}

static void der_bigint_bytes(bytebuf_t *out, const unsigned char *bytes, int len) {
    /* strip leading zero bytes, then add a 0x00 pad if high bit set */
    while (len > 1 && bytes[0] == 0) { bytes++; len--; }
    int need_pad = (len > 0 && (bytes[0] & 0x80)) ? 1 : 0;
    unsigned char *tmp = (unsigned char *)malloc(len + need_pad);
    if (need_pad) tmp[0] = 0;
    memcpy(tmp + need_pad, bytes, len);
    der_tlv(out, 0x02, tmp, len + need_pad);
    free(tmp);
}

static void der_null(bytebuf_t *out) { unsigned char n[2] = {0x05, 0x00}; bb_append(out, n, 2); }

/* pre-built minimal OID DER encodings (tag 0x06, len, bytes) */
static const unsigned char OID_SHA1[]        = {0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a};
static const unsigned char OID_RSA_ENC[]     = {0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01};
static const unsigned char OID_PKCS7_DATA[]  = {0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01};
static const unsigned char OID_PKCS7_SIGNED[]= {0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02};

static void build_alg_id(bytebuf_t *out, const unsigned char *oid, int oidlen) {
    bytebuf_t inner; bb_init(&inner);
    der_oid_raw(&inner, oid, oidlen);
    der_null(&inner);
    der_sequence(out, &inner);
    free(inner.buf);
}

/* RSA sign via embedded fixed key: signature = base^d mod n (PKCS#1 v1.5 padding + DigestInfo(SHA1)) */
static const unsigned char SHA1_DIGESTINFO_PREFIX[] = {
    0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14
};

static void rsa_sign_sha1(const unsigned char *digest20, unsigned char *sig_out /* RSA_MODULUS_N_len bytes */) {
    int k = RSA_MODULUS_N_len; /* key size in bytes, 256 for 2048-bit */
    unsigned char *em = (unsigned char *)malloc(k);
    unsigned char t[15 + 20];
    memcpy(t, SHA1_DIGESTINFO_PREFIX, sizeof(SHA1_DIGESTINFO_PREFIX));
    memcpy(t + sizeof(SHA1_DIGESTINFO_PREFIX), digest20, 20);
    int tlen = sizeof(SHA1_DIGESTINFO_PREFIX) + 20;

    /* EMSA-PKCS1-v1_5 encode: 0x00 0x01 FF..FF 0x00 T */
    int ps_len = k - tlen - 3;
    em[0] = 0x00; em[1] = 0x01;
    for (int i = 0; i < ps_len; i++) em[2 + i] = 0xFF;
    em[2 + ps_len] = 0x00;
    memcpy(em + 3 + ps_len, t, tlen);

    bn_t base, exp, mod, res;
    bn_from_bytes(&base, em, k);
    bn_from_bytes(&exp, RSA_PRIVATE_D, RSA_PRIVATE_D_len);
    bn_from_bytes(&mod, RSA_MODULUS_N, RSA_MODULUS_N_len);
    bn_modexp(&base, &exp, &mod, &res);

    /* res.d is BN_MAX_BYTES wide big-endian; take last k bytes */
    memcpy(sig_out, res.d + (BN_MAX_BYTES - k), k);
    free(em);
}

/* ---------------- MANIFEST.MF / CERT.SF construction ---------------- */

static void wrap_manifest_line(bytebuf_t *out, const char *s) {
    int len = (int)strlen(s);
    int pos = 0;
    int first = 1;
    while (pos < len) {
        int limit = first ? 70 : 69;
        int chunk = (len - pos) < limit ? (len - pos) : limit;
        if (!first) bb_append_byte(out, ' ');
        bb_append(out, (const unsigned char *)(s + pos), chunk);
        bb_append_str(out, "\r\n");
        pos += chunk;
        first = 0;
    }
}

static void get_device_prop(const char *name, char *out, int outsz) {
    char buf[PROP_VALUE_MAX];
    buf[0] = 0;
    __system_property_get(name, buf);
    snprintf(out, outsz, "%s", buf);
}

static void url_encode(const char *in, char *out, int outsz) {
    int j = 0;
    for (int i = 0; in[i] && j < outsz - 4; i++) {
        unsigned char c = (unsigned char)in[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out[j++] = c;
        } else {
            j += snprintf(out + j, outsz - j, "%%%02X", c);
        }
    }
    out[j] = 0;
}

/* Splits a "https://host[/path]" URL into host and path components
   (path defaults to "/" if absent). Only https is supported (see
   http_fetch.h). */
static int split_url(const char *url, char *host, int hostsz, char *path, int pathsz) {
    const char *p = url;
    if (!strncmp(p, "https://", 8)) p += 8;
    else if (!strncmp(p, "http://", 7)) p += 7;

    const char *slash = strchr(p, '/');
    if (slash) {
        int hlen = (int)(slash - p);
        if (hlen >= hostsz) hlen = hostsz - 1;
        memcpy(host, p, hlen);
        host[hlen] = 0;
        snprintf(path, pathsz, "%s", slash);
    } else {
        snprintf(host, hostsz, "%s", p);
        snprintf(path, pathsz, "/");
    }
    return 0;
}

/* Appends "&key=url_encode(value)" to buf, but only if the property named
   `propname` actually has a value - devices/builds don't all expose the
   same properties, so an empty one is just omitted rather than sent blank. */
static void append_prop_param(bytebuf_t *buf, const char *key, const char *propname) {
    char raw[256], enc[512];
    get_device_prop(propname, raw, sizeof(raw));
    if (!raw[0]) return;
    url_encode(raw, enc, sizeof(enc));
    bb_append_str(buf, "&");
    bb_append_str(buf, key);
    bb_append_str(buf, "=");
    bb_append_str(buf, enc);
}

/* Fetches the patch config from `config_url`, appending device/firmware
   identification as query params - enough for the server to serve
   different rules per device/platform/firmware build without this tool
   needing to know anything about what it's patching:
     serial, manufacturer, model, device, platform, fingerprint (the full
     firmware build fingerprint), android (release version), sdk (API
     level), build_id.
   Returns a malloc'd JSON string (caller frees), or NULL if the fetch
   failed outright (network error) or came back with a non-2xx status or
   an empty body - the caller treats all of those as "nothing to do this
   cycle", never as "use some fallback rules". */
static char *fetch_config(const char *config_url) {
    bytebuf_t q; bb_init(&q);

    {
        char serial[64];
        get_device_prop("ro.serialno", serial, sizeof(serial));
        if (!serial[0]) get_device_prop("ro.boot.serialno", serial, sizeof(serial));
        if (serial[0]) {
            char enc[128];
            url_encode(serial, enc, sizeof(enc));
            bb_append_str(&q, "&serial=");
            bb_append_str(&q, enc);
        }
    }
    append_prop_param(&q, "manufacturer", "ro.product.manufacturer");
    append_prop_param(&q, "model", "ro.product.model");
    append_prop_param(&q, "device", "ro.product.device");
    append_prop_param(&q, "platform", "ro.board.platform");
    append_prop_param(&q, "fingerprint", "ro.build.fingerprint");
    append_prop_param(&q, "android", "ro.build.version.release");
    append_prop_param(&q, "sdk", "ro.build.version.sdk");
    append_prop_param(&q, "build_id", "ro.build.id");

    char host[256], path[256], full_path[900];
    split_url(config_url, host, sizeof(host), path, sizeof(path));
    /* q starts with '&' (or is empty); turn the first one into '?' */
    if (q.len > 0) q.buf[0] = '?';
    snprintf(full_path, sizeof(full_path), "%s%.*s", path, q.len, q.len ? (const char *)q.buf : "");
    free(q.buf);

    /* Polls themselves are not logged (one every few seconds would flood the
       log); a failure is logged once when it starts, and once more when
       fetching works again. */
    static int fetch_failing = 0;
    int status = 0;
    char *body = https_get(host, full_path, 5, &status);

    if (!body) {
        if (!fetch_failing) logmsg("config fetch failed (network/TLS error): https://%s%s", host, full_path);
        fetch_failing = 1;
        return NULL;
    }
    if (status < 200 || status >= 300) {
        if (!fetch_failing) logmsg("config fetch got HTTP %d, ignoring", status);
        fetch_failing = 1;
        free(body);
        return NULL;
    }
    if (!body[0]) {
        if (!fetch_failing) logmsg("config fetch returned empty body, ignoring");
        fetch_failing = 1;
        free(body);
        return NULL;
    }

    if (fetch_failing) logmsg("config fetch works again (%zu bytes)", strlen(body));
    fetch_failing = 0;
    return body;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes an even-length hex string into malloc'd raw bytes. Returns NULL
   on a malformed (odd-length or non-hex) string. */
static unsigned char *hex_decode(const char *hex, long *out_len) {
    size_t hlen = strlen(hex);
    if (hlen == 0 || hlen % 2 != 0) return NULL;
    long blen = (long)(hlen / 2);
    unsigned char *buf = (unsigned char *)malloc((size_t)blen);
    if (!buf) return NULL;
    for (long i = 0; i < blen; i++) {
        int hi = hexval(hex[i * 2]), lo = hexval(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) { free(buf); return NULL; }
        buf[i] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = blen;
    return buf;
}

/* A plain JSON string can't carry arbitrary binary (no embedded NUL, no
   raw non-UTF8 bytes), so pattern accepts a pattern_hex form too.
   Precedence when both are given: pattern_hex over pattern. Returns
   malloc'd bytes (caller frees) and NULL (with *out_len untouched) if
   neither was provided or pattern_hex was malformed. */
static unsigned char *resolve_pattern(const patch_rule_t *rule, long *out_len) {
    if (rule->pattern_hex[0]) return hex_decode(rule->pattern_hex, out_len);
    if (rule->pattern[0]) {
        long l = (long)strlen(rule->pattern);
        unsigned char *buf = (unsigned char *)malloc((size_t)l);
        if (buf) memcpy(buf, rule->pattern, (size_t)l);
        *out_len = l;
        return buf;
    }
    return NULL;
}

/* replace has three forms - plain string, replace_hex (binary via hex), or
   replace_file (content read from a device-local path at apply time, for
   replacements too large/binary to comfortably inline in the config JSON
   at all). Precedence when more than one is given: replace_file over
   replace_hex over replace. Unlike resolve_pattern(), a genuinely empty
   replace ("delete the matched bytes") must stay distinguishable from
   "replace_file/replace_hex was given but unreadable/malformed" - so this
   reports failure via `*ok` rather than a NULL return, since an empty
   result is itself a valid success (NULL buffer, length 0). */
static unsigned char *resolve_replace(const patch_rule_t *rule, long *out_len, int *ok) {
    *ok = 0;
    if (rule->replace_file[0]) {
        unsigned char *buf = read_whole_file(rule->replace_file, out_len);
        if (!buf) return NULL;
        *ok = 1;
        return buf;
    }
    if (rule->replace_hex[0]) {
        unsigned char *buf = hex_decode(rule->replace_hex, out_len);
        if (!buf) return NULL;
        *ok = 1;
        return buf;
    }
    long l = (long)strlen(rule->replace);
    unsigned char *buf = (unsigned char *)malloc(l > 0 ? (size_t)l : 1);
    if (!buf) return NULL;
    if (l > 0) memcpy(buf, rule->replace, (size_t)l);
    *out_len = l;
    *ok = 1;
    return buf;
}

/* Applies every rule whose file_name mask matches `relpath` (fnmatch,
   FNM_PATHNAME so a bare "*.cfg" doesn't cross directory separators),
   in the order given, doing a plain substring replace pattern->replace
   (see resolve_pattern()/resolve_replace() for where pattern/replace bytes
   actually come from - plain string, hex, or a file). Returns the number
   of rules that actually matched *and* replaced at least one occurrence. */
/* default_file_name is used in place of a rule's own (empty) file_name -
   for a "file_path" target there's only one file, nothing to disambiguate,
   so config authors don't need to repeat the path in every rule. Pass ""
   (never matches anything) for "apk_path" targets, where an empty
   file_name on a rule is just left unmatched as before. */
static int apply_rules_to_file(const char *full_path, const char *relpath,
                                const rule_set_t *rs, const char *default_file_name) {
    int applied = 0;

    for (int r = 0; r < rs->count; r++) {
        const patch_rule_t *rule = &rs->rules[r];
        const char *file_name = rule->file_name[0] ? rule->file_name : default_file_name;
        if (!file_name || !file_name[0]) continue;
        if (fnmatch(file_name, relpath, FNM_PATHNAME) != 0 &&
            strcmp(file_name, relpath) != 0) {
            continue;
        }

        long fromlen = 0;
        unsigned char *pattern_buf = resolve_pattern(rule, &fromlen);
        if (!pattern_buf || fromlen == 0) { free(pattern_buf); continue; }

        long tolen = 0;
        int replace_ok = 0;
        unsigned char *replace_buf = resolve_replace(rule, &tolen, &replace_ok);
        if (!replace_ok) {
            logmsg("rule #%d: replace_file/replace_hex unreadable or malformed, skipping", r);
            free(pattern_buf);
            free(replace_buf);
            continue;
        }

        long flen;
        unsigned char *data = read_whole_file(full_path, &flen);
        if (!data) { free(pattern_buf); free(replace_buf); continue; }

        long outcap = flen + 1024;
        unsigned char *outbuf = (unsigned char *)malloc(outcap);
        long op = 0;
        int replaced = 0;
        for (long i = 0; i < flen; ) {
            if (i + fromlen <= flen && memcmp(data + i, pattern_buf, (size_t)fromlen) == 0) {
                if (op + tolen > outcap) { outcap = (op + tolen) * 2; outbuf = (unsigned char *)realloc(outbuf, outcap); }
                if (tolen > 0) memcpy(outbuf + op, replace_buf, (size_t)tolen);
                op += tolen;
                i += fromlen;
                replaced++;
            } else {
                if (op + 1 > outcap) { outcap *= 2; outbuf = (unsigned char *)realloc(outbuf, outcap); }
                outbuf[op++] = data[i++];
            }
        }

        if (replaced > 0) {
            write_whole_file(full_path, outbuf, op);
            logmsg("patched: %s (%d occurrences of rule #%d, %ld -> %ld bytes)", relpath, replaced, r, fromlen, tolen);
            applied++;
        }
        free(data);
        free(outbuf);
        free(pattern_buf);
        free(replace_buf);
    }

    return applied;
}

/* Bind-mounts `source` over every path that currently holds a copy of the
   target package: the given system path itself, plus any per-user
   base.apk copy under /data/app/<dir containing package_name> this OEM's
   PackageManager may keep (discovered via plain directory scan - `pm path`
   isn't usable this early in boot). Returns the number of successful
   mounts. */
/* Bind-mounting swaps what a *new* open() of system_path sees, but any
   process that already has the APK open (e.g. the app itself, running)
   keeps reading its original fd/mmap - it will not observe the patched
   content until it re-opens the APK, which normally only happens on
   process restart. force-stop the app after a real content change so the
   next launch picks up the freshly patched assets. */
static void restart_app(const char *package_name) {
    if (!package_name || !package_name[0]) return;
    /* Always restart only after a short delay, so the freshly mounted (or
       unmounted) file has settled in every relevant mount namespace before
       the app is killed - otherwise its re-fork would come up against the
       file it had open before the (un)mount. Callers invoke this right after
       every mount and every unmount. */
    usleep(100 * 1000);
    pid_t pid = fork();
    if (pid == 0) {
        execl("/system/bin/killall", "killall", package_name, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        logmsg("restarted app: killall %s (exit %d)", package_name,
               WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    } else {
        logmsg("restart_app: fork failed (%s)", strerror(errno));
    }
}

/* Runs an arbitrary shell command as root, sourced from the (trusted, our
   own server's) remote config. Only invoked when its hash differs from the
   last one we ran, so a persistent "exec" entry doesn't get re-executed on
   every poll tick. */
static void run_exec_command(const char *cmd) {
    logmsg("executing root command from config: %s", cmd);
    pid_t pid = fork();
    if (pid == 0) {
        execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        logmsg("exec command finished (exit %d)", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    } else {
        logmsg("run_exec_command: fork failed (%s)", strerror(errno));
    }
}

/* Calls cb(base_apk_path, ctx) for system_path itself, plus every
   /data/app/<dir containing package_name>/base.apk copy this OEM's
   PackageManager may keep (found via plain directory scan - `pm path` isn't
   usable this early in boot). Shared by mount_over_all_copies() and
   unmount_all_copies() so the "find every copy of this app" logic exists
   exactly once. */
static int for_each_apk_copy(const char *system_path, const char *package_name,
                              void (*cb)(const char *path, void *ctx), void *ctx) {
    int count = 0;
    cb(system_path, ctx);
    count++;

    if (package_name && package_name[0]) {
        DIR *d = opendir("/data/app");
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
                char sub[600];
                snprintf(sub, sizeof(sub), "/data/app/%s", ent->d_name);
                DIR *d2 = opendir(sub);
                if (!d2) continue;
                struct dirent *ent2;
                while ((ent2 = readdir(d2)) != NULL) {
                    if (!strstr(ent2->d_name, package_name)) continue;
                    char base_apk[900];
                    snprintf(base_apk, sizeof(base_apk), "%s/%s/base.apk", sub, ent2->d_name);
                    struct stat st;
                    if (stat(base_apk, &st) != 0) continue;
                    cb(base_apk, ctx);
                    count++;
                }
                closedir(d2);
            }
            closedir(d);
        }
    }
    return count;
}

static void cb_mount(const char *path, void *ctx) {
    const char *source = (const char *)ctx;
    umount2(path, MNT_DETACH);
    if (mount(source, path, NULL, MS_BIND, NULL) == 0) {
        logmsg("bind mount OK: %s -> %s", source, path);
    } else {
        logmsg("bind mount FAILED for %s (%s)", path, strerror(errno));
    }
}

static int mount_over_all_copies(const char *source, const char *system_path, const char *package_name) {
    int count = for_each_apk_copy(system_path, package_name, cb_mount, (void *)source);

    /* Android gives zygote-launched apps their own mount namespace. A bind
       mount made only in the Magisk daemon's namespace is therefore invisible
       to the app, even though mount() succeeds. Put the same mount in every
       relevant zygote/app namespace as well. */
    if (package_name && package_name[0]) {
        DIR *proc = opendir("/proc");
        if (proc) {
            struct dirent *ent;
            ino_t seen[32];
            int seen_count = 0;
            while ((ent = readdir(proc)) != NULL) {
                if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;

                char procfile[128], name[256];
                snprintf(procfile, sizeof(procfile), "/proc/%s/cmdline", ent->d_name);
                FILE *pf = fopen(procfile, "r");
                if (!pf) continue;
                size_t n = fread(name, 1, sizeof(name) - 1, pf);
                fclose(pf);
                if (n == 0) continue;
                name[n] = 0;

                int relevant = !strcmp(name, "zygote") || !strcmp(name, "zygote64") ||
                               !strncmp(name, package_name, strlen(package_name));
                if (!relevant) continue;

                snprintf(procfile, sizeof(procfile), "/proc/%s/ns/mnt", ent->d_name);
                struct stat nsst;
                if (stat(procfile, &nsst) != 0) continue;
                int duplicate = 0;
                for (int i = 0; i < seen_count; i++) {
                    if (seen[i] == nsst.st_ino) { duplicate = 1; break; }
                }
                if (duplicate || seen_count >= (int)(sizeof(seen) / sizeof(seen[0]))) continue;
                seen[seen_count++] = nsst.st_ino;

                int nsfd = open(procfile, O_RDONLY);
                int selfns = open("/proc/self/ns/mnt", O_RDONLY);
                if (nsfd < 0 || selfns < 0) {
                    if (nsfd >= 0) close(nsfd);
                    if (selfns >= 0) close(selfns);
                    continue;
                }
                if (enter_mount_namespace(nsfd) == 0) {
                    int mounted = for_each_apk_copy(system_path, package_name, cb_mount, (void *)source);
                    count += mounted;
                    logmsg("mounted in namespace of %s (pid %s): %d mount(s)", name, ent->d_name, mounted);
                    if (enter_mount_namespace(selfns) != 0) {
                        logmsg("cannot restore mount namespace after pid %s: %s", ent->d_name, strerror(errno));
                    }
                } else {
                    logmsg("cannot enter mount namespace of pid %s: %s", ent->d_name, strerror(errno));
                }
                close(nsfd);
                close(selfns);
            }
            closedir(proc);
        }
    }
    return count;
}

/* A bind mount can disappear without the config changing (for example when
   Android recreates an isolated mount namespace).  The config fast path must
   not make that loss permanent: restore cached mounts before deciding that
   there is nothing new to process. */
/* ---------------- Boot safety ----------------
   A patched system file that is broken can hang Android's own boot (see
   safety.h), after which the network never comes up and the patcher can
   never fetch a fix. Three layers keep that from happening or from sticking:

   1. patched_file_sane(): a patched file is checked before it's cached or
      mounted - at build time and again before every (boot-time) mount.
   2. boot_guard: post-fs-data ("boot" mode) bumps an attempt counter in
      boot_guard; the daemon deletes the file once sys.boot_completed=1. So
      a guard that is still there at the next boot means the previous boot
      never completed. Level 1 (second attempt) skips plain-file targets,
      level 2 (third and later) skips every patch - the device then boots
      stock, with its network, and can be fixed remotely.
   3. Watchdog: if boot_completed hasn't happened BOOT_TIMEOUT_SEC after
      the daemon started, the plain-file builds currently in the cache are
      put in quarantine (by content hash - the same bad output is never
      mounted again, a corrected one is) and the device is rebooted. */
#define BOOT_TIMEOUT_SEC 600
#define BOOT_MAX_REBOOTS 3

static char g_guard_path[600];
static char g_quar_path[600];
static int g_skip_level = 0;   /* 0 = normal, 1 = skip file targets, 2 = skip all */
static int g_deferred = 0;     /* a target was held back by safe mode this cycle */
static time_t g_daemon_start;

static int guard_attempts(void) {
    FILE *f = fopen(g_guard_path, "r");
    if (!f) return 0;
    int n = 0;
    if (fscanf(f, "attempts=%d", &n) != 1) n = 1;
    fclose(f);
    return n < 1 ? 1 : n;
}

static void guard_write(int n) {
    FILE *f = fopen(g_guard_path, "w");
    if (!f) return;
    fprintf(f, "attempts=%d\n", n);
    fflush(f);
    fsync(fileno(f));
    fclose(f);
}

static int skip_level_for(int attempts) {
    return attempts <= 1 ? 0 : (attempts == 2 ? 1 : 2);
}

/* Is this cache row a plain-file patch (as opposed to a ZIP/APK)? Those are
   the ones that can wedge the boot, so safe mode / quarantine cover them. */
static int patched_is_plain_file(const char *patched_path) {
    unsigned char sig[4] = {0};
    FILE *f = fopen(patched_path, "rb");
    if (!f) return 1;
    size_t n = fread(sig, 1, 4, f);
    fclose(f);
    return !(n == 4 && sig[0] == 'P' && sig[1] == 'K' && sig[2] == 3 && sig[3] == 4);
}

static int quarantined(const char *patched_sha1) {
    FILE *f = fopen(g_quar_path, "r");
    if (!f) return 0;
    char line[128];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strcmp(line, patched_sha1)) { found = 1; break; }
    }
    fclose(f);
    return found;
}

static void quarantine_add(const char *patched_sha1) {
    if (quarantined(patched_sha1)) return;
    FILE *f = fopen(g_quar_path, "a");
    if (!f) return;
    fprintf(f, "%s\n", patched_sha1);
    fclose(f);
}

/* 1 if the patched file is safe to hand to the system. */
static int patched_file_sane(const char *patched_path, const char *target_path) {
    struct stat st;
    if (stat(patched_path, &st) != 0 || st.st_size == 0) {
        logmsg("sanity: %s is missing or empty", patched_path);
        return 0;
    }
    size_t tl = strlen(target_path);
    if (tl > 4 && !strcmp(target_path + tl - 4, ".xml")) {
        long len;
        unsigned char *data = read_whole_file(patched_path, &len);
        if (!data) { logmsg("sanity: cannot read %s", patched_path); return 0; }
        char err[160];
        int ok = xml_wellformed(data, len, err, sizeof(err));
        free(data);
        if (!ok) {
            logmsg("sanity: %s is not well-formed XML (%s)", target_path, err);
            return 0;
        }
    }
    return 1;
}

/* logmsg() that stays quiet for a message it has already printed - used for
   conditions that are re-evaluated every poll cycle. */
static void log_once(const char *fmt, ...) {
    static uint32_t seen[64];
    static int nseen = 0;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    uint32_t h = 2166136261u;
    for (const char *p = buf; *p; p++) { h ^= (unsigned char)*p; h *= 16777619u; }
    for (int i = 0; i < nseen; i++) if (seen[i] == h) return;
    if (nseen < 64) seen[nseen++] = h;
    logmsg("%s", buf);
}

/* Should a cached row be left unmounted right now (safe mode / quarantine /
   failed sanity check)? Logs why. A row that fails the sanity check is
   dropped so the daemon rebuilds it. */
static int row_blocked(const char *cache_index_path, const cache_entry_t *e) {
    int is_file = patched_is_plain_file(e->patched_path);
    if (g_skip_level >= 2 || (g_skip_level >= 1 && is_file)) {
        log_once("safe mode (level %d): not mounting %s", g_skip_level, e->name);
        g_deferred = 1;
        return 1;
    }
    if (is_file && quarantined(e->patched)) {
        log_once("quarantined build %.12s (an earlier boot hung with it): not mounting %s", e->patched, e->name);
        return 1;
    }
    if (!patched_file_sane(e->patched_path, e->name)) {
        logmsg("dropping unusable cached build of %s", e->name);
        cache_index_remove(cache_index_path, e->name);
        return 1;
    }
    return 0;
}

/* Daemon, once per loop: clear the guard when boot finished; otherwise, if
   it is taking suspiciously long, quarantine and reboot. */
static void boot_guard_tick(const char *cache_index_path) {
    int attempts = guard_attempts();
    if (attempts == 0) return;

    char done[PROP_VALUE_MAX];
    get_device_prop("sys.boot_completed", done, sizeof(done));
    if (!strcmp(done, "1")) {
        unlink(g_guard_path);
        g_skip_level = 0;
        logmsg("boot completed (attempt %d), boot guard cleared", attempts);
        return;
    }

    static int fired = 0;
    if (fired || difftime(time(NULL), g_daemon_start) < BOOT_TIMEOUT_SEC) return;
    fired = 1;
    if (attempts > BOOT_MAX_REBOOTS) {
        logmsg("boot still not completed after %ds, attempt %d - giving up rebooting",
               BOOT_TIMEOUT_SEC, attempts);
        return;
    }

    cache_index_t idx;
    cache_index_load(cache_index_path, &idx);
    for (int i = 0; i < idx.count; i++) {
        if (patched_is_plain_file(idx.entries[i].patched_path)) {
            quarantine_add(idx.entries[i].patched);
            logmsg("boot watchdog: quarantined build %.12s of %s",
                   idx.entries[i].patched, idx.entries[i].name);
        }
    }
    logmsg("boot watchdog: boot not completed %ds after start (attempt %d) - rebooting",
           BOOT_TIMEOUT_SEC, attempts);
    sync();
    pid_t pid = fork();
    if (pid == 0) {
        execl("/system/bin/reboot", "reboot", (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        waitpid(pid, NULL, 0);
    }
}

/* Deletes every patched*.apk next to the cache index that no cache row
   references any more - left behind when a target is reverted, its row is
   dropped as stale, or the target is renamed. A file that is still
   bind-mounted somewhere stays alive through the mount, so unlinking it
   is always safe. Stale patched*.tmp from an interrupted build go too. */
static void gc_patched_files(const char *cache_index_path) {
    char dir[600];
    snprintf(dir, sizeof(dir), "%s", cache_index_path);
    char *slash = strrchr(dir, '/');
    if (slash) *slash = 0; else snprintf(dir, sizeof(dir), ".");

    cache_index_t idx;
    cache_index_load(cache_index_path, &idx);

    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t len = strlen(de->d_name);
        if (strncmp(de->d_name, "patched", 7) != 0 || len < 4 ||
            (strcmp(de->d_name + len - 4, ".apk") != 0 &&
             strcmp(de->d_name + len - 4, ".tmp") != 0)) continue;
        char full[900];
        snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
        int used = 0;
        for (int i = 0; i < idx.count; i++) {
            if (!strcmp(idx.entries[i].patched_path, full)) { used = 1; break; }
        }
        if (used) continue;
        if (unlink(full) == 0) logmsg("removed unused cached patch: %s", full);
        else logmsg("cannot remove unused cached patch %s: %s", full, strerror(errno));
    }
    closedir(d);
}

static int rm_tree_cb(const char *path, const struct stat *sb, int flag, struct FTW *ftw) {
    (void)sb; (void)flag; (void)ftw;
    remove(path);
    return 0;
}

/* rm -rf; a missing path is fine. */
static void rm_tree(const char *path) {
    nftw(path, rm_tree_cb, 16, FTW_DEPTH | FTW_PHYS);
}

/* Re-establishes cached mounts that went missing. A row whose original
   changed underneath it (app update, the app rewrote its own file, ...) is
   dropped instead of being re-checked - and re-logged - every cycle.
   Returns the number of rows dropped. */
static int ensure_cached_mounts(const char *cache_index_path) {
    cache_index_t idx;
    if (cache_index_load(cache_index_path, &idx) != 0) return 0;
    int dropped = 0;

    for (int i = 0; i < idx.count; i++) {
        const cache_entry_t *e = &idx.entries[i];
        struct stat source_st, target_st;
        int mounted = stat(e->patched_path, &source_st) == 0 &&
                      stat(e->name, &target_st) == 0 &&
                      source_st.st_dev == target_st.st_dev &&
                      source_st.st_ino == target_st.st_ino;
        if (mounted) continue;

        /* Something else may be mounted over the target (e.g. a stale
           mount of an older build): peel it off so the fingerprint below
           sees the real original, as process_target() does. */
        for (int k = 0; k < 8 && umount2(e->name, MNT_DETACH) == 0; k++) {}

        char current_hex[41];
        if (content_fingerprint(e->name, current_hex) != 0) {
            /* Not readable (yet) - e.g. credential-encrypted app data before
               unlock. Not a changed original: keep the row, retry later. */
            continue;
        }
        if (strcmp(current_hex, e->orig) != 0) {
            logmsg("cached mount missing and original changed, dropping stale cache row: %s", e->name);
            cache_index_remove(cache_index_path, e->name);
            dropped++;
            continue;
        }

        if (row_blocked(cache_index_path, e)) continue;

        umount2(e->name, MNT_DETACH);
        int mounts = mount_over_all_copies(e->patched_path, e->name, e->package_name);
        logmsg("restored lost cached mount: %s (%d mount(s))", e->name, mounts);
        if (mounts > 0) restart_app(e->package_name);
    }
    if (dropped) gc_patched_files(cache_index_path);
    return dropped;
}

static void cb_unmount(const char *path, void *ctx) {
    (void)ctx;
    if (umount2(path, MNT_DETACH) == 0) {
        logmsg("reverted (unmounted): %s", path);
    }
}

/* Reverts a target back to its original on-disk file by dropping our bind
   mount(s) - the underlying /system file was never modified, so this alone
   is enough. */
static int unmount_all_copies(const char *system_path, const char *package_name) {
    int count = for_each_apk_copy(system_path, package_name, cb_unmount, NULL);

    /* The corresponding bind mounts may also live in zygote/app namespaces;
       remove them there so manual revert and config-driven revert are real
       reverts from the application's point of view. */
    if (package_name && package_name[0]) {
        DIR *proc = opendir("/proc");
        if (proc) {
            struct dirent *ent;
            ino_t seen[32];
            int seen_count = 0;
            while ((ent = readdir(proc)) != NULL) {
                if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;

                char procfile[128], name[256];
                snprintf(procfile, sizeof(procfile), "/proc/%s/cmdline", ent->d_name);
                FILE *pf = fopen(procfile, "r");
                if (!pf) continue;
                size_t n = fread(name, 1, sizeof(name) - 1, pf);
                fclose(pf);
                if (n == 0) continue;
                name[n] = 0;

                int relevant = !strcmp(name, "zygote") || !strcmp(name, "zygote64") ||
                               !strncmp(name, package_name, strlen(package_name));
                if (!relevant) continue;

                snprintf(procfile, sizeof(procfile), "/proc/%s/ns/mnt", ent->d_name);
                struct stat nsst;
                if (stat(procfile, &nsst) != 0) continue;
                int duplicate = 0;
                for (int i = 0; i < seen_count; i++) {
                    if (seen[i] == nsst.st_ino) { duplicate = 1; break; }
                }
                if (duplicate || seen_count >= (int)(sizeof(seen) / sizeof(seen[0]))) continue;
                seen[seen_count++] = nsst.st_ino;

                int nsfd = open(procfile, O_RDONLY);
                int selfns = open("/proc/self/ns/mnt", O_RDONLY);
                if (nsfd < 0 || selfns < 0) {
                    if (nsfd >= 0) close(nsfd);
                    if (selfns >= 0) close(selfns);
                    continue;
                }
                if (enter_mount_namespace(nsfd) == 0) {
                    count += for_each_apk_copy(system_path, package_name, cb_unmount, NULL);
                    if (enter_mount_namespace(selfns) != 0) {
                        logmsg("cannot restore mount namespace after revert pid %s: %s", ent->d_name, strerror(errno));
                    }
                } else {
                    logmsg("cannot enter mount namespace for revert pid %s: %s", ent->d_name, strerror(errno));
                }
                close(nsfd);
                close(selfns);
            }
            closedir(proc);
        }
    }
    return count;
}

/* ---- LED ring notifications ----
   This device (Yandex Station "chiron") has no visible notification shade
   in its custom launcher - `cmd notification post` completes without error
   but nothing is ever shown. The one guaranteed-visible, permission-free
   signal is its own RGB LED ring (/sys/class/leds/chiron:<color>:ring<0-47>),
   plain sysfs, no Android service involved.

   While a real rebuild is in progress: continuous yellow<->blue, 1s per
   color, running in a forked child so it doesn't block the actual
   extract/sign/repack work. The moment the rebuild finishes, the blinker is
   killed and a solid result color is held for 10s: green for success, red
   for failure. */
#define LED_RING_COUNT 48
static void led_set(const char *color, int value) {
    char path[80];
    for (int i = 0; i < LED_RING_COUNT; i++) {
        snprintf(path, sizeof(path), "/sys/class/leds/chiron:%s:ring%d/brightness", color, i);
        FILE *f = fopen(path, "w");
        if (!f) continue;
        fprintf(f, "%d", value);
        fclose(f);
    }
}

static void led_off(void) {
    led_set("red", 0);
    led_set("green", 0);
    led_set("blue", 0);
}

/* Yellow = red + green channels together (this ring has no dedicated
   yellow LED). */
static void led_set_yellow(int value) {
    led_set("red", value);
    led_set("green", value);
}

static void led_pulse(const char *color, int times, int on_ms, int off_ms) {
    for (int t = 0; t < times; t++) {
        led_set(color, 200);
        usleep((useconds_t)on_ms * 1000);
        led_set(color, 0);
        if (t < times - 1) usleep((useconds_t)off_ms * 1000);
    }
}

/* Runs in a forked child: yellow 1s, blue 1s, repeat, until killed. Returns
   the child pid (<=0 if fork failed - led_stop_patching_blink() handles
   that safely). */
static pid_t led_start_patching_blink(void) {
    pid_t pid = fork();
    if (pid == 0) {
        for (;;) {
            led_set_yellow(200);
            sleep(1);
            led_off();
            led_set("blue", 200);
            sleep(1);
            led_off();
        }
        _exit(0);
    }
    if (pid < 0) logmsg("led_start_patching_blink: fork failed (%s)", strerror(errno));
    return pid;
}

static void led_stop_patching_blink(pid_t pid) {
    if (pid > 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
    led_off();
}

/* Overall per-config result, shown asynchronously in a forked child so it
   never blocks the poll loop: the result color blinks 3x (1s on / 1s off),
   then the ring is turned off. No per-target 10s hold anymore - statuses are
   aggregated across the whole config and this is blinked once at the end. */
#define LED_STATUS_FAILED 0
#define LED_STATUS_PATCHED 1
#define LED_STATUS_SKIPPED 2
static void led_show_final(int status) {
    pid_t pid = fork();
    if (pid == 0) {
        for (int t = 0; t < 3; t++) {
            if (status == LED_STATUS_SKIPPED) led_set_yellow(200);
            else led_set(status == LED_STATUS_PATCHED ? "green" : "red", 200);
            sleep(1);
            led_off();
            if (t < 2) sleep(1);
        }
        _exit(0);
    }
    if (pid < 0) logmsg("led_show_final: fork failed (%s)", strerror(errno));
}

static void notify_revert(void) { led_pulse("blue", 3, 100, 100); }

/* Phase 0: instant offline mount, no network involved. If the current
   on-disk original apk matches a cache_index entry we already have a valid
   patched build for, mount it right away - this is what makes the patch
   survive a reboot even before the network (which this very app may be
   responsible for bringing up) is available. Fast (one sampled fingerprint,
   no HTTP, no extraction), so it's safe to run synchronously from
   post-fs-data, unlike the full fetch/rebuild pipeline below which can
   easily take 30+ seconds and risks getting killed by Magisk's post-fs-data
   time budget. */
static void phase0_instant_mount(const char *cache_index_path) {
    cache_index_t idx0;
    cache_index_load(cache_index_path, &idx0);

    for (int i = 0; i < idx0.count; i++) {
        const cache_entry_t *e = &idx0.entries[i];
        umount2(e->name, MNT_DETACH);
        char hex[41];
        if (content_fingerprint(e->name, hex) != 0) {
            /* Not readable this early: credential-encrypted app data (FBE) is
               still locked, so a file target inside /data/user/ can't be
               mounted yet. Ignore it - leave its cache row alone and let the
               daemon patch it once storage is unlocked. */
            logmsg("target not readable at boot, leaving for daemon: %s", e->name);
            continue;
        }
        if (strcmp(e->orig, hex) != 0) {
            logmsg("original changed, dropping stale cache row: %s", e->name);
            cache_index_remove(cache_index_path, e->name);
            continue;
        }
        struct stat pst;
        if (stat(e->patched_path, &pst) != 0 || pst.st_size == 0) continue;
        if (row_blocked(cache_index_path, e)) continue;
        int m = mount_over_all_copies(e->patched_path, e->name, e->package_name);
        logmsg("instant local-cache mount (no network): %s (%d mount(s))", e->name, m);
        /* Kill the app right after the mount (short delay inside restart_app)
           so it reloads the patched APK - only for APK targets (they carry a
           package_name), never for plain files. Don't kill the same package
           twice (several cached rows can share one package). */
        if (m > 0 && e->package_name[0]) {
            int already = 0;
            for (int j = 0; j < i; j++) {
                if (idx0.entries[j].package_name[0] &&
                    !strcmp(idx0.entries[j].package_name, e->package_name)) { already = 1; break; }
            }
            if (!already) restart_app(e->package_name);
        }
    }
    gc_patched_files(cache_index_path);
}

/* Derives a stable, collision-free per-target output path from the CLI's
   base patched_out path: "<dir>/patched_<sha1(target_apk)[:12]>.apk". Needed
   now that a single config can list multiple targets - each needs its own
   rebuilt-APK file, they can't all share one patched.apk. */
static void derive_patched_path(const char *base_patched_out, const char *target_apk,
                                 char *out, size_t outsz) {
    unsigned char d[20];
    sha1_buf((const unsigned char *)target_apk, strlen(target_apk), d);
    char hex12[13];
    for (int i = 0; i < 6; i++) snprintf(hex12 + i * 2, 3, "%02x", d[i]);

    char dir[500];
    const char *slash = strrchr(base_patched_out, '/');
    if (slash) {
        size_t dl = (size_t)(slash - base_patched_out);
        if (dl >= sizeof(dir)) dl = sizeof(dir) - 1;
        memcpy(dir, base_patched_out, dl);
        dir[dl] = 0;
    } else {
        dir[0] = '.'; dir[1] = 0;
    }
    snprintf(out, outsz, "%s/patched_%s.apk", dir, hex12);
}

/* Hashes just this target's own fields (path/package/type/rules) - NOT the
   whole config file. Editing one target (or the top-level poll_interval/
   config_url/exec) must not invalidate every OTHER target's cache entry and
   force it through a pointless rebuild; each target's cache key needs to
   depend only on the bytes that actually describe that target. */
static void target_content_hash(const target_config_t *t, char *hex_out) {
    SHA1_CTX ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const unsigned char *)t->apk_path, strlen(t->apk_path));
    sha1_update(&ctx, (const unsigned char *)t->package_name, strlen(t->package_name));
    sha1_update(&ctx, (const unsigned char *)t->type, strlen(t->type));
    for (int i = 0; i < t->rules.count; i++) {
        const patch_rule_t *r = &t->rules.rules[i];
        sha1_update(&ctx, (const unsigned char *)r->file_name, strlen(r->file_name));
        sha1_update(&ctx, (const unsigned char *)r->pattern, strlen(r->pattern));
        sha1_update(&ctx, (const unsigned char *)r->pattern_hex, strlen(r->pattern_hex));
        sha1_update(&ctx, (const unsigned char *)r->replace, strlen(r->replace));
        sha1_update(&ctx, (const unsigned char *)r->replace_hex, strlen(r->replace_hex));
        sha1_update(&ctx, (const unsigned char *)r->replace_file, strlen(r->replace_file));
    }
    unsigned char digest[20];
    sha1_final(&ctx, digest);
    for (int i = 0; i < 20; i++) snprintf(hex_out + i * 2, 3, "%02x", digest[i]);
}

/* Target processing outcome, reported by process_target() and aggregated by
   the caller into one LED status for the whole config. */
#define TARGET_FAILED  (-1)  /* rebuild/mount error -> red */
#define TARGET_SKIPPED 0     /* already patched (cache hit) -> yellow */
#define TARGET_REBUILT 1     /* rebuilt + mounted -> green */

/* Derives an Android package name from an app-data path of the form
   /data/user/<uid>/<pkg>/... or /data/data/<pkg>/... Returns 0 and fills
   out, or -1 if the path doesn't look like an app data dir. Used to restart
   the owning app after patching a plain file target that lives inside its
   private data directory. */
static int package_name_from_path(const char *path, char *out, size_t outsz) {
    const char *p;
    if (!strncmp(path, "/data/user/", 11)) {
        p = path + 11;
        const char *slash = strchr(p, '/');
        if (!slash) return -1;
        p = slash + 1;
    } else if (!strncmp(path, "/data/data/", 11)) {
        p = path + 11;
    } else {
        return -1;
    }
    const char *end = strchr(p, '/');
    size_t len = end ? (size_t)(end - p) : strlen(p);
    if (len == 0 || len >= outsz) return -1;
    memcpy(out, p, len);
    out[len] = 0;
    return 0;
}

/* Resolves the package to restart for a target: its explicit package_name,
   or (for a plain-file target without one) the package derived from its
   path. Returns 0 and fills out, or -1 if no package can be determined. */
static int target_package(const target_config_t *t, char *out, size_t outsz) {
    if (t->package_name[0]) { snprintf(out, outsz, "%s", t->package_name); return 0; }
    if (!strcmp(t->type, "file")) return package_name_from_path(t->apk_path, out, outsz);
    return -1;
}

/* Full extract/patch/sign/repack/mount pipeline for one target.
   Rebuilds only if (apk, target-content) isn't already in the cache index
   for this target; mounts either way. Returns TARGET_REBUILT when this
   target was really rebuilt and successfully mounted, TARGET_SKIPPED when
   the cached patched build was reused (already patched), or TARGET_FAILED
   on any error. The caller aggregates these into one LED status and restarts
   apps only after every target has been processed. */
static int process_target(const char *work_dir, const char *cache_index_path,
                          const char *base_patched_out, const target_config_t *tgt) {
    char cfg_hex[41];
    target_content_hash(tgt, cfg_hex);
    const char *target_apk = tgt->apk_path;
    /* Set by the parser based on which key the config used ("apk_path" vs
       "file_path") - see json_parse_target_object(). */
    int is_file_type = !strcmp(tgt->type, "file");
    /* No default package_name - an empty one just means
       mount_over_all_copies() skips the /data/app scan and only touches
       the target's own system path. Guessing some app's package here
       would risk bind-mounting this target over an unrelated app's
       base.apk if package_name was simply left unset in the config. */
    const char *package_name = tgt->package_name;

    if (tgt->rules.count == 0) {
        logmsg("target %s: no rules, nothing to do", target_apk);
        return TARGET_SKIPPED;
    }

    /* Safe mode (previous boot never completed): hold back what could wedge
       the boot. g_deferred makes run_cycle() process the config again once
       the boot has completed and the guard is cleared. */
    if (g_skip_level >= 2 || (g_skip_level >= 1 && is_file_type)) {
        log_once("safe mode (level %d): deferring target %s", g_skip_level, target_apk);
        g_deferred = 1;
        return TARGET_SKIPPED;
    }

    /* Built into patched_final + ".tmp" and only renamed into place once it
       has passed the sanity checks: an interrupted or rejected build must
       never replace the file the cache (and, after a reboot, the mounts)
       point to. patched_out is the tmp path while building and is switched
       to patched_final after the rename. */
    char patched_final[600], patched_out[620];
    derive_patched_path(base_patched_out, target_apk, patched_final, sizeof(patched_final));
    snprintf(patched_out, sizeof(patched_out), "%s.tmp", patched_final);

    /* We run in the global mount namespace, so once our own bind mount is
       active, target_apk resolves to our own previously patched output, not
       the pristine on-disk file - fingerprinting it as-is would make the
       cache key drift from run to run (and mismatch after every reboot, when
       the mount is gone and the path reverts to pristine). Drop any bind
       mount first so the fingerprint always reflects the true original
       source. */
    umount2(target_apk, MNT_DETACH);

    char apk_hex[41];
    if (content_fingerprint(target_apk, apk_hex) != 0) {
        logmsg("cannot read target apk: %s", target_apk);
        return TARGET_FAILED;
    }

    cache_index_t idx1;
    cache_index_load(cache_index_path, &idx1);
    const cache_entry_t *hit = cache_index_find(&idx1, target_apk);

    int use_cached_patch = 0;
    char hit_patched_path[512] = {0};
    struct stat pst;
    if (hit && !strcmp(hit->orig, apk_hex) && !strcmp(hit->cfg, cfg_hex) && stat(hit->patched_path, &pst) == 0) {
        if (is_file_type && quarantined(hit->patched)) {
            log_once("quarantined build %.12s (an earlier boot hung with it): not mounting %s",
                     hit->patched, target_apk);
            return TARGET_FAILED;
        }
        if (patched_file_sane(hit->patched_path, target_apk)) {
            use_cached_patch = 1;
            snprintf(hit_patched_path, sizeof(hit_patched_path), "%s", hit->patched_path);
            logmsg("target %s: apk + config unchanged, reusing cached patched APK", target_apk);
        } else {
            logmsg("target %s: cached build is unusable, rebuilding", target_apk);
        }
    }

    if (!use_cached_patch) {
        if (tgt->exec_before[0]) {
            logmsg("target %s: running exec_before", target_apk);
            run_exec_command(tgt->exec_before);
        }
        pid_t blink_pid = led_start_patching_blink();

        if (is_file_type) {
            /* Plain flat file (e.g. an SELinux mac_permissions.xml) - no
               ZIP, no v1 signature, just a straight copy + substring
               replace(s) and a bind-mount over the original. */
            long flen;
            unsigned char *data = read_whole_file(target_apk, &flen);
            if (!data) {
                logmsg("cannot read target file: %s", target_apk);
                led_stop_patching_blink(blink_pid);
                return TARGET_FAILED;
            }
            int wr_ok = (write_whole_file(patched_out, data, flen) == 0);
            free(data);
            if (!wr_ok) {
                logmsg("cannot write patched file: %s", patched_out);
                led_stop_patching_blink(blink_pid);
                return TARGET_FAILED;
            }

            char basename[256];
            const char *slash = strrchr(target_apk, '/');
            snprintf(basename, sizeof(basename), "%s", slash ? slash + 1 : target_apk);

            /* File targets don't need a per-rule file_name - there's only
               one file, nothing to disambiguate - so it's implied to be
               the target's own basename. */
            if (apply_rules_to_file(patched_out, basename, &tgt->rules, basename) == 0) {
                logmsg("rules present but nothing matched, nothing to mount");
                led_stop_patching_blink(blink_pid);
                return TARGET_FAILED;
            }
            logmsg("patched plain file: %s", target_apk);
            goto rebuild_done;
        }

        const rule_set_t *rules_ptr = &tgt->rules;
        char extract_dir[768];
        snprintf(extract_dir, sizeof(extract_dir), "%s/apk_extract", work_dir);
        /* Start from an empty dir: leftovers from an earlier (different)
           APK would otherwise be repacked into this one. */
        rm_tree(extract_dir);
        mkdir_p(extract_dir);

        if (extract_zip(target_apk, extract_dir) != 0) {
            logmsg("extract failed");
            rm_tree(extract_dir);
            led_stop_patching_blink(blink_pid);
            return TARGET_FAILED;
        }
        logmsg("APK extracted");

        file_list_t *rule_files = NULL;
        walk_dir(extract_dir, "", &rule_files);
        int patched_count = 0;
        for (file_list_t *f = rule_files; f; f = f->next) {
            if (!strncmp(f->relpath, "META-INF/", 9)) continue;
            char full[1024];
            snprintf(full, sizeof(full), "%s/%s", extract_dir, f->relpath);
            if (apply_rules_to_file(full, f->relpath, rules_ptr, "") > 0) patched_count++;
        }

        if (patched_count == 0) {
            logmsg("rules present but nothing matched, nothing to mount");
            rm_tree(extract_dir);
            led_stop_patching_blink(blink_pid);
            return TARGET_FAILED;
        }

    /* remove old META-INF */
    char metainf[900];
    snprintf(metainf, sizeof(metainf), "%s/META-INF", extract_dir);
    {
        /* directory removal without relying on external rm: manual recursive delete */
        DIR *d = opendir(metainf);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
                char p[1024];
                snprintf(p, sizeof(p), "%s/%s", metainf, ent->d_name);
                remove(p);
            }
            closedir(d);
            rmdir(metainf);
        }
    }
    logmsg("old META-INF removed");

    /* Build MANIFEST.MF */
    file_list_t *files = NULL;
    walk_dir(extract_dir, "", &files);

    int nfiles = 0;
    for (file_list_t *f = files; f; f = f->next) nfiles++;
    const char **paths = (const char **)malloc(sizeof(char *) * nfiles);
    {
        int i = 0;
        for (file_list_t *f = files; f; f = f->next) paths[i++] = f->relpath;
    }
    qsort(paths, nfiles, sizeof(char *), cmp_relpath);

    bytebuf_t manifest; bb_init(&manifest);
    bb_append_str(&manifest, "Manifest-Version: 1.0\r\n");
    bb_append_str(&manifest, "Created-By: 1.0 (Online Patcher for Magisk)\r\n");
    bb_append_str(&manifest, "\r\n");

    bytebuf_t *sections = (bytebuf_t *)malloc(sizeof(bytebuf_t) * nfiles);
    int real_n = 0;

    for (int i = 0; i < nfiles; i++) {
        if (!strncmp(paths[i], "META-INF/", 9)) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", extract_dir, paths[i]);
        long flen;
        unsigned char *data = read_whole_file(full, &flen);
        if (!data) continue;
        unsigned char digest[20];
        sha1_buf(data, flen, digest);
        free(data);
        char b64[64];
        base64_encode(digest, 20, b64);

        bytebuf_t sec; bb_init(&sec);
        char line[600];
        snprintf(line, sizeof(line), "Name: %s", paths[i]);
        wrap_manifest_line(&sec, line);
        snprintf(line, sizeof(line), "SHA1-Digest: %s", b64);
        wrap_manifest_line(&sec, line);
        bb_append_str(&sec, "\r\n");

        bb_append(&manifest, sec.buf, sec.len);
        sections[real_n++] = sec; /* keep for CERT.SF per-entry digest, store relpath separately */
    }

    /* re-collect names aligned with sections (skip META-INF ones consistently) */
    const char **section_names = (const char **)malloc(sizeof(char *) * real_n);
    {
        int si = 0;
        for (int i = 0; i < nfiles; i++) {
            if (!strncmp(paths[i], "META-INF/", 9)) continue;
            section_names[si++] = paths[i];
        }
    }

    unsigned char manifest_digest[20];
    sha1_buf(manifest.buf, manifest.len, manifest_digest);
    char manifest_digest_b64[64];
    base64_encode(manifest_digest, 20, manifest_digest_b64);

    bytebuf_t certsf; bb_init(&certsf);
    bb_append_str(&certsf, "Signature-Version: 1.0\r\n");
    {
        char line[128];
        snprintf(line, sizeof(line), "SHA1-Digest-Manifest: %s", manifest_digest_b64);
        wrap_manifest_line(&certsf, line);
    }
    bb_append_str(&certsf, "Created-By: 1.0 (Online Patcher for Magisk)\r\n");
    bb_append_str(&certsf, "\r\n");

    for (int i = 0; i < real_n; i++) {
        unsigned char d[20];
        sha1_buf(sections[i].buf, sections[i].len, d);
        char b64[64];
        base64_encode(d, 20, b64);
        char line[600];
        snprintf(line, sizeof(line), "Name: %s", section_names[i]);
        wrap_manifest_line(&certsf, line);
        snprintf(line, sizeof(line), "SHA1-Digest: %s", b64);
        wrap_manifest_line(&certsf, line);
        bb_append_str(&certsf, "\r\n");
    }

    /* sign CERT.SF */
    unsigned char sf_digest[20];
    sha1_buf(certsf.buf, certsf.len, sf_digest);
    unsigned char *signature = (unsigned char *)malloc(RSA_MODULUS_N_len);
    rsa_sign_sha1(sf_digest, signature);
    logmsg("CERT.SF signed (RSA-%d, pure-C modexp)", RSA_MODULUS_N_len * 8);

    /* build CERT.RSA (PKCS7 SignedData, detached, no signed attrs) */
    bytebuf_t signerinfo_seq; bb_init(&signerinfo_seq);
    {
        bytebuf_t v; bb_init(&v); der_bigint_bytes(&v, (unsigned char[]){1}, 1); bb_append(&signerinfo_seq, v.buf, v.len); free(v.buf);

        bytebuf_t issuer_and_serial; bb_init(&issuer_and_serial);
        bb_append(&issuer_and_serial, CERT_RAW_ISSUER, CERT_RAW_ISSUER_len);
        {
            bytebuf_t serial_tlv; bb_init(&serial_tlv);
            der_bigint_bytes(&serial_tlv, CERT_SERIAL, CERT_SERIAL_len);
            bb_append(&issuer_and_serial, serial_tlv.buf, serial_tlv.len);
            free(serial_tlv.buf);
        }
        bytebuf_t issuer_seq; bb_init(&issuer_seq);
        der_sequence(&issuer_seq, &issuer_and_serial);
        bb_append(&signerinfo_seq, issuer_seq.buf, issuer_seq.len);
        free(issuer_and_serial.buf); free(issuer_seq.buf);

        bytebuf_t alg1; bb_init(&alg1); build_alg_id(&alg1, OID_SHA1, sizeof(OID_SHA1));
        bb_append(&signerinfo_seq, alg1.buf, alg1.len); free(alg1.buf);

        bytebuf_t alg2; bb_init(&alg2); build_alg_id(&alg2, OID_RSA_ENC, sizeof(OID_RSA_ENC));
        bb_append(&signerinfo_seq, alg2.buf, alg2.len); free(alg2.buf);

        bytebuf_t sigwrap; bb_init(&sigwrap);
        der_tlv(&sigwrap, 0x04, signature, RSA_MODULUS_N_len);
        bb_append(&signerinfo_seq, sigwrap.buf, sigwrap.len);
        free(sigwrap.buf);
    }
    bytebuf_t signerinfo_full; bb_init(&signerinfo_full);
    der_sequence(&signerinfo_full, &signerinfo_seq);
    free(signerinfo_seq.buf);

    bytebuf_t signerinfos_set; bb_init(&signerinfos_set);
    der_set(&signerinfos_set, &signerinfo_full);
    free(signerinfo_full.buf);

    bytebuf_t digestalgs_inner; bb_init(&digestalgs_inner);
    build_alg_id(&digestalgs_inner, OID_SHA1, sizeof(OID_SHA1));
    bytebuf_t digestalgs_set; bb_init(&digestalgs_set);
    der_set(&digestalgs_set, &digestalgs_inner);
    free(digestalgs_inner.buf);

    bytebuf_t inner_ci; bb_init(&inner_ci);
    der_oid_raw(&inner_ci, OID_PKCS7_DATA, sizeof(OID_PKCS7_DATA));
    bytebuf_t inner_ci_seq; bb_init(&inner_ci_seq);
    der_sequence(&inner_ci_seq, &inner_ci);
    free(inner_ci.buf);

    bytebuf_t certs_field; bb_init(&certs_field);
    der_context(&certs_field, 0, CERT_DER, CERT_DER_len);

    bytebuf_t signeddata_inner; bb_init(&signeddata_inner);
    {
        bytebuf_t v; bb_init(&v); der_bigint_bytes(&v, (unsigned char[]){1}, 1);
        bb_append(&signeddata_inner, v.buf, v.len); free(v.buf);
        bb_append(&signeddata_inner, digestalgs_set.buf, digestalgs_set.len);
        bb_append(&signeddata_inner, inner_ci_seq.buf, inner_ci_seq.len);
        bb_append(&signeddata_inner, certs_field.buf, certs_field.len);
        bb_append(&signeddata_inner, signerinfos_set.buf, signerinfos_set.len);
    }
    bytebuf_t signeddata_seq; bb_init(&signeddata_seq);
    der_sequence(&signeddata_seq, &signeddata_inner);
    free(signeddata_inner.buf);

    bytebuf_t outer_content; bb_init(&outer_content);
    der_context(&outer_content, 0, signeddata_seq.buf, signeddata_seq.len);
    free(signeddata_seq.buf);

    bytebuf_t pkcs7_inner; bb_init(&pkcs7_inner);
    der_oid_raw(&pkcs7_inner, OID_PKCS7_SIGNED, sizeof(OID_PKCS7_SIGNED));
    bb_append(&pkcs7_inner, outer_content.buf, outer_content.len);
    free(outer_content.buf);

    bytebuf_t pkcs7; bb_init(&pkcs7);
    der_sequence(&pkcs7, &pkcs7_inner);
    free(pkcs7_inner.buf);

    /* write META-INF files */
    mkdir_p(metainf);
    {
        char p[1024];
        snprintf(p, sizeof(p), "%s/MANIFEST.MF", metainf);
        write_whole_file(p, manifest.buf, manifest.len);
        snprintf(p, sizeof(p), "%s/CERT.SF", metainf);
        write_whole_file(p, certsf.buf, certsf.len);
        snprintf(p, sizeof(p), "%s/CERT.RSA", metainf);
        write_whole_file(p, pkcs7.buf, pkcs7.len);
    }
    logmsg("APK v1-signed (self-contained, no jarsigner/apksigner)");

    /* repack (STORED entries only, no compressor needed) */
    file_list_t *all_files = NULL;
    walk_dir(extract_dir, "", &all_files);
    int total = 0;
    for (file_list_t *f = all_files; f; f = f->next) total++;
    const char **allpaths = (const char **)malloc(sizeof(char *) * total);
    { int i = 0; for (file_list_t *f = all_files; f; f = f->next) allpaths[i++] = f->relpath; }
    qsort(allpaths, total, sizeof(char *), cmp_relpath);

    FILE *out = fopen(patched_out, "wb");
    if (!out) {
        logmsg("cannot open output apk");
        rm_tree(extract_dir);
        led_stop_patching_blink(blink_pid);
        return TARGET_FAILED;
    }

    typedef struct { char name[512]; uint32_t crc; uint32_t size; uint32_t offset; } cdent_t;
    cdent_t *cdents = (cdent_t *)malloc(sizeof(cdent_t) * total);

    long cur_offset = 0;
    for (int i = 0; i < total; i++) {
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", extract_dir, allpaths[i]);
        long flen;
        unsigned char *data = read_whole_file(full, &flen);
        if (!data) continue;
        uint32_t crc = crc32_buf(data, flen);

        int name_len = (int)strlen(allpaths[i]);

        /* Native libs are mmap'd directly out of the APK by the linker, so
           their data must start at a page-aligned offset (what `zipalign -p`
           does). Everything else just needs the default 4-byte alignment. */
        int align = (strncmp(allpaths[i], "lib/", 4) == 0) ? 16384 : 4;

        long base = cur_offset + 30 + name_len;
        int rem = (int)(base % align);
        int needed = (align - rem) % align;
        if (needed < 4) needed += align; /* must fit the 4-byte extra-field header itself */
        int padding_bytes = needed - 4;

        unsigned char lh[30];
        memset(lh, 0, 30);
        wr32(lh + 0, 0x04034b50);
        wr16(lh + 4, 20);   /* version needed */
        wr16(lh + 6, 0);    /* flags */
        wr16(lh + 8, 0);    /* method: stored */
        wr16(lh + 10, 0);   /* mod time */
        wr16(lh + 12, 0);   /* mod date */
        wr32(lh + 14, crc);
        wr32(lh + 18, (uint32_t)flen);
        wr32(lh + 22, (uint32_t)flen);
        wr16(lh + 26, (uint16_t)name_len);
        wr16(lh + 28, (uint16_t)needed);

        unsigned char extra_hdr[4];
        wr16(extra_hdr + 0, 0x0000);
        wr16(extra_hdr + 2, (uint16_t)padding_bytes);

        cdents[i].offset = (uint32_t)cur_offset;
        cdents[i].crc = crc;
        cdents[i].size = (uint32_t)flen;
        snprintf(cdents[i].name, sizeof(cdents[i].name), "%s", allpaths[i]);

        fwrite(lh, 1, 30, out);
        fwrite(allpaths[i], 1, name_len, out);
        fwrite(extra_hdr, 1, 4, out);
        for (int p = 0; p < padding_bytes; p++) fputc(0, out);
        fwrite(data, 1, flen, out);
        cur_offset += 30 + name_len + needed + flen;
        free(data);
    }

    long cd_start = cur_offset;
    for (int i = 0; i < total; i++) {
        unsigned char ch[46];
        memset(ch, 0, 46);
        wr32(ch + 0, 0x02014b50);
        wr16(ch + 4, 20);
        wr16(ch + 6, 20);
        wr16(ch + 8, 0);
        wr16(ch + 10, 0);
        wr16(ch + 12, 0);
        wr16(ch + 14, 0);
        wr32(ch + 16, cdents[i].crc);
        wr32(ch + 20, cdents[i].size);
        wr32(ch + 24, cdents[i].size);
        wr16(ch + 28, (uint16_t)strlen(cdents[i].name));
        wr32(ch + 42, cdents[i].offset);
        fwrite(ch, 1, 46, out);
        fwrite(cdents[i].name, 1, strlen(cdents[i].name), out);
        cur_offset += 46 + strlen(cdents[i].name);
    }
    long cd_size = cur_offset - cd_start;

    unsigned char eocd[22];
    memset(eocd, 0, 22);
    wr32(eocd + 0, 0x06054b50);
    wr16(eocd + 8, (uint16_t)total);
    wr16(eocd + 10, (uint16_t)total);
    wr32(eocd + 12, (uint32_t)cd_size);
    wr32(eocd + 16, (uint32_t)cd_start);
    fwrite(eocd, 1, 22, out);

    fclose(out);
    logmsg("repacked -> %s (%d entries, STORED)", patched_out, total);
    /* The extracted tree is as large as the APK itself (hundreds of MB) and
       is never reused - the next rebuild extracts afresh. */
    rm_tree(extract_dir);

rebuild_done:
    copy_file_attrs(target_apk, patched_out);
    {
        char patched_hex[41];
        if (!patched_file_sane(patched_out, target_apk)) {
            logmsg("target %s: patched build rejected, NOT mounting it (check the rules)", target_apk);
            unlink(patched_out);
            led_stop_patching_blink(blink_pid);
            return TARGET_FAILED;
        }
        if (content_fingerprint(patched_out, patched_hex) == 0) {
            if (is_file_type && quarantined(patched_hex)) {
                logmsg("target %s: this exact build (%.12s) hung an earlier boot, NOT mounting it",
                       target_apk, patched_hex);
                unlink(patched_out);
                led_stop_patching_blink(blink_pid);
                return TARGET_FAILED;
            }
            if (rename(patched_out, patched_final) != 0) {
                logmsg("cannot move %s into place: %s", patched_out, strerror(errno));
                unlink(patched_out);
                led_stop_patching_blink(blink_pid);
                return TARGET_FAILED;
            }
            snprintf(patched_out, sizeof(patched_out), "%s", patched_final);
            cache_index_put(cache_index_path, target_apk, package_name, apk_hex, patched_hex, cfg_hex, patched_out);
            logmsg("cache updated: %s (orig=%.12s patched=%.12s cfg=%.12s)",
                   target_apk, apk_hex, patched_hex, cfg_hex);
        } else {
            logmsg("cannot fingerprint patched build %s", patched_out);
            unlink(patched_out);
            led_stop_patching_blink(blink_pid);
            return TARGET_FAILED;
        }
    }
    led_stop_patching_blink(blink_pid);
    logmsg("=== Patching complete: %s ===", target_apk);
    } /* end if (!use_cached_patch) */

    {
        const char *mount_source = use_cached_patch ? hit_patched_path : patched_out;
        if (use_cached_patch) copy_file_attrs(target_apk, hit_patched_path);
        int mounted = mount_over_all_copies(mount_source, target_apk, package_name);
        logmsg("total mounts: %d", mounted);

        if (use_cached_patch) return TARGET_SKIPPED;
        if (mounted <= 0) return TARGET_FAILED;
        if (tgt->exec_after[0]) {
            logmsg("target %s: running exec_after", target_apk);
            run_exec_command(tgt->exec_after);
        }
        return TARGET_REBUILT;
    }
}

/* One patch/poll cycle (daemon mode - post-fs-data's "boot" mode only ever
   calls phase0_instant_mount, never this):
      0. phase0_instant_mount(), on the very first cycle only. Later cycles
         use ensure_cached_mounts(), which only touches a mount that has
         actually gone missing - so while the network is still down at boot
         the APK isn't re-mounted over itself and the app isn't killed again
         every poll. *first_cycle stays set until the first config is
         actually processed, which only forces that processing past the
         "config unchanged" fast path.
     1. Fetch the remote config (short timeout). A network error, non-2xx
        status, or empty body all mean "nothing to do this cycle" - never a
        fallback patch. If the fetched config is byte-identical to the last
        one we successfully processed, stop right here too: no reason to
        fingerprint any (possibly 300+ MB) apk again for a config we've
        already applied.
     2. Otherwise: process_target() for every target the config lists, then
        revert (unmount + drop from the cache index) any target that WAS
        cached from a previous config but is no longer listed - removing a
        target from the config is how you tell the patcher to put the
        original back.
     3. Run the config's "exec" root command, if any and if it changed since
        last time. */
static void run_cycle(const char *work_dir, const char *cache_index_path,
                       const char *patched_out, patcher_state_t *st, int *first_cycle) {
    static int phase0_done = 0;
    int force_process = 0;
    if (!phase0_done) {
        phase0_instant_mount(cache_index_path);
        phase0_done = 1;
    } else {
        /* A cache row whose original changed underneath it was dropped:
           process the config again even if it's unchanged, so that target
           gets rebuilt from its new original. */
        force_process = ensure_cached_mounts(cache_index_path) > 0;
    }
    /* Targets held back by safe mode are processed as soon as the boot
       guard has been cleared (boot completed). */
    if (g_deferred && g_skip_level == 0) {
        force_process = 1;
        g_deferred = 0;
    }

    /* ---- Phase 1: fetch remote config, patch/mount/revert if it changed ---- */
    if (!st->config_url[0]) {
        logmsg("no config_url configured, nothing to do this cycle");
        return;
    }
    char *config_text = fetch_config(st->config_url);
    if (!config_text) return;

    unsigned char cfg_digest[20];
    sha1_buf((const unsigned char *)config_text, strlen(config_text), cfg_digest);
    char cfg_hex[41];
    for (int i = 0; i < 20; i++) snprintf(cfg_hex + i * 2, 3, "%02x", cfg_digest[i]);

    if (!*first_cycle && !force_process && !strcmp(cfg_hex, st->last_config_hash)) {
        free(config_text);
        return;
    }

    /* patch_config_t holds MAX_TARGETS targets; each target's rules are now
       heap-grown (see rules_json.h), so the struct itself is modest. Still
       heap-allocate it rather than the stack - historically a fat on-stack
       copy here overflowed a tight rlimit in some shell contexts, and heap
       keeps that impossible regardless of future field growth. Rules are
       freed via free_patch_config() before free(cfg) on every exit path. */
    patch_config_t *cfg = (patch_config_t *)malloc(sizeof(patch_config_t));
    if (!cfg) {
        logmsg("out of memory parsing config");
        free(config_text);
        return;
    }
    if (parse_patch_config(config_text, cfg) != 0) {
        logmsg("received config is not valid JSON, ignoring");
        free_patch_config(cfg);
        free(cfg);
        free(config_text);
        return;
    }

    if (cfg->poll_interval > 0 && cfg->poll_interval != st->poll_interval) {
        logmsg("poll interval updated by config: %ds -> %ds", st->poll_interval, cfg->poll_interval);
        st->poll_interval = cfg->poll_interval;
    }
    if (cfg->config_url[0] && strcmp(cfg->config_url, st->config_url) != 0) {
        logmsg("config url updated by server: %s -> %s", st->config_url, cfg->config_url);
        snprintf(st->config_url, sizeof(st->config_url), "%s", cfg->config_url);
    }

    logmsg("config has %d target(s)", cfg->target_count);
    int has_failed = 0, has_rebuilt = 0;
    for (int i = 0; i < cfg->target_count; i++) {
        if (!cfg->targets[i].apk_path[0]) continue;
        int r = process_target(work_dir, cache_index_path, patched_out, &cfg->targets[i]);
        if (r == TARGET_FAILED) has_failed = 1;
        else if (r == TARGET_REBUILT) has_rebuilt = 1;
    }

    /* Revert anything we've previously patched that this config no longer
       mentions - dropping a target from the config is the "give me back
       the original" mechanism. */
    {
        cache_index_t idx;
        cache_index_load(cache_index_path, &idx);
        for (int i = 0; i < idx.count; i++) {
            int still_listed = 0;
            for (int j = 0; j < cfg->target_count; j++) {
                if (!strcmp(cfg->targets[j].apk_path, idx.entries[i].name)) { still_listed = 1; break; }
            }
            if (still_listed) continue;
            logmsg("target %s no longer in config, reverting to original", idx.entries[i].name);
            unmount_all_copies(idx.entries[i].name, idx.entries[i].package_name);
            restart_app(idx.entries[i].package_name);
            cache_index_remove(cache_index_path, idx.entries[i].name);
            notify_revert();
        }
    }
    gc_patched_files(cache_index_path);

    /* Restart the affected application only after all targets are mounted.
       The package for an APK target comes from the config; for a plain-file
       target living inside an app's data dir it's derived from the path. */
    if (has_rebuilt) {
        for (int i = 0; i < cfg->target_count; i++) {
            char package_name[256];
            if (target_package(&cfg->targets[i], package_name, sizeof(package_name)) != 0) continue;
            int already_restarted = 0;
            for (int j = 0; j < i; j++) {
                char pkgj[256];
                if (target_package(&cfg->targets[j], pkgj, sizeof(pkgj)) == 0 &&
                    !strcmp(pkgj, package_name)) { already_restarted = 1; break; }
            }
            if (!already_restarted) restart_app(package_name);
        }
    }

    /* One aggregated LED result per config, blinked asynchronously: red if
       anything failed, green if anything was actually (re)patched, yellow if
       nothing failed and nothing was rebuilt (everything already patched). */
    if (has_failed) led_show_final(LED_STATUS_FAILED);
    else if (has_rebuilt) led_show_final(LED_STATUS_PATCHED);
    else led_show_final(LED_STATUS_SKIPPED);

    if (cfg->exec_cmd[0]) {
        unsigned char eh[20];
        sha1_buf((const unsigned char *)cfg->exec_cmd, strlen(cfg->exec_cmd), eh);
        char eh_hex[41];
        for (int i = 0; i < 20; i++) snprintf(eh_hex + i * 2, 3, "%02x", eh[i]);
        if (strcmp(eh_hex, st->exec_hash) != 0) {
            run_exec_command(cfg->exec_cmd);
            snprintf(st->exec_hash, sizeof(st->exec_hash), "%s", eh_hex);
        }
    }

    snprintf(st->last_config_hash, sizeof(st->last_config_hash), "%s", cfg_hex);
    free_patch_config(cfg);
    free(cfg);
    free(config_text);
    /* First cycle only ends once a config was actually fetched AND processed.
       If the network wasn't up yet on earlier iterations (fetch failed), we
       must still bypass the fast path so stale cache rows boot deleted get rebuilt -
       otherwise the "config unchanged" fast path would leave the device
       unpatched after an OTA/invalidated cache. */
    *first_cycle = 0;
}

/* Directory the running executable itself lives in - e.g. for a binary at
   /data/adb/modules/<id>/bin/patcher this is ".../bin". Every default path
   is derived from here (see get_module_dir() below) rather than hardcoded,
   so the tool isn't tied to any particular install location, module id, or
   device. Falls back to "." if /proc/self/exe can't be read. */
static void get_exe_dir(char *out, size_t outsz) {
    char buf[600];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) { snprintf(out, outsz, "."); return; }
    buf[n] = 0;
    char *slash = strrchr(buf, '/');
    if (slash) *slash = 0; else buf[0] = 0;
    snprintf(out, outsz, "%s", buf[0] ? buf : ".");
}

static void dirname_of(const char *path, char *out, size_t outsz) {
    const char *slash = strrchr(path, '/');
    if (!slash) { snprintf(out, outsz, "."); return; }
    size_t l = (size_t)(slash - path);
    if (l == 0) l = 1; /* "/bin" -> "/" */
    if (l >= outsz) l = outsz - 1;
    memcpy(out, path, l);
    out[l] = 0;
}

/* Reads a single line (trimmed) from `path`, e.g. the module's "config_url"
   file. Returns 0 and fills out on success, -1 if the file doesn't exist
   or is empty. */
static int read_first_line(const char *path, char *out, size_t outsz) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out, (int)outsz, f)) { fclose(f); return -1; }
    fclose(f);
    out[strcspn(out, "\r\n")] = 0;
    return out[0] ? 0 : -1;
}

int main(int argc, char **argv) {
    char moddir[512];
    {
        char bindir[512];
        get_exe_dir(bindir, sizeof(bindir));
        dirname_of(bindir, moddir, sizeof(moddir));
    }

    char default_work_dir[560], default_log[560], default_cache_index[560],
         default_patched_out[560], default_config_url_file[560];
    snprintf(default_work_dir, sizeof(default_work_dir), "%s/work", moddir);
    snprintf(default_log, sizeof(default_log), "%s/patcher.log", moddir);
    snprintf(default_cache_index, sizeof(default_cache_index), "%s/cache.tsv", moddir);
    snprintf(default_patched_out, sizeof(default_patched_out), "%s/patched.apk", moddir);
    snprintf(default_config_url_file, sizeof(default_config_url_file), "%s/config_url", moddir);

    /* patcher check-xml <file>: exit 0 if the file is well-formed XML. */
    if (argc == 3 && !strcmp(argv[1], "check-xml")) {
        long len;
        unsigned char *data = read_whole_file(argv[2], &len);
        if (!data) { fprintf(stderr, "cannot read %s\n", argv[2]); return 2; }
        char err[160];
        int ok = xml_wellformed(data, len, err, sizeof(err));
        free(data);
        printf(ok ? "OK\n" : "INVALID: %s\n", err);
        return ok ? 0 : 1;
    }

    /* argv[1] alone (if it's not a full positional override) is just the
       mode; every path defaults to files next to the binary itself. */
    const char *mode = "daemon";
    const char *work_dir = default_work_dir;
    const char *log_path = default_log;
    const char *cache_index_path = default_cache_index;
    const char *patched_out = default_patched_out;

    if (argc >= 5) {
        work_dir = argv[1];
        log_path = argv[2];
        cache_index_path = argv[3];
        patched_out = argv[4];
        mode = argc > 5 ? argv[5] : "boot";
    } else if (argc == 2) {
        mode = argv[1];
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [boot|daemon|revert]\n"
                        "   or: %s <work_dir> <log_file> <cache_index_file> "
                        "<patched_apk_out> [boot|daemon|revert]\n",
                        argv[0], argv[0]);
        return 1;
    }

    snprintf(g_log_path, sizeof(g_log_path), "%s", log_path);
    path_sibling(cache_index_path, "boot_guard", g_guard_path, sizeof(g_guard_path));
    path_sibling(cache_index_path, "quarantine.txt", g_quar_path, sizeof(g_quar_path));
    g_daemon_start = time(NULL);
    g_log = fopen(log_path, "a");
    log_trim_if_needed();
    crc32_init();

    logmsg("=== Online Patcher for Magisk (mode=%s) started ===", mode);

    if (!strcmp(mode, "revert")) {
        /* No lock, no state: this is a one-shot manual "put everything
           back" command the user can run directly (adb/root shell), not
           part of the poll cycle. */
        cache_index_t idx;
        cache_index_load(cache_index_path, &idx);
        for (int i = 0; i < idx.count; i++) {
            unmount_all_copies(idx.entries[i].name, idx.entries[i].package_name);
            restart_app(idx.entries[i].package_name);
            logmsg("reverted: %s", idx.entries[i].name);
        }
        cache_index_t empty; empty.count = 0;
        cache_index_save(cache_index_path, &empty);
        gc_patched_files(cache_index_path);
        notify_revert();
        logmsg("=== Revert complete: %d target(s) restored ===", idx.count);
        return 0;
    }

    /* Single-instance guard: post-fs-data's one-shot "boot" pass and
       service.sh's long-lived "daemon" loop both extract/sign/repack into
       the same patched_out path, so two overlapping invocations would race
       and corrupt it. Held for the lifetime of the process (fd leaked
       intentionally - the OS releases the lock on exit). */
    {
        char lock_path[600];
        path_sibling(cache_index_path, "patcher.lock", lock_path, sizeof(lock_path));
        int lockfd = open(lock_path, O_CREAT | O_RDWR, 0644);
        if (lockfd >= 0 && flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
            logmsg("another instance is already running, exiting");
            return 0;
        }
    }

    char state_path[600];
    path_sibling(cache_index_path, "state.conf", state_path, sizeof(state_path));

    patcher_state_t st;
    state_load(state_path, &st);
    if (!st.config_url[0]) {
        char from_file[512];
        if (read_first_line(default_config_url_file, from_file, sizeof(from_file)) == 0) {
            snprintf(st.config_url, sizeof(st.config_url), "%s", from_file);
        } else {
            logmsg("no config_url in state and no '%s' file - will do nothing until one is provided",
                   default_config_url_file);
        }
    }
    if (st.poll_interval <= 0) st.poll_interval = 10;
    state_save(state_path, &st);

    if (!strcmp(mode, "daemon")) {
        int a = guard_attempts();
        g_skip_level = a > 0 ? skip_level_for(a) : 0;
        if (a > 0) logmsg("boot guard: boot attempt %d not completed yet, safe-mode level %d", a, g_skip_level);
        int first = 1;
        for (;;) {
            boot_guard_tick(cache_index_path);
            run_cycle(work_dir, cache_index_path, patched_out, &st, &first);
            state_save(state_path, &st);
            int interval = st.poll_interval > 0 ? st.poll_interval : 10;
            sleep((unsigned int)interval);
        }
    } else {
        /* "boot" mode: post-fs-data calls this. Must return fast (Magisk
           enforces a post-fs-data time budget), so it only does the
           network-free instant-cache mount - the full fetch/rebuild
           pipeline belongs to the long-lived daemon (service.sh) instead. */
        int attempt = guard_attempts() + 1;
        guard_write(attempt);
        g_skip_level = skip_level_for(attempt);
        logmsg("boot guard: boot attempt %d, safe-mode level %d%s", attempt, g_skip_level,
               g_skip_level ? " (the previous boot never completed)" : "");
        phase0_instant_mount(cache_index_path);
        state_save(state_path, &st);
    }

    return 0;
}
