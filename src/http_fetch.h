#pragma once
// Minimal HTTPS GET client for a standalone native binary.
//
// Android's NDK does not expose libssl/libcrypto for direct linking (Google
// removed public OpenSSL headers/libs from the NDK), so this dlopen()s the
// system's own BoringSSL libraries at runtime instead. Every Android device
// (rooted or not) ships libssl.so/libcrypto.so under /system or the
// conscrypt apex - it's what the whole OS's TLS stack runs on - so this adds
// no external dependency beyond what's already guaranteed present, and
// avoids hand-rolling a TLS stack.
//
// Certificate verification is intentionally left disabled: this tool talks
// to a user-controlled MITM/testing endpoint, not a public API where chain
// validation would matter.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

typedef void SSL_CTX;
typedef void SSL;
typedef void SSL_METHOD;

typedef SSL_METHOD *(*fn_TLS_client_method)(void);
typedef SSL_CTX *(*fn_SSL_CTX_new)(const SSL_METHOD *);
typedef void (*fn_SSL_CTX_set_verify)(SSL_CTX *, int, void *);
typedef SSL *(*fn_SSL_new)(SSL_CTX *);
typedef int (*fn_SSL_set_fd)(SSL *, int);
typedef int (*fn_SSL_set_tlsext_host_name)(SSL *, const char *);
typedef int (*fn_SSL_connect)(SSL *);
typedef int (*fn_SSL_write)(SSL *, const void *, int);
typedef int (*fn_SSL_read)(SSL *, void *, int);
typedef void (*fn_SSL_free)(SSL *);
typedef void (*fn_SSL_CTX_free)(SSL_CTX *);
typedef int (*fn_SSL_get_error)(const SSL *, int);

typedef struct {
    void *libssl;
    void *libcrypto;
    fn_TLS_client_method TLS_client_method;
    fn_SSL_CTX_new SSL_CTX_new;
    fn_SSL_CTX_set_verify SSL_CTX_set_verify;
    fn_SSL_new SSL_new;
    fn_SSL_set_fd SSL_set_fd;
    fn_SSL_set_tlsext_host_name SSL_set_tlsext_host_name_f;
    fn_SSL_connect SSL_connect;
    fn_SSL_write SSL_write;
    fn_SSL_read SSL_read;
    fn_SSL_free SSL_free;
    fn_SSL_CTX_free SSL_CTX_free;
    fn_SSL_get_error SSL_get_error;
    int ok;
} tls_lib_t;

static tls_lib_t g_tls;

static int tls_lib_load(void) {
    memset(&g_tls, 0, sizeof(g_tls));

    const char *ssl_paths[] = {
        "libssl.so", "/system/lib64/libssl.so", "/apex/com.android.conscrypt/lib64/libssl.so", NULL
    };
    const char *crypto_paths[] = {
        "libcrypto.so", "/system/lib64/libcrypto.so", "/apex/com.android.conscrypt/lib64/libcrypto.so", NULL
    };

    for (int i = 0; ssl_paths[i] && !g_tls.libssl; i++) g_tls.libssl = dlopen(ssl_paths[i], RTLD_NOW | RTLD_GLOBAL);
    for (int i = 0; crypto_paths[i] && !g_tls.libcrypto; i++) g_tls.libcrypto = dlopen(crypto_paths[i], RTLD_NOW | RTLD_GLOBAL);

    if (!g_tls.libssl || !g_tls.libcrypto) return -1;

    g_tls.TLS_client_method = (fn_TLS_client_method)dlsym(g_tls.libssl, "TLS_client_method");
    if (!g_tls.TLS_client_method) g_tls.TLS_client_method = (fn_TLS_client_method)dlsym(g_tls.libssl, "SSLv23_client_method");
    g_tls.SSL_CTX_new = (fn_SSL_CTX_new)dlsym(g_tls.libssl, "SSL_CTX_new");
    g_tls.SSL_CTX_set_verify = (fn_SSL_CTX_set_verify)dlsym(g_tls.libssl, "SSL_CTX_set_verify");
    g_tls.SSL_new = (fn_SSL_new)dlsym(g_tls.libssl, "SSL_new");
    g_tls.SSL_set_fd = (fn_SSL_set_fd)dlsym(g_tls.libssl, "SSL_set_fd");
    g_tls.SSL_set_tlsext_host_name_f = (fn_SSL_set_tlsext_host_name)dlsym(g_tls.libssl, "SSL_set_tlsext_host_name");
    g_tls.SSL_connect = (fn_SSL_connect)dlsym(g_tls.libssl, "SSL_connect");
    g_tls.SSL_write = (fn_SSL_write)dlsym(g_tls.libssl, "SSL_write");
    g_tls.SSL_read = (fn_SSL_read)dlsym(g_tls.libssl, "SSL_read");
    g_tls.SSL_free = (fn_SSL_free)dlsym(g_tls.libssl, "SSL_free");
    g_tls.SSL_CTX_free = (fn_SSL_CTX_free)dlsym(g_tls.libssl, "SSL_CTX_free");
    g_tls.SSL_get_error = (fn_SSL_get_error)dlsym(g_tls.libssl, "SSL_get_error");

    g_tls.ok = g_tls.TLS_client_method && g_tls.SSL_CTX_new && g_tls.SSL_new &&
               g_tls.SSL_set_fd && g_tls.SSL_connect && g_tls.SSL_write &&
               g_tls.SSL_read && g_tls.SSL_free && g_tls.SSL_CTX_free;
    return g_tls.ok ? 0 : -1;
}

/* Connects to host:443, sends a plain HTTP/1.1 GET over TLS, returns the
   response body (headers stripped) as a malloc'd NUL-terminated buffer, or
   NULL on any failure. `timeout_sec` bounds the whole operation. If
   `out_status` is non-NULL, it's set to the parsed HTTP status code (0 if
   the status line couldn't be parsed) - a 200 response and a 404 error page
   both come back as a non-NULL body, so callers that care about the
   difference need this. */

/* Reassembles a chunked HTTP body (everything after the headers) into a
   malloc'd, NUL-terminated string. Tolerates a truncated stream: whatever
   complete data was received is returned. */
static char *http_dechunk(const char *body) {
    size_t cap = strlen(body) + 1;
    char *out = (char *)malloc(cap);
    if (!out) return NULL;
    size_t o = 0;
    const char *p = body;
    for (;;) {
        char *end;
        unsigned long sz = strtoul(p, &end, 16);
        if (end == p) break;
        const char *eol = strstr(end, "\r\n");
        if (!eol) break;
        p = eol + 2;
        if (sz == 0) break;
        size_t avail = strlen(p);
        if (sz > avail) sz = avail;
        memcpy(out + o, p, sz);
        o += sz;
        p += sz;
        if (p[0] == '\r' && p[1] == '\n') p += 2;
        else break;
    }
    out[o] = 0;
    return out;
}
static char *https_get(const char *host, const char *path, int timeout_sec, int *out_status) {
    if (out_status) *out_status = 0;
    if (!g_tls.ok && tls_lib_load() != 0) return NULL;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &res) != 0 || !res) return NULL;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return NULL; }

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return NULL;
    }
    freeaddrinfo(res);

    SSL_CTX *ctx = g_tls.SSL_CTX_new(g_tls.TLS_client_method());
    if (!ctx) { close(fd); return NULL; }
    if (g_tls.SSL_CTX_set_verify) g_tls.SSL_CTX_set_verify(ctx, 0 /* SSL_VERIFY_NONE */, NULL);

    SSL *ssl = g_tls.SSL_new(ctx);
    if (!ssl) { g_tls.SSL_CTX_free(ctx); close(fd); return NULL; }

    g_tls.SSL_set_fd(ssl, fd);
    if (g_tls.SSL_set_tlsext_host_name_f) g_tls.SSL_set_tlsext_host_name_f(ssl, host);

    if (g_tls.SSL_connect(ssl) != 1) {
        g_tls.SSL_free(ssl);
        g_tls.SSL_CTX_free(ctx);
        close(fd);
        return NULL;
    }

    char req[1024];
    snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: online-patcher-magisk/1.0\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host);

    if (g_tls.SSL_write(ssl, req, (int)strlen(req)) <= 0) {
        g_tls.SSL_free(ssl);
        g_tls.SSL_CTX_free(ctx);
        close(fd);
        return NULL;
    }

    size_t cap = 65536, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { g_tls.SSL_free(ssl); g_tls.SSL_CTX_free(ctx); close(fd); return NULL; }

    for (;;) {
        if (len + 4096 > cap) { cap *= 2; buf = (char *)realloc(buf, cap); }
        int n = g_tls.SSL_read(ssl, buf + len, (int)(cap - len - 1));
        if (n <= 0) break;
        len += (size_t)n;
    }
    buf[len] = 0;

    g_tls.SSL_free(ssl);
    g_tls.SSL_CTX_free(ctx);
    close(fd);

    if (out_status) {
        /* "HTTP/1.1 200 OK\r\n..." */
        const char *sp = strchr(buf, ' ');
        if (sp) *out_status = atoi(sp + 1);
    }

    /* strip HTTP headers: body starts after the first blank line */
    char *body = strstr(buf, "\r\n\r\n");
    if (!body) { free(buf); return NULL; }
    body += 4;

    /* The server may answer with "Transfer-Encoding: chunked" (Apache does
       for generated responses): the body is then a series of
       "<hex size> CRLF <data> CRLF" pieces that must be reassembled, or the
       chunk-size lines end up in the middle of the JSON. */
    char *result;
    {
        size_t hl = (size_t)(body - buf);
        char *hdr = (char *)malloc(hl + 1);
        int chunked = 0;
        if (hdr) {
            for (size_t i = 0; i < hl; i++) hdr[i] = (char)((buf[i] >= 'A' && buf[i] <= 'Z') ? buf[i] + 32 : buf[i]);
            hdr[hl] = 0;
            const char *te = strstr(hdr, "\ntransfer-encoding:");
            if (te) {
                const char *eol = strstr(te + 1, "\r\n");
                const char *ch = strstr(te, "chunked");
                chunked = ch && (!eol || ch < eol);
            }
            free(hdr);
        }
        result = chunked ? http_dechunk(body) : strdup(body);
    }
    free(buf);
    return result;
}
