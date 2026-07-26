#pragma once
// Small persisted key=value state file, sits next to the cache index and
// survives both process restarts and reboots. Lets the server steer the
// running daemon (change the poll URL/interval), keeps the daemon from
// re-running an unchanged "exec" command, and - the main point of
// last_config_hash - lets a poll tick recognize "the config is byte-identical
// to what I already applied" from a cheap string compare, without ever
// touching (fingerprinting) the target apk.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char config_url[512];
    int poll_interval;          /* seconds; <=0 means "unset, use default" */
    char exec_hash[41];         /* sha1 of the last "exec" command actually run */
    char last_config_hash[41];  /* sha1 of the last config text successfully processed */
} patcher_state_t;

static void state_load(const char *path, patcher_state_t *st) {
    memset(st, 0, sizeof(*st));
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[900];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        const char *key = line;
        const char *val = eq + 1;
        if (!strcmp(key, "config_url")) snprintf(st->config_url, sizeof(st->config_url), "%s", val);
        else if (!strcmp(key, "poll_interval")) st->poll_interval = atoi(val);
        else if (!strcmp(key, "exec_hash")) snprintf(st->exec_hash, sizeof(st->exec_hash), "%s", val);
        else if (!strcmp(key, "last_config_hash")) snprintf(st->last_config_hash, sizeof(st->last_config_hash), "%s", val);
    }
    fclose(f);
}

static void state_save(const char *path, const patcher_state_t *st) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "config_url=%s\n", st->config_url);
    fprintf(f, "poll_interval=%d\n", st->poll_interval);
    fprintf(f, "exec_hash=%s\n", st->exec_hash);
    fprintf(f, "last_config_hash=%s\n", st->last_config_hash);
    fclose(f);
}

/* Computes the sibling path "<dir of base_path>/<filename>". */
static void path_sibling(const char *base_path, const char *filename, char *out, size_t outsz) {
    const char *slash = strrchr(base_path, '/');
    if (slash) {
        size_t dirlen = (size_t)(slash - base_path);
        if (dirlen >= outsz) dirlen = outsz - 1;
        memcpy(out, base_path, dirlen);
        snprintf(out + dirlen, outsz - dirlen, "/%s", filename);
    } else {
        snprintf(out, outsz, "%s", filename);
    }
}
