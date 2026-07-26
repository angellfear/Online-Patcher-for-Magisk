#pragma once
// Persistent local cache registry, survives reboots:
//   name<TAB>package_name<TAB>orig_sha1<TAB>patched_sha1<TAB>config_sha1<TAB>patched_file_path
//
// `name` identifies the target apk (its path) - one row per patched target,
// so this naturally supports multiple apks/files at once. Looking up by name
// and comparing orig_sha1 against the current on-disk content is what lets
// the patcher apply a known-good patched APK immediately at boot, before any
// network is available. `package_name` is kept alongside so a revert can
// also unmount any /data/app/<pkg>-*/base.apk copies, not just the row's
// primary path.

#include <stdio.h>
#include <string.h>

#define CACHE_MAX_ENTRIES 32

typedef struct {
    char name[512];
    char package_name[256];
    char orig[41];
    char patched[41];
    char cfg[41];
    char patched_path[512];
} cache_entry_t;

typedef struct {
    cache_entry_t entries[CACHE_MAX_ENTRIES];
    int count;
} cache_index_t;

static int cache_index_load(const char *path, cache_index_t *idx) {
    idx->count = 0;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[2200];
    while (fgets(line, sizeof(line), f) && idx->count < CACHE_MAX_ENTRIES) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0]) continue;
        char *fields[6];
        int nf = 0;
        char *p = line;
        while (nf < 6) {
            char *tab = strchr(p, '\t');
            fields[nf++] = p;
            if (!tab) break;
            *tab = 0;
            p = tab + 1;
        }
        if (nf < 6) continue;
        cache_entry_t *e = &idx->entries[idx->count];
        snprintf(e->name, sizeof(e->name), "%s", fields[0]);
        snprintf(e->package_name, sizeof(e->package_name), "%s", fields[1]);
        snprintf(e->orig, sizeof(e->orig), "%s", fields[2]);
        snprintf(e->patched, sizeof(e->patched), "%s", fields[3]);
        snprintf(e->cfg, sizeof(e->cfg), "%s", fields[4]);
        snprintf(e->patched_path, sizeof(e->patched_path), "%s", fields[5]);
        idx->count++;
    }
    fclose(f);
    return 0;
}

static int cache_index_save(const char *path, const cache_index_t *idx) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    for (int i = 0; i < idx->count; i++) {
        const cache_entry_t *e = &idx->entries[i];
        fprintf(f, "%s\t%s\t%s\t%s\t%s\t%s\n", e->name, e->package_name, e->orig, e->patched, e->cfg, e->patched_path);
    }
    fclose(f);
    return 0;
}

static const cache_entry_t *cache_index_find(const cache_index_t *idx, const char *name) {
    for (int i = 0; i < idx->count; i++) {
        if (!strcmp(idx->entries[i].name, name)) return &idx->entries[i];
    }
    return NULL;
}

/* Inserts or updates (by name) and saves to disk immediately. */
static void cache_index_put(const char *path, const char *name, const char *package_name,
                             const char *orig, const char *patched, const char *cfg,
                             const char *patched_path) {
    cache_index_t idx;
    cache_index_load(path, &idx);

    int found = -1;
    for (int i = 0; i < idx.count; i++) {
        if (!strcmp(idx.entries[i].name, name)) { found = i; break; }
    }
    cache_entry_t *e;
    if (found >= 0) {
        e = &idx.entries[found];
    } else if (idx.count < CACHE_MAX_ENTRIES) {
        e = &idx.entries[idx.count++];
    } else {
        e = &idx.entries[CACHE_MAX_ENTRIES - 1];
    }
    snprintf(e->name, sizeof(e->name), "%s", name);
    snprintf(e->package_name, sizeof(e->package_name), "%s", package_name);
    snprintf(e->orig, sizeof(e->orig), "%s", orig);
    snprintf(e->patched, sizeof(e->patched), "%s", patched);
    snprintf(e->cfg, sizeof(e->cfg), "%s", cfg);
    snprintf(e->patched_path, sizeof(e->patched_path), "%s", patched_path);

    cache_index_save(path, &idx);
}

/* Removes the entry for `name`, if present, and saves. Used when a target
   drops out of the config (revert) or an explicit revert is requested. */
static void cache_index_remove(const char *path, const char *name) {
    cache_index_t idx;
    cache_index_load(path, &idx);
    int w = 0;
    for (int i = 0; i < idx.count; i++) {
        if (strcmp(idx.entries[i].name, name) != 0) {
            if (w != i) idx.entries[w] = idx.entries[i];
            w++;
        }
    }
    idx.count = w;
    cache_index_save(path, &idx);
}
