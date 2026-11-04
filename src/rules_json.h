#pragma once
// Minimal parser for the patch config:
//   {
//     "poll_interval": 10, "config_url": "...", "exec": "...",
//     "targets": [
//       { "apk_path": "...", "package_name": "...",
//         "exec_before": "...", "exec_after": "...",
//         "rules": [ { "file_name": "...", "pattern": "...", "replace": "..." }, ... ] },
//       { "file_create": "/system/etc/.../new.file", "content_hex": "...",
//         "mode": "644", "context": "u:object_r:...:s0" },
//       ...
//     ]
//   }
//
// Deliberately narrow: just enough JSON to read this specific shape. Not a
// general JSON parser. Any target apk_path missing from a freshly-received
// config (vs. what was previously seen) is what run_cycle() uses to decide
// what to revert - this parser just needs to expose the target list as-is.

#include <stdlib.h>
#include <string.h>

#define MAX_TARGETS 8

/* pattern/replace can each be given as a plain JSON string OR as a
   *_hex field (even-length hex digits, decoded to raw bytes - needed for
   binary content that can't round-trip through a JSON string, e.g. bytes
   containing NUL). replace can additionally come from replace_file (a
   device-local path whose content is read at apply time), for
   replacements too large/binary to comfortably inline in the config JSON
   at all (values are resolved in patcher.c's resolve_pattern()/
   resolve_replace(), not here - this parser just carries whichever raw
   fields were present). Exactly one of pattern/pattern_hex and one of
   replace/replace_hex/replace_file is expected per rule; if more than one
   is given, resolve_*() picks a fixed precedence (hex over plain, file
   over hex over plain). */
/* pattern_hex / replace / replace_hex are heap strings of whatever length
   the config carries (a binary AndroidManifest.xml chunk is ~15 KB, i.e.
   ~30k hex digits). They're never NULL after a successful parse, and are
   freed by free_patch_config(). */
typedef struct {
    char file_name[256];
    char pattern[512];
    char *pattern_hex;
    char *replace;
    char *replace_hex;
    char replace_file[512];
} patch_rule_t;

/* rules is grown dynamically (no fixed cap) - a config may carry as many
   rules per target as it likes. Owned by the rule_set_t; freed via
   free_patch_config(). */
typedef struct {
    patch_rule_t *rules;
    int count;
    int cap;
} rule_set_t;

static const char *json_skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* Parses a JSON string literal starting at *p (which must point at the
   opening quote). Writes the unescaped value into out (size outsz) and
   returns a pointer just past the closing quote, or NULL on malformed input. */
static const char *json_parse_string(const char *p, char *out, int outsz) {
    if (*p != '"') return NULL;
    p++;
    int i = 0;
    while (*p && *p != '"') {
        char c = *p;
        if (c == '\\' && p[1]) {
            p++;
            switch (*p) {
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case 'r': c = '\r'; break;
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                case '/': c = '/'; break;
                default: c = *p; break;
            }
        }
        if (i < outsz - 1) out[i++] = c;
        p++;
    }
    out[i] = 0;
    if (*p != '"') return NULL;
    return p + 1;
}

/* Like json_parse_string(), but allocates a buffer exactly big enough for the
   unescaped value (no length limit). *out is malloc'd; caller frees. Returns
   a pointer just past the closing quote, or NULL on malformed input / OOM. */
static const char *json_parse_string_dyn(const char *p, char **out) {
    if (*p != '"') return NULL;
    const char *q = p + 1;
    size_t n = 0;
    while (*q && *q != '"') {
        if (*q == '\\' && q[1]) q++;
        q++;
        n++;
    }
    if (*q != '"') return NULL;
    char *buf = (char *)malloc(n + 1);
    if (!buf) return NULL;
    json_parse_string(p, buf, (int)(n + 1));
    *out = buf;
    return q + 1;
}

static const char *json_parse_number(const char *p, long *out) {
    p = json_skip_ws(p);
    char *end;
    long v = strtol(p, &end, 10);
    if (end == p) return NULL;
    *out = v;
    return end;
}

/* Parses one { "file_name": "...", "pattern": "...", "replace": "..." }
   object into `rule`. Keys may appear in any order; unknown keys are
   skipped (their string value is read and discarded). Returns a pointer
   just past the closing '}', or NULL on malformed input. */
static void free_rule_fields(patch_rule_t *rule) {
    free(rule->pattern_hex);
    free(rule->replace);
    free(rule->replace_hex);
    rule->pattern_hex = rule->replace = rule->replace_hex = NULL;
}

static const char *json_parse_rule_object(const char *p, patch_rule_t *rule) {
    memset(rule, 0, sizeof(*rule));
    p = json_skip_ws(p);
    if (*p != '{') return NULL;
    p++;

    for (;;) {
        p = json_skip_ws(p);
        if (*p == '}') goto done;
        if (*p != '"') goto fail;

        char key[64];
        p = json_parse_string(p, key, sizeof(key));
        if (!p) goto fail;

        p = json_skip_ws(p);
        if (*p != ':') goto fail;
        p++;
        p = json_skip_ws(p);

        char *value = NULL;
        p = json_parse_string_dyn(p, &value);
        if (!p) goto fail;

        if (!strcmp(key, "file_name") || !strcmp(key, "file") || !strcmp(key, "mask")) {
            snprintf(rule->file_name, sizeof(rule->file_name), "%s", value);
        } else if (!strcmp(key, "pattern") || !strcmp(key, "from")) {
            snprintf(rule->pattern, sizeof(rule->pattern), "%s", value);
        } else if (!strcmp(key, "replace_file")) {
            snprintf(rule->replace_file, sizeof(rule->replace_file), "%s", value);
        } else if (!strcmp(key, "pattern_hex")) {
            free(rule->pattern_hex); rule->pattern_hex = value; value = NULL;
        } else if (!strcmp(key, "replace") || !strcmp(key, "to")) {
            free(rule->replace); rule->replace = value; value = NULL;
        } else if (!strcmp(key, "replace_hex")) {
            free(rule->replace_hex); rule->replace_hex = value; value = NULL;
        }
        /* unknown keys: value already consumed, just ignore */
        free(value);

        p = json_skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') goto done;
        goto fail;
    }

done:
    if (*p == '}') p++;
    if (!rule->pattern_hex) rule->pattern_hex = strdup("");
    if (!rule->replace) rule->replace = strdup("");
    if (!rule->replace_hex) rule->replace_hex = strdup("");
    if (!rule->pattern_hex || !rule->replace || !rule->replace_hex) { free_rule_fields(rule); return NULL; }
    return p;
fail:
    free_rule_fields(rule);
    return NULL;
}

/* Parses a JSON array of rule objects starting at *p (the opening '[').
   Returns a pointer just past the closing ']' (rs->count may be 0 for an
   empty array), or NULL on malformed input. */
static const char *json_parse_rules_array(const char *p, rule_set_t *rs) {
    rs->rules = NULL;
    rs->count = 0;
    rs->cap = 0;
    p = json_skip_ws(p);
    if (*p != '[') return NULL;
    p++;

    for (;;) {
        p = json_skip_ws(p);
        if (*p == ']') return p + 1;

        if (rs->count >= rs->cap) {
            int newcap = rs->cap ? rs->cap * 2 : 8;
            patch_rule_t *nr = (patch_rule_t *)realloc(rs->rules, (size_t)newcap * sizeof(patch_rule_t));
            if (!nr) return NULL;
            rs->rules = nr;
            rs->cap = newcap;
        }
        p = json_parse_rule_object(p, &rs->rules[rs->count]);
        if (!p) return NULL;
        rs->count++;

        p = json_skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == ']') return p + 1;
        return NULL;
    }
}

typedef struct {
    char apk_path[512];
    char package_name[256];
    char type[16];      /* "apk" (default), "file" or "create" - see process_target() */
    /* Optional root shell commands run around an actual (re)patch of this
       target - not on a cached reuse: exec_before right before the rebuild
       starts, exec_after once the patched build is mounted (before the app
       is restarted). Empty = none. */
    char exec_before[1024];
    char exec_after[1024];
    /* "file_create" targets only (type == "create"): the new file's whole
       content as hex (a heap string like pattern_hex - PEM/hex blobs run to
       kilobytes), plus the mode (octal string, "644" - empty = 644) and an
       optional SELinux context to set on the created file. Applied by
       process_create_target() in patcher.c; rules/exec_* are ignored for
       this target type. */
    char *content_hex;
    char mode_str[8];
    char context[256];
    rule_set_t rules;
} target_config_t;

/* Parses one { "apk_path": "...", "package_name": "...", "exec_before": "...",
   "exec_after": "...", "rules": [...] }
   object. Keys may appear in any order. Returns a pointer just past the
   closing '}', or NULL on malformed input (apk_path/package_name missing is
   not a parse error - caller decides whether that target is usable). */
static const char *json_parse_target_object(const char *p, target_config_t *t) {
    memset(t, 0, sizeof(*t));
    p = json_skip_ws(p);
    if (*p != '{') return NULL;
    p++;

    for (;;) {
        p = json_skip_ws(p);
        if (*p == '}') return p + 1;
        if (*p != '"') return NULL;

        char key[64];
        p = json_parse_string(p, key, sizeof(key));
        if (!p) return NULL;

        p = json_skip_ws(p);
        if (*p != ':') return NULL;
        p++;
        p = json_skip_ws(p);

        if (!strcmp(key, "rules")) {
            p = json_parse_rules_array(p, &t->rules);
            if (!p) return NULL;
        } else if (!strcmp(key, "content_hex")) {
            /* Heap string: the created file's content is kilobytes of hex,
               far past the fixed 1024-byte value buffer below. */
            char *value = NULL;
            p = json_parse_string_dyn(p, &value);
            if (!p) return NULL;
            free(t->content_hex);
            t->content_hex = value;
        } else {
            char value[1024];
            const char *after = json_parse_string(p, value, sizeof(value));
            if (!after) return NULL;
            p = after;
            /* Which key is used says what kind of target this is - no
               separate "type" field, no extension sniffing. "apk_path" ->
               ZIP extract/sign/repack pipeline. "file_path" -> plain
               copy+replace+mount, no ZIP, no signing. "file_create" ->
               brand-new file placed into the module's magic-mount tree,
               content/mode/context straight from the config. */
            if (!strcmp(key, "apk_path")) {
                snprintf(t->apk_path, sizeof(t->apk_path), "%s", value);
                snprintf(t->type, sizeof(t->type), "apk");
            } else if (!strcmp(key, "file_path")) {
                snprintf(t->apk_path, sizeof(t->apk_path), "%s", value);
                snprintf(t->type, sizeof(t->type), "file");
            } else if (!strcmp(key, "file_create")) {
                snprintf(t->apk_path, sizeof(t->apk_path), "%s", value);
                snprintf(t->type, sizeof(t->type), "create");
            } else if (!strcmp(key, "package_name")) {
                snprintf(t->package_name, sizeof(t->package_name), "%s", value);
            } else if (!strcmp(key, "exec_before")) {
                snprintf(t->exec_before, sizeof(t->exec_before), "%s", value);
            } else if (!strcmp(key, "exec_after")) {
                snprintf(t->exec_after, sizeof(t->exec_after), "%s", value);
            } else if (!strcmp(key, "mode")) {
                snprintf(t->mode_str, sizeof(t->mode_str), "%s", value);
            } else if (!strcmp(key, "context")) {
                snprintf(t->context, sizeof(t->context), "%s", value);
            }
        }

        p = json_skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') return p + 1;
        return NULL;
    }
}

typedef struct {
    int poll_interval;         /* seconds; 0 = not present in this config */
    char config_url[512];      /* lets the server redirect future polls elsewhere */
    char exec_cmd[1024];       /* shell command to run as root; empty = none */
    target_config_t targets[MAX_TARGETS];
    int target_count;
} patch_config_t;

/* Parses the top-level config object. Returns 0 on success (target_count
   may be 0 for `"targets": []`, meaning "nothing to patch right now" - not
   an error), -1 if "targets" is missing/malformed or the JSON itself is
   malformed. */
static int parse_patch_config(const char *json, patch_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    const char *key;
    const char *p;

    key = strstr(json, "\"poll_interval\"");
    if (key) {
        p = strchr(key, ':');
        if (p) {
            p = json_skip_ws(p + 1);
            long v;
            if (json_parse_number(p, &v) && v > 0) cfg->poll_interval = (int)v;
        }
    }

    key = strstr(json, "\"config_url\"");
    if (key) {
        p = strchr(key, ':');
        if (p) {
            p = json_skip_ws(p + 1);
            json_parse_string(p, cfg->config_url, sizeof(cfg->config_url));
        }
    }

    key = strstr(json, "\"exec\"");
    if (key) {
        p = strchr(key, ':');
        if (p) {
            p = json_skip_ws(p + 1);
            json_parse_string(p, cfg->exec_cmd, sizeof(cfg->exec_cmd));
        }
    }

    key = strstr(json, "\"targets\"");
    if (!key) return -1;
    p = strchr(key, ':');
    if (!p) return -1;
    p = json_skip_ws(p + 1);
    if (*p != '[') return -1;
    p++;

    cfg->target_count = 0;
    for (;;) {
        p = json_skip_ws(p);
        if (*p == ']') break;

        if (cfg->target_count >= MAX_TARGETS) return -1;
        p = json_parse_target_object(p, &cfg->targets[cfg->target_count]);
        if (!p) return -1;
        cfg->target_count++;

        p = json_skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == ']') break;
        return -1;
    }

    return 0;
}

/* Frees the per-target dynamically-grown rule arrays. Safe to call on a
   cfg that was memset to zero and/or only partially parsed (each target's
   rules pointer is NULL until its rules array is allocated), so it also
   cleans up after a mid-parse failure. Does not free cfg itself. */
static void free_patch_config(patch_config_t *cfg) {
    if (!cfg) return;
    for (int i = 0; i < MAX_TARGETS; i++) {
        for (int k = 0; k < cfg->targets[i].rules.count; k++)
            free_rule_fields(&cfg->targets[i].rules.rules[k]);
        free(cfg->targets[i].rules.rules);
        cfg->targets[i].rules.rules = NULL;
        cfg->targets[i].rules.count = 0;
        cfg->targets[i].rules.cap = 0;
        free(cfg->targets[i].content_hex);
        cfg->targets[i].content_hex = NULL;
    }
}
