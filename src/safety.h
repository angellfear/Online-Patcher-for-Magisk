#pragma once
// Sanity checks for patched output, run BEFORE it is ever bind-mounted.
//
// A patch that leaves a system file malformed can wedge the whole boot: e.g.
// a mac_permissions.xml without its closing </policy> sends system_server's
// PackageManager into an endless parse loop, so Android never finishes
// booting, never gets a network, and the patcher can never fetch the fix.
// Catching it here keeps such a file from being mounted in the first place.

#include <stdio.h>
#include <string.h>

#define XML_MAX_DEPTH 64

/* Minimal well-formedness check: tags nest and close correctly, exactly one
   root element, attribute quotes are balanced, comments / CDATA / PI /
   DOCTYPE are terminated. Not a validating parser - entities and attribute
   syntax aren't examined. Returns 1 if well-formed, else 0 with a short
   reason in err. */
static int xml_wellformed(const unsigned char *d, long n, char *err, size_t errsz) {
    struct { long off; int len; } stack[XML_MAX_DEPTH];
    int depth = 0, roots = 0;
    long i = 0;

#define XML_FAIL(...) do { snprintf(err, errsz, __VA_ARGS__); return 0; } while (0)

    while (i < n) {
        if (d[i] != '<') { i++; continue; }

        if (i + 1 >= n) XML_FAIL("file ends inside '<'");

        if (d[i + 1] == '?') {
            long j = i + 2;
            while (j + 1 < n && !(d[j] == '?' && d[j + 1] == '>')) j++;
            if (j + 1 >= n) XML_FAIL("unterminated <? ?> at offset %ld", i);
            i = j + 2;
        } else if (i + 3 < n && !memcmp(d + i, "<!--", 4)) {
            long j = i + 4;
            while (j + 2 < n && memcmp(d + j, "-->", 3) != 0) j++;
            if (j + 2 >= n) XML_FAIL("unterminated comment at offset %ld", i);
            i = j + 3;
        } else if (i + 8 < n && !memcmp(d + i, "<![CDATA[", 9)) {
            long j = i + 9;
            while (j + 2 < n && memcmp(d + j, "]]>", 3) != 0) j++;
            if (j + 2 >= n) XML_FAIL("unterminated CDATA at offset %ld", i);
            i = j + 3;
        } else if (d[i + 1] == '!') {
            long j = i + 2;
            while (j < n && d[j] != '>') j++;
            if (j >= n) XML_FAIL("unterminated <! at offset %ld", i);
            i = j + 1;
        } else if (d[i + 1] == '/') {
            long s = i + 2, j = s;
            while (j < n && d[j] != '>' && d[j] != ' ' && d[j] != '\t' && d[j] != '\r' && d[j] != '\n') j++;
            int len = (int)(j - s);
            while (j < n && d[j] != '>') j++;
            if (j >= n) XML_FAIL("unterminated closing tag at offset %ld", i);
            if (depth == 0) XML_FAIL("closing tag with nothing open at offset %ld", i);
            depth--;
            if (stack[depth].len != len || memcmp(d + stack[depth].off, d + s, (size_t)len) != 0)
                XML_FAIL("closing tag at offset %ld does not match <%.*s>",
                         i, stack[depth].len, d + stack[depth].off);
            i = j + 1;
        } else {
            long s = i + 1, j = s;
            while (j < n && d[j] != '>' && d[j] != '/' && d[j] != ' ' && d[j] != '\t' && d[j] != '\r' && d[j] != '\n') j++;
            int len = (int)(j - s);
            if (len == 0) XML_FAIL("empty tag name at offset %ld", i);
            int self_close = 0;
            unsigned char quote = 0;
            for (; j < n; j++) {
                if (quote) { if (d[j] == quote) quote = 0; continue; }
                if (d[j] == '"' || d[j] == '\'') { quote = d[j]; continue; }
                if (d[j] == '>') { self_close = (d[j - 1] == '/'); break; }
            }
            if (j >= n) XML_FAIL("unterminated <%.*s> tag at offset %ld", len, d + s, i);
            if (depth == 0) {
                if (++roots > 1) XML_FAIL("more than one root element (offset %ld)", i);
            }
            if (!self_close) {
                if (depth >= XML_MAX_DEPTH) XML_FAIL("nesting deeper than %d", XML_MAX_DEPTH);
                stack[depth].off = s;
                stack[depth].len = len;
                depth++;
            }
            i = j + 1;
        }
    }
    if (depth > 0) XML_FAIL("<%.*s> is never closed", stack[depth - 1].len, d + stack[depth - 1].off);
    if (roots == 0) XML_FAIL("no root element");
#undef XML_FAIL
    return 1;
}
