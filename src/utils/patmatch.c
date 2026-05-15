/*
 * NGFW - Next-Generation Firewall
 * Pattern matching engine (Boyer-Moore-Horspool + wildcard fallback)
 * Copyright (C) 2024 NGFW Project
 */

#include "ngfw/patmatch.h"
#include "ngfw/memory.h"
#include <string.h>

patmatch_ctx_t *patmatch_compile(const u8 *pattern, u32 len, u32 type, bool ignore_case)
{
    if (!pattern || len == 0) return NULL;

    patmatch_ctx_t *ctx = ngfw_malloc(sizeof(patmatch_ctx_t));
    if (!ctx) return NULL;

    ctx->pattern = ngfw_malloc(len + 1);
    if (!ctx->pattern) {
        ngfw_free(ctx);
        return NULL;
    }

    if (ignore_case) {
        for (u32 i = 0; i < len; i++) {
            u8 c = pattern[i];
            if (c >= 'A' && c <= 'Z') c += 0x20;
            ((u8 *)ctx->pattern)[i] = c;
        }
    } else {
        memcpy((void *)ctx->pattern, pattern, len);
    }
    ((u8 *)ctx->pattern)[len] = '\0';
    ctx->pattern_len = len;
    ctx->type = type;
    ctx->ignore_case = ignore_case;

    /* Initialize BMH bad-character shift table */
    u32 i;
    for (i = 0; i < 256; i++) {
        ctx->shift_table[i] = len;
    }
    for (i = 0; i < len - 1; i++) {
        ctx->shift_table[ctx->pattern[i]] = len - 1 - i;
    }

    return ctx;
}

void patmatch_destroy(patmatch_ctx_t *ctx)
{
    if (!ctx) return;
    if (ctx->pattern) ngfw_free((void *)ctx->pattern);
    ngfw_free(ctx);
}

/* Boyer-Moore-Horspool exact substring search */
static int bmh_find(patmatch_ctx_t *ctx, const u8 *data, u32 data_len)
{
    u32 plen = ctx->pattern_len;
    const u8 *p = ctx->pattern;

    if (plen > data_len) return -1;
    if (plen == 0) return 0;

    u32 i = plen - 1;
    while (i < data_len) {
        u32 j = plen - 1;
        while (j > 0 && data[i - (plen - 1 - j)] == p[j]) {
            j--;
        }
        if (j == 0 && data[i - plen + 1] == p[0]) {
            return (int)(i - plen + 1);
        }
        i += ctx->shift_table[data[i]];
    }
    return -1;
}

/* Wildcard match: supports '*' (any sequence) and '?' (single char) */
static bool wildcard_match(const u8 *pat, u32 plen, const u8 *data, u32 dlen)
{
    if (plen == 0) return dlen == 0;

    /* Simple recursive wildcard matching with early termination */
    u32 p = 0, d = 0, star = (u32)-1, ss = 0;

    while (d < dlen) {
        if (p < plen && pat[p] == '*') {
            star = p++;
            ss = d;
            continue;
        }

        if (p < plen && (pat[p] == '?' || pat[p] == data[d])) {
            p++; d++;
            continue;
        }

        if (star != (u32)-1) {
            p = star + 1;
            d = ++ss;
            continue;
        }

        return false;
    }

    while (p < plen && pat[p] == '*') p++;

    return p == plen;
}

int patmatch_find(patmatch_ctx_t *ctx, const u8 *data, u32 data_len)
{
    if (!ctx || !data) return -1;

    switch (ctx->type) {
    case PATMATCH_EXACT:
        return bmh_find(ctx, data, data_len);
    case PATMATCH_WILDCARD:
        /* For wildcards we scan through the data trying to match at each position */
        if (ctx->pattern_len == 0) return 0;
        for (u32 i = 0; i <= data_len; i++) {
            if (wildcard_match(ctx->pattern, ctx->pattern_len,
                               data + i, data_len - i)) {
                if (i == 0 || ctx->pattern[0] != '*') return (int)i;
                /* Leading '*' matches from start */
                return (int)i;
            }
        }
        return -1;
    default:
        /* Fallback: exact BMH for unknown types */
        return bmh_find(ctx, data, data_len);
    }
}

bool patmatch_match(patmatch_ctx_t *ctx, const u8 *data, u32 data_len)
{
    if (!ctx || !data) return false;

    if (ctx->type == PATMATCH_WILDCARD) {
        return wildcard_match(ctx->pattern, ctx->pattern_len, data, data_len);
    }

    /* For exact/regex, data must match exactly */
    if (data_len != ctx->pattern_len) return false;
    return memcmp(ctx->pattern, data, data_len) == 0;
}
