/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_CORE_MATCH_H
#define NGFW_CORE_MATCH_H

#include "ngfw/types.h"

/*
 * Pattern Matching Engine
 * BMH, Aho-Corasick, wildcard matching
 */

/* Boyer-Moore-Horspool for exact matching */
typedef struct bmh_ctx bmh_ctx_t;

bmh_ctx_t *bmh_compile(const u8 *pattern, u32 len);
void bmh_destroy(bmh_ctx_t *ctx);
int bmh_find(bmh_ctx_t *ctx, const u8 *text, u32 text_len);

/* Aho-Corasick for multi-pattern matching */
typedef struct ac_matcher ac_matcher_t;

ac_matcher_t *ac_matcher_create(u32 max_patterns);
void ac_matcher_destroy(ac_matcher_t *matcher);
ngfw_ret_t ac_matcher_add_pattern(ac_matcher_t *matcher, const u8 *pattern, u32 len, u32 id);
ngfw_ret_t ac_matcher_build(ac_matcher_t *matcher);
ngfw_ret_t ac_matcher_find(ac_matcher_t *matcher, const u8 *data, u32 data_len,
                           u32 *matches, u32 *match_count, u32 max_matches);

/* Wildcard matching (* and ?) */
typedef struct wildcard_ctx wildcard_ctx_t;

wildcard_ctx_t *wildcard_compile(const char *pattern);
void wildcard_destroy(wildcard_ctx_t *ctx);
bool wildcard_match(wildcard_ctx_t *ctx, const char *text);

#endif
