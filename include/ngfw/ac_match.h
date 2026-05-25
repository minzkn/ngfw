/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef NGFW_AC_MATCH_H
#define NGFW_AC_MATCH_H

#include "types.h"

/*
 * Aho-Corasick multi-pattern matching engine
 * 
 * Time complexity: O(n + m + z) where:
 *   n = text length
 *   m = total pattern length  
 *   z = number of matches
 * 
 * Space complexity: O(m * alphabet_size)
 */

typedef struct ac_matcher ac_matcher_t;

/* Create AC matcher with estimated max patterns */
ac_matcher_t *ac_matcher_create(u32 max_patterns);

/* Destroy matcher and free all memory */
void ac_matcher_destroy(ac_matcher_t *matcher);

/* Add pattern to matcher (must be called before ac_matcher_build) */
ngfw_ret_t ac_matcher_add_pattern(ac_matcher_t *matcher, const u8 *pattern, u32 len, u32 signature_id);

/* Build failure links - must be called after adding all patterns */
ngfw_ret_t ac_matcher_build(ac_matcher_t *matcher);

/* Find all matching patterns in data
 * Returns array of signature IDs in 'matches' up to max_matches
 * Returns NGFW_OK if matches found, NGFW_ERR_NOT_FOUND if none
 */
ngfw_ret_t ac_matcher_find(ac_matcher_t *matcher, const u8 *data, u32 data_len,
                           u32 *matches, u32 *match_count, u32 max_matches);

/* Statistics */
u32 ac_matcher_get_node_count(ac_matcher_t *matcher);
u32 ac_matcher_get_signature_count(ac_matcher_t *matcher);

#endif
