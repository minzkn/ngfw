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

#include "ngfw/ac_match.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include <string.h>

#define AC_MAX_ALPHABET 256

typedef struct ac_node {
    struct ac_node *fail;
    struct ac_node *next[AC_MAX_ALPHABET];
    u32 *output;        /* Array of signature IDs that match at this node */
    u32 output_count;
    u32 depth;
} ac_node_t;

struct ac_matcher {
    ac_node_t *root;
    u32 node_count;
    u32 max_node_count;
    u32 signature_count;
    bool built;
};

static ac_node_t *ac_node_create(void)
{
    ac_node_t *node = ngfw_calloc(1, sizeof(ac_node_t));
    if (!node) return NULL;
    
    node->fail = NULL;
    memset(node->next, 0, sizeof(node->next));
    node->output = NULL;
    node->output_count = 0;
    node->depth = 0;
    
    return node;
}

static void ac_node_destroy(ac_node_t *node)
{
    if (!node) return;
    
    for (int i = 0; i < AC_MAX_ALPHABET; i++) {
        if (node->next[i]) {
            ac_node_destroy(node->next[i]);
        }
    }
    
    if (node->output) {
        ngfw_free(node->output);
    }
    
    ngfw_free(node);
}

ac_matcher_t *ac_matcher_create(u32 max_patterns)
{
    ac_matcher_t *matcher = ngfw_malloc(sizeof(ac_matcher_t));
    if (!matcher) return NULL;
    
    matcher->root = ac_node_create();
    if (!matcher->root) {
        ngfw_free(matcher);
        return NULL;
    }
    
    matcher->node_count = 1;  /* Root node */
    matcher->max_node_count = max_patterns * 64;  /* Estimate: 64 nodes per pattern */
    matcher->signature_count = 0;
    matcher->built = false;
    
    return matcher;
}

void ac_matcher_destroy(ac_matcher_t *matcher)
{
    if (!matcher) return;
    
    if (matcher->root) {
        ac_node_destroy(matcher->root);
    }
    
    ngfw_free(matcher);
}

ngfw_ret_t ac_matcher_add_pattern(ac_matcher_t *matcher, const u8 *pattern, u32 len, u32 signature_id)
{
    if (!matcher || !matcher->root || !pattern || len == 0) {
        return NGFW_ERR_INVALID;
    }
    
    if (matcher->built) {
        log_err("Cannot add pattern after AC automaton is built");
        return NGFW_ERR_INVALID;
    }
    
    ac_node_t *current = matcher->root;
    
    for (u32 i = 0; i < len; i++) {
        u8 c = pattern[i];
        
        if (!current->next[c]) {
            current->next[c] = ac_node_create();
            if (!current->next[c]) {
                return NGFW_ERR_NO_MEM;
            }
            current->next[c]->depth = current->depth + 1;
            matcher->node_count++;
        }
        
        current = current->next[c];
    }
    
    /* Add signature ID to output list */
    u32 new_count = current->output_count + 1;
    u32 *new_output = ngfw_realloc(current->output, sizeof(u32) * new_count);
    if (!new_output) {
        return NGFW_ERR_NO_MEM;
    }
    
    new_output[current->output_count] = signature_id;
    current->output = new_output;
    current->output_count = new_count;
    matcher->signature_count++;
    
    return NGFW_OK;
}

static void ac_build_failure_links(ac_matcher_t *matcher)
{
    ac_node_t **queue;
    u32 head = 0;
    u32 tail = 0;
    
    queue = ngfw_malloc(sizeof(ac_node_t *) * matcher->node_count);
    if (!queue) return;
    
    /* Initialize root's fail to itself */
    matcher->root->fail = matcher->root;
    
    /* Enqueue all depth-1 nodes */
    for (int c = 0; c < AC_MAX_ALPHABET; c++) {
        if (matcher->root->next[c]) {
            matcher->root->next[c]->fail = matcher->root;
            queue[tail++] = matcher->root->next[c];
        } else {
            matcher->root->next[c] = matcher->root;  /* Point to root */
        }
    }
    
    /* BFS to build failure links */
    while (head < tail) {
        ac_node_t *current = queue[head++];
        
        for (int c = 0; c < AC_MAX_ALPHABET; c++) {
            if (current->next[c]) {
                /* Find failure state */
                ac_node_t *fail = current->fail;
                while (fail != matcher->root && !fail->next[c]) {
                    fail = fail->fail;
                }
                
                current->next[c]->fail = fail->next[c] ? fail->next[c] : matcher->root;
                
                /* Merge output from failure node */
                ac_node_t *fail_node = current->next[c]->fail;
                if (fail_node->output_count > 0) {
                    u32 new_count = current->next[c]->output_count + fail_node->output_count;
                    u32 *new_output = ngfw_realloc(current->next[c]->output, 
                                                    sizeof(u32) * new_count);
                    if (new_output) {
                        memcpy(new_output + current->next[c]->output_count,
                               fail_node->output,
                               sizeof(u32) * fail_node->output_count);
                        current->next[c]->output = new_output;
                        current->next[c]->output_count = new_count;
                    }
                }
                
                queue[tail++] = current->next[c];
            } else {
                /* Point to failure node's transition */
                current->next[c] = current->fail->next[c];
            }
        }
    }
    
    ngfw_free(queue);
    matcher->built = true;
}

ngfw_ret_t ac_matcher_build(ac_matcher_t *matcher)
{
    if (!matcher || !matcher->root) {
        return NGFW_ERR_INVALID;
    }
    
    if (matcher->built) {
        return NGFW_OK;  /* Already built */
    }
    
    ac_build_failure_links(matcher);
    
    log_info("AC matcher built: %u nodes, %u signatures", 
             matcher->node_count, matcher->signature_count);
    
    return NGFW_OK;
}

ngfw_ret_t ac_matcher_find(ac_matcher_t *matcher, const u8 *data, u32 data_len, 
                           u32 *matches, u32 *match_count, u32 max_matches)
{
    if (!matcher || !matcher->root || !matcher->built) {
        return NGFW_ERR_INVALID;
    }
    
    if (!data || data_len == 0) {
        return NGFW_ERR_INVALID;
    }
    
    u32 found = 0;
    ac_node_t *current = matcher->root;
    
    for (u32 i = 0; i < data_len && found < max_matches; i++) {
        u8 c = data[i];
        
        /* Follow transition (already optimized during build) */
        current = current->next[c];
        
        /* Check for matches at this node */
        if (current->output_count > 0) {
            for (u32 j = 0; j < current->output_count && found < max_matches; j++) {
                matches[found++] = current->output[j];
            }
        }
    }
    
    if (match_count) {
        *match_count = found;
    }
    
    return found > 0 ? NGFW_OK : NGFW_ERR_NOT_FOUND;
}

u32 ac_matcher_get_node_count(ac_matcher_t *matcher)
{
    return matcher ? matcher->node_count : 0;
}

u32 ac_matcher_get_signature_count(ac_matcher_t *matcher)
{
    return matcher ? matcher->signature_count : 0;
}
