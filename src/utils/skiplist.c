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

#include "ngfw/skiplist.h"
#include "ngfw/memory.h"
#include <stdlib.h>
#include <string.h>

#define MAX_LEVEL 16

struct skiplist_node {
    void *key;
    void *value;
    skiplist_node_t *forward[MAX_LEVEL + 1];
};

struct skiplist {
    skiplist_node_t *header;
    u32 level;
    u32 size;
    skiplist_compare_t compare;
};

static u32 random_level(void)
{
    u32 level = 0;
    while (level < MAX_LEVEL && (rand() & 1)) {
        level++;
    }
    return level;
}

skiplist_t *skiplist_create(skiplist_compare_t compare)
{
    skiplist_t *list = ngfw_malloc(sizeof(skiplist_t));
    if (!list) return NULL;
    
    list->header = ngfw_malloc(sizeof(skiplist_node_t));
    if (!list->header) {
        ngfw_free(list);
        return NULL;
    }
    
    for (u32 i = 0; i <= MAX_LEVEL; i++) {
        list->header->forward[i] = NULL;
    }
    list->header->key = NULL;
    list->header->value = NULL;
    
    list->level = 0;
    list->size = 0;
    list->compare = compare ? compare : (skiplist_compare_t)strcmp;
    
    return list;
}

void skiplist_destroy(skiplist_t *list)
{
    if (!list) return;
    
    skiplist_node_t *node = list->header->forward[0];
    while (node) {
        skiplist_node_t *next = node->forward[0];
        ngfw_free(node);
        node = next;
    }
    
    ngfw_free(list->header);
    ngfw_free(list);
}

bool skiplist_insert(skiplist_t *list, void *key, void *value)
{
    if (!list || !key) return false;
    
    skiplist_node_t *update[MAX_LEVEL + 1];
    skiplist_node_t *node = list->header;
    
    for (int i = list->level; i >= 0; i--) {
        while (node->forward[i] && list->compare(node->forward[i]->key, key) < 0) {
            node = node->forward[i];
        }
        update[i] = node;
    }
    
    node = node->forward[0];
    
    if (node && list->compare(node->key, key) == 0) {
        node->value = value;
        return true;
    }
    
    u32 new_level = random_level();
    
    if (new_level > list->level) {
        for (u32 i = list->level + 1; i <= new_level; i++) {
            update[i] = list->header;
        }
        list->level = new_level;
    }
    
    skiplist_node_t *new_node = ngfw_malloc(sizeof(skiplist_node_t));
    if (!new_node) return false;
    
    new_node->key = key;
    new_node->value = value;
    
    for (u32 i = 0; i <= new_level; i++) {
        new_node->forward[i] = update[i]->forward[i];
        update[i]->forward[i] = new_node;
    }
    
    list->size++;
    return true;
}

void *skiplist_search(skiplist_t *list, const void *key)
{
    if (!list || !key) return NULL;
    
    skiplist_node_t *node = list->header;
    
    for (int i = list->level; i >= 0; i--) {
        while (node->forward[i] && list->compare(node->forward[i]->key, key) < 0) {
            node = node->forward[i];
        }
    }
    
    node = node->forward[0];
    
    if (node && list->compare(node->key, key) == 0) {
        return node->value;
    }
    
    return NULL;
}

bool skiplist_delete(skiplist_t *list, const void *key)
{
    if (!list || !key) return false;
    
    skiplist_node_t *update[MAX_LEVEL + 1];
    skiplist_node_t *node = list->header;
    
    for (int i = list->level; i >= 0; i--) {
        while (node->forward[i] && list->compare(node->forward[i]->key, key) < 0) {
            node = node->forward[i];
        }
        update[i] = node;
    }
    
    node = node->forward[0];
    
    if (!node || list->compare(node->key, key) != 0) {
        return false;
    }
    
    for (u32 i = 0; i <= list->level; i++) {
        if (update[i]->forward[i] != node) break;
        update[i]->forward[i] = node->forward[i];
    }
    
    ngfw_free(node);
    
    while (list->level > 0 && list->header->forward[list->level] == NULL) {
        list->level--;
    }
    
    list->size--;
    return true;
}

u32 skiplist_size(skiplist_t *list)
{
    return list ? list->size : 0;
}

bool skiplist_empty(skiplist_t *list)
{
    return list ? list->size == 0 : true;
}

void skiplist_foreach(skiplist_t *list, skiplist_foreach_cb cb, void *arg)
{
    if (!list || !cb) return;
    
    skiplist_node_t *node = list->header->forward[0];
    while (node) {
        if (!cb(node->key, node->value, arg)) {
            break;
        }
        node = node->forward[0];
    }
}
