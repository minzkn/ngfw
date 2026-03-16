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

#include "ngfw/lrucache.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

typedef struct lru_node {
    void *key;
    void *value;
    struct lru_node *prev;
    struct lru_node *next;
} lru_node_t;

struct lru_cache {
    hash_table_t *hash;
    lru_node_t *head;
    lru_node_t *tail;
    u32 capacity;
    u32 size;
    lru_destructor_t destructor;
};

static u32 hash_key(const void *key, u32 size)
{
    (void)size;
    return (u32)(uintptr_t)key;
}

static bool equal_key(const void *a, const void *b)
{
    return a == b;
}

static void destroy_node(void *key, void *value)
{
    (void)key;
    if (value) ngfw_free(value);
}

lru_cache_t *lru_create(u32 capacity, lru_destructor_t destructor)
{
    if (capacity == 0) return NULL;
    
    lru_cache_t *cache = ngfw_malloc(sizeof(lru_cache_t));
    if (!cache) return NULL;
    
    cache->hash = hash_create(capacity * 2, hash_key, equal_key, destroy_node);
    if (!cache->hash) {
        ngfw_free(cache);
        return NULL;
    }
    
    cache->capacity = capacity;
    cache->size = 0;
    cache->head = NULL;
    cache->tail = NULL;
    cache->destructor = destructor;
    
    return cache;
}

void lru_destroy(lru_cache_t *cache)
{
    if (!cache) return;
    
    lru_clear(cache);
    hash_destroy(cache->hash);
    ngfw_free(cache);
}

static void lru_detach(lru_cache_t *cache, lru_node_t *node)
{
    if (node->prev) {
        node->prev->next = node->next;
    } else {
        cache->head = node->next;
    }
    
    if (node->next) {
        node->next->prev = node->prev;
    } else {
        cache->tail = node->prev;
    }
}

static void lru_attach_head(lru_cache_t *cache, lru_node_t *node)
{
    node->next = cache->head;
    node->prev = NULL;
    
    if (cache->head) {
        cache->head->prev = node;
    }
    cache->head = node;
    
    if (!cache->tail) {
        cache->tail = node;
    }
}

static void lru_evict(lru_cache_t *cache)
{
    if (!cache->tail || cache->size <= cache->capacity) return;
    
    while (cache->size > cache->capacity && cache->tail) {
        lru_node_t *evict = cache->tail;
        
        lru_detach(cache, evict);
        
        hash_remove(cache->hash, evict->key);
        
        if (cache->destructor) {
            cache->destructor(evict->key, evict->value);
        } else {
            ngfw_free(evict->key);
            ngfw_free(evict->value);
        }
        
        ngfw_free(evict);
        cache->size--;
    }
}

bool lru_put(lru_cache_t *cache, const void *key, void *value)
{
    if (!cache || !key || !value) return false;
    
    lru_node_t *existing = hash_lookup(cache->hash, key);
    if (existing) {
        if (cache->destructor) {
            cache->destructor((void *)key, existing->value);
        } else {
            ngfw_free(existing->value);
        }
        existing->value = value;
        lru_detach(cache, existing);
        lru_attach_head(cache, existing);
        return true;
    }
    
    if (cache->size >= cache->capacity) {
        lru_evict(cache);
    }
    
    lru_node_t *node = ngfw_malloc(sizeof(lru_node_t));
    if (!node) return false;
    
    node->key = (void *)key;
    node->value = value;
    node->prev = NULL;
    node->next = NULL;
    
    void *key_copy = (void *)key;
    hash_insert(cache->hash, key_copy, node);
    lru_attach_head(cache, node);
    cache->size++;
    
    return true;
}

void *lru_get(lru_cache_t *cache, const void *key)
{
    if (!cache || !key) return NULL;
    
    lru_node_t *node = hash_lookup(cache->hash, key);
    if (!node) return NULL;
    
    lru_detach(cache, node);
    lru_attach_head(cache, node);
    
    return node->value;
}

void *lru_remove(lru_cache_t *cache, const void *key)
{
    if (!cache || !key) return NULL;
    
    lru_node_t *node = hash_remove(cache->hash, key);
    if (!node) return NULL;
    
    lru_detach(cache, node);
    
    void *value = node->value;
    ngfw_free(node);
    cache->size--;
    
    return value;
}

bool lru_contains(lru_cache_t *cache, const void *key)
{
    if (!cache || !key) return false;
    return hash_lookup(cache->hash, key) != NULL;
}

u32 lru_size(lru_cache_t *cache)
{
    return cache ? cache->size : 0;
}

u32 lru_capacity(lru_cache_t *cache)
{
    return cache ? cache->capacity : 0;
}

void lru_clear(lru_cache_t *cache)
{
    if (!cache) return;
    
    lru_node_t *node = cache->head;
    while (node) {
        lru_node_t *next = node->next;
        
        if (cache->destructor) {
            cache->destructor(node->key, node->value);
        }
        
        ngfw_free(node);
        node = next;
    }
    
    hash_destroy(cache->hash);
    cache->hash = hash_create(cache->capacity * 2, hash_key, equal_key, destroy_node);
    
    cache->head = NULL;
    cache->tail = NULL;
    cache->size = 0;
}
