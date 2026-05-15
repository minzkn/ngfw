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

#ifndef NGFW_HASH_H
#define NGFW_HASH_H

#include "types.h"
#include <pthread.h>

typedef u32 (*hash_func_t)(const void *key, u32 size);
typedef bool (*hash_equal_t)(const void *a, const void *b);
typedef void (*hash_destroy_t)(void *key, void *value);

struct hash_node {
    void *key;
    void *value;
    struct hash_node *next;
};

#define HASH_SEGMENT_COUNT 16

struct hash_segment {
    pthread_rwlock_t lock;
};

struct hash_table {
    struct hash_node **buckets;
    u32 size;
    u32 count;
    hash_func_t hash;
    hash_equal_t equal;
    hash_destroy_t destroy;
    struct hash_segment *segments;  /* Segment locks for reduced contention */
    u32 segment_count;
};

typedef struct hash_table hash_table_t;

static inline u32 default_hash(const void *key, u32 size)
{
    if (size == 0) return 0;
    /* Generic pointer/int hash - safe for any key type */
    u32 h = (u32)(uintptr_t)key;
    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);
    return h % size;
}

void **hash_iterate_start(hash_table_t *table);
bool hash_iterate_has_next(void **iter);
void *hash_iterate_next(hash_table_t *table, void **iter);

hash_table_t *hash_create(u32 size, hash_func_t hash, hash_equal_t equal, hash_destroy_t destroy);
void hash_destroy(hash_table_t *table);
ngfw_ret_t hash_insert(hash_table_t *table, void *key, void *value);
void *hash_lookup(hash_table_t *table, const void *key);
void *hash_remove(hash_table_t *table, const void *key);
u32 hash_size(hash_table_t *table);
bool hash_empty(hash_table_t *table);

/* Thread-safe operations with explicit locking */
void hash_rdlock(hash_table_t *table);
void hash_wrlock(hash_table_t *table);
void hash_unlock(hash_table_t *table);
ngfw_ret_t hash_insert_locked(hash_table_t *table, void *key, void *value);
void *hash_lookup_locked(hash_table_t *table, const void *key);
void *hash_remove_locked(hash_table_t *table, const void *key);

u32 hash_int(const void *key, u32 size);
u32 hash_str(const void *key, u32 size);
bool equal_int(const void *a, const void *b);
bool equal_str(const void *a, const void *b);

#endif
