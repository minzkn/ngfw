/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_CORE_DS_H
#define NGFW_CORE_DS_H

#include "ngfw/types.h"
#include <pthread.h>

/*
 * Core Data Structures
 * List, hash table, tree, bitmap, skip list, LRU cache
 */

/* Doubly linked list */
typedef struct list_node list_node_t;
typedef struct list list_t;

list_t *list_create(void (*destroy)(void *data));
void list_destroy(list_t *list);
ngfw_ret_t list_append(list_t *list, void *data);
ngfw_ret_t list_prepend(list_t *list, void *data);
ngfw_ret_t list_remove(list_t *list, void *data);
u32 list_size(list_t *list);
void *list_first(list_t *list);
void *list_last(list_t *list);

#define list_for_each(list, node) \
    for ((node) = (list)->head; (node) != NULL; (node) = (node)->next)

/* Hash table with segment locking */
typedef u32 (*hash_func_t)(const void *key, u32 size);
typedef bool (*hash_equal_t)(const void *a, const void *b);
typedef void (*hash_destroy_t)(void *key, void *value);

typedef struct hash_table hash_table_t;

hash_table_t *hash_create(u32 size, hash_func_t hash, hash_equal_t equal, hash_destroy_t destroy);
void hash_destroy(hash_table_t *table);
ngfw_ret_t hash_insert(hash_table_t *table, void *key, void *value);
void *hash_lookup(hash_table_t *table, const void *key);
void *hash_remove(hash_table_t *table, const void *key);
u32 hash_size(hash_table_t *table);
bool hash_empty(hash_table_t *table);

/* Segment locking for concurrency */
void hash_rdlock(hash_table_t *table);
void hash_wrlock(hash_table_t *table);
void hash_unlock(hash_table_t *table);

/* Bitmap for efficient set operations */
typedef struct bitmap bitmap_t;

bitmap_t *bitmap_create(u32 bits);
void bitmap_destroy(bitmap_t *bm);
void bitmap_set(bitmap_t *bm, u32 bit);
void bitmap_clear(bitmap_t *bm, u32 bit);
bool bitmap_test(bitmap_t *bm, u32 bit);
u32 bitmap_find_first_set(bitmap_t *bm);
u32 bitmap_find_first_zero(bitmap_t *bm);

/* Skip list for sorted data */
typedef struct skiplist skiplist_t;

skiplist_t *skiplist_create(int (*cmp)(const void *a, const void *b));
void skiplist_destroy(skiplist_t *sl);
ngfw_ret_t skiplist_insert(skiplist_t *sl, void *data);
void *skiplist_find(skiplist_t *sl, const void *key);
void *skiplist_remove(skiplist_t *sl, const void *key);

/* LRU Cache */
typedef struct lrucache lrucache_t;

lrucache_t *lrucache_create(u32 capacity);
void lrucache_destroy(lrucache_t *cache);
void *lrucache_get(lrucache_t *cache, const void *key);
ngfw_ret_t lrucache_put(lrucache_t *cache, void *key, void *value);
void *lrucache_remove(lrucache_t *cache, const void *key);

#endif
