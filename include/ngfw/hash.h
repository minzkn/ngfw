#ifndef NGFW_HASH_H
#define NGFW_HASH_H

#include "types.h"

typedef u32 (*hash_func_t)(const void *key, u32 size);
typedef bool (*hash_equal_t)(const void *a, const void *b);
typedef void (*hash_destroy_t)(void *key, void *value);

struct hash_node {
    void *key;
    void *value;
    struct hash_node *next;
};

struct hash_table {
    struct hash_node **buckets;
    u32 size;
    u32 count;
    hash_func_t hash;
    hash_equal_t equal;
    hash_destroy_t destroy;
};

typedef struct hash_table hash_table_t;

static inline u32 default_hash(const void *key, u32 size)
{
    u32 h = 5381;
    const unsigned char *str = (const unsigned char *)key;
    while (*str) {
        h = ((h << 5) + h) + *str++;
    }
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

u32 hash_int(const void *key);
u32 hash_str(const void *key);
bool equal_int(const void *a, const void *b);
bool equal_str(const void *a, const void *b);

#endif
