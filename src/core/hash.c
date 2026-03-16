#include "ngfw/hash.h"
#include "ngfw/memory.h"
#include <stddef.h>
#include <string.h>

hash_table_t *hash_create(u32 size, hash_func_t hash, hash_equal_t equal, hash_destroy_t destroy)
{
    if (size == 0) size = 256;
    
    hash_table_t *table = ngfw_malloc(sizeof(hash_table_t));
    if (!table) return NULL;
    
    table->buckets = ngfw_calloc(size, sizeof(struct hash_node *));
    if (!table->buckets) {
        ngfw_free(table);
        return NULL;
    }
    
    table->size = size;
    table->count = 0;
    table->hash = hash ? hash : default_hash;
    table->equal = equal;
    table->destroy = destroy;
    
    return table;
}

void hash_destroy(hash_table_t *table)
{
    if (!table) return;
    
    for (u32 i = 0; i < table->size; i++) {
        struct hash_node *node = table->buckets[i];
        while (node) {
            struct hash_node *next = node->next;
            if (table->destroy) {
                table->destroy(node->key, node->value);
            }
            ngfw_free(node);
            node = next;
        }
    }
    
    ngfw_free(table->buckets);
    ngfw_free(table);
}

ngfw_ret_t hash_insert(hash_table_t *table, void *key, void *value)
{
    if (!table) return NGFW_ERR_INVALID;
    
    u32 idx = table->hash(key, table->size);
    
    struct hash_node *node = ngfw_malloc(sizeof(struct hash_node));
    if (!node) return NGFW_ERR_NO_MEM;
    
    node->key = key;
    node->value = value;
    node->next = table->buckets[idx];
    table->buckets[idx] = node;
    table->count++;
    
    return NGFW_OK;
}

void *hash_lookup(hash_table_t *table, const void *key)
{
    if (!table) return NULL;
    
    u32 idx = table->hash(key, table->size);
    struct hash_node *node = table->buckets[idx];
    
    while (node) {
        if (table->equal && table->equal(key, node->key)) {
            return node->value;
        } else if (key == node->key) {
            return node->value;
        }
        node = node->next;
    }
    
    return NULL;
}

void *hash_remove(hash_table_t *table, const void *key)
{
    if (!table) return NULL;
    
    u32 idx = table->hash(key, table->size);
    struct hash_node *node = table->buckets[idx];
    struct hash_node *prev = NULL;
    
    while (node) {
        if (table->equal && table->equal(key, node->key)) {
            if (prev) {
                prev->next = node->next;
            } else {
                table->buckets[idx] = node->next;
            }
            
            void *value = node->value;
            ngfw_free(node);
            table->count--;
            return value;
        }
        prev = node;
        node = node->next;
    }
    
    return NULL;
}

u32 hash_size(hash_table_t *table)
{
    return table ? table->count : 0;
}

bool hash_empty(hash_table_t *table)
{
    return !table || table->count == 0;
}

u32 hash_int(const void *key)
{
    return (u32)(uintptr_t)key;
}

u32 hash_str(const void *key)
{
    const char *str = (const char *)key;
    u32 h = 5381;
    while (*str) {
        h = ((h << 5) + h) + (u8)*str++;
    }
    return h;
}

bool equal_int(const void *a, const void *b)
{
    return a == b;
}

bool equal_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b) == 0;
}

void **hash_iterate_start(hash_table_t *table)
{
    if (!table) return NULL;
    
    for (u32 i = 0; i < table->size; i++) {
        if (table->buckets[i]) {
            void **iter = ngfw_malloc(sizeof(void *) * 2);
            if (iter) {
                iter[0] = (void *)(uintptr_t)i;
                iter[1] = table->buckets[i];
            }
            return iter;
        }
    }
    return NULL;
}

bool hash_iterate_has_next(void **iter)
{
    if (!iter) return false;
    return iter[1] != NULL;
}

void *hash_iterate_next(hash_table_t *table, void **iter)
{
    if (!table || !iter) return NULL;
    
    struct hash_node *node = (struct hash_node *)iter[1];
    if (!node) return NULL;
    
    void *value = node->value;
    
    if (node->next) {
        iter[1] = node->next;
    } else {
        u32 idx = (u32)(uintptr_t)iter[0] + 1;
        for (u32 i = idx; i < table->size; i++) {
            if (table->buckets[i]) {
                iter[0] = (void *)(uintptr_t)i;
                iter[1] = table->buckets[i];
                return value;
            }
        }
        iter[1] = NULL;
    }
    
    return value;
}
