#ifndef NGFW_LRUCACHE_H
#define NGFW_LRUCACHE_H

#include "ngfw/types.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct lru_cache lru_cache_t;

typedef void (*lru_destructor_t)(void *key, void *value);

lru_cache_t *lru_create(u32 capacity, lru_destructor_t destructor);
void lru_destroy(lru_cache_t *cache);
bool lru_put(lru_cache_t *cache, const void *key, void *value);
void *lru_get(lru_cache_t *cache, const void *key);
void *lru_remove(lru_cache_t *cache, const void *key);
bool lru_contains(lru_cache_t *cache, const void *key);
u32 lru_size(lru_cache_t *cache);
u32 lru_capacity(lru_cache_t *cache);
void lru_clear(lru_cache_t *cache);

#endif
