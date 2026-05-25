/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_CORE_MEMORY_H
#define NGFW_CORE_MEMORY_H

#include "ngfw/types.h"
#include <stddef.h>

/*
 * Core Memory Management
 * Slab allocator, memory pool, ring buffer
 */

/* Slab allocator for fixed-size objects */
typedef struct slab_cache slab_cache_t;

slab_cache_t *slab_cache_create(const char *name, size_t size, u32 align);
void slab_cache_destroy(slab_cache_t *cache);
void *slab_alloc(slab_cache_t *cache);
void slab_free(slab_cache_t *cache, void *obj);
u32 slab_cache_get_used(slab_cache_t *cache);

/* Memory pool for packet buffers */
typedef struct mem_pool mem_pool_t;

mem_pool_t *mem_pool_create(size_t block_size, u32 block_count);
void mem_pool_destroy(mem_pool_t *pool);
void *mem_pool_alloc(mem_pool_t *pool);
void mem_pool_free(mem_pool_t *pool, void *block);
u32 mem_pool_available(mem_pool_t *pool);

/* Ring buffer for lock-free queues */
typedef struct ring_buffer ring_buffer_t;

ring_buffer_t *ring_buffer_create(u32 capacity);
void ring_buffer_destroy(ring_buffer_t *rb);
ngfw_ret_t ring_buffer_push(ring_buffer_t *rb, void *item);
void *ring_buffer_pop(ring_buffer_t *rb);
u32 ring_buffer_count(ring_buffer_t *rb);
bool ring_buffer_empty(ring_buffer_t *rb);
bool ring_buffer_full(ring_buffer_t *rb);

#endif
