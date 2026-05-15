/*
 * NGFW - Slab Allocator Interface
 * High-performance memory pool for fixed-size allocations
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_SLAB_ALLOC_H
#define NGFW_SLAB_ALLOC_H

#include "types.h"

typedef struct slab_pool slab_pool_t;

/* Create a slab pool for objects of given size */
slab_pool_t *slab_pool_create(u32 object_size, u32 initial_slabs);

/* Grow the pool by allocating a new slab */
ngfw_ret_t slab_pool_grow(slab_pool_t *pool);

/* Allocate an object from the pool */
void *slab_alloc(slab_pool_t *pool);

/* Free an object back to the pool */
void slab_free(slab_pool_t *pool, void *ptr);

/* Destroy the pool and free all memory */
void slab_pool_destroy(slab_pool_t *pool);

/* Get statistics */
u32 slab_pool_get_used_count(slab_pool_t *pool);
u32 slab_pool_get_free_count(slab_pool_t *pool);
void slab_pool_get_stats(slab_pool_t *pool, u64 *alloc_count, u64 *free_count, u32 *used, u32 *free_objs);

#endif
