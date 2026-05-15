/*
 * NGFW - Slab Allocator for Session Objects
 * High-performance memory pool for fixed-size allocations
 * Copyright (C) 2024 NGFW Project
 */

#include "ngfw/types.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define SLAB_MAGIC 0xDEADBEEF
#define SLAB_ALIGNMENT 64  /* Cache line alignment */

typedef struct slab_header {
    u32 magic;
    u32 object_size;
    u32 total_objects;
    u32 free_objects;
    pthread_mutex_t lock;
    void *free_list;
} slab_header_t;

typedef struct slab_object {
    struct slab_object *next;
} slab_object_t;

typedef struct slab_pool {
    slab_header_t **slabs;
    u32 slab_count;
    u32 max_slabs;
    u32 objects_per_slab;
    u32 object_size;
    u64 alloc_count;
    u64 free_count;
    u64 slab_alloc_count;
} slab_pool_t;

/* Forward declaration */
static ngfw_ret_t slab_pool_grow(slab_pool_t *pool);

slab_pool_t *slab_pool_create(u32 object_size, u32 initial_slabs)
{
    if (object_size == 0 || object_size > 4096) {
        log_err("Invalid object size: %u", object_size);
        return NULL;
    }
    
    /* Ensure minimum size for free list pointer */
    if (object_size < sizeof(slab_object_t)) {
        object_size = sizeof(slab_object_t);
    }
    
    /* Align object size to cache line */
    object_size = (object_size + SLAB_ALIGNMENT - 1) & ~(SLAB_ALIGNMENT - 1);
    
    slab_pool_t *pool = ngfw_malloc(sizeof(slab_pool_t));
    if (!pool) return NULL;
    
    memset(pool, 0, sizeof(slab_pool_t));
    pool->object_size = object_size;
    pool->objects_per_slab = (4096 - sizeof(slab_header_t)) / object_size;
    pool->max_slabs = initial_slabs > 0 ? initial_slabs : 16;
    pool->slab_count = 0;
    
    /* Allocate initial slabs */
    pool->slabs = ngfw_malloc(sizeof(slab_header_t *) * pool->max_slabs);
    if (!pool->slabs) {
        ngfw_free(pool);
        return NULL;
    }
    
    memset(pool->slabs, 0, sizeof(slab_header_t *) * pool->max_slabs);
    
    /* Create initial slabs */
    for (u32 i = 0; i < initial_slabs; i++) {
        if (slab_pool_grow(pool) != NGFW_OK) {
            log_warn("Failed to create initial slab %u", i);
            break;
        }
    }
    
    log_info("Slab pool created: object_size=%u, objects_per_slab=%u, initial_slabs=%u",
             object_size, pool->objects_per_slab, initial_slabs);
    
    return pool;
}

static ngfw_ret_t slab_pool_grow(slab_pool_t *pool)
{
    if (!pool) return NGFW_ERR_INVALID;
    
    if (pool->slab_count >= pool->max_slabs) {
        /* Grow slab array */
        u32 new_max = pool->max_slabs * 2;
        slab_header_t **new_slabs = ngfw_realloc(pool->slabs, sizeof(slab_header_t *) * new_max);
        if (!new_slabs) return NGFW_ERR_NO_MEM;
        
        pool->slabs = new_slabs;
        memset(&pool->slabs[pool->max_slabs], 0, sizeof(slab_header_t *) * (new_max - pool->max_slabs));
        pool->max_slabs = new_max;
    }
    
    /* Allocate new slab */
    size_t slab_size = sizeof(slab_header_t) + (pool->object_size * pool->objects_per_slab);
    slab_header_t *slab = ngfw_malloc(slab_size);
    if (!slab) return NGFW_ERR_NO_MEM;
    
    memset(slab, 0, slab_size);
    slab->magic = SLAB_MAGIC;
    slab->object_size = pool->object_size;
    slab->total_objects = pool->objects_per_slab;
    slab->free_objects = pool->objects_per_slab;
    pthread_mutex_init(&slab->lock, NULL);
    
    /* Initialize free list */
    u8 *objects = (u8 *)slab + sizeof(slab_header_t);
    slab->free_list = objects;
    
    slab_object_t *prev = NULL;
    for (u32 i = 0; i < pool->objects_per_slab; i++) {
        slab_object_t *obj = (slab_object_t *)(objects + (i * pool->object_size));
        obj->next = prev;
        prev = obj;
    }
    
    pool->slabs[pool->slab_count++] = slab;
    pool->slab_alloc_count++;
    
    return NGFW_OK;
}

void *slab_alloc(slab_pool_t *pool)
{
    if (!pool) return NULL;
    
    /* Try to allocate from existing slabs */
    for (u32 i = 0; i < pool->slab_count; i++) {
        slab_header_t *slab = pool->slabs[i];
        if (!slab || slab->free_objects == 0) continue;
        
        pthread_mutex_lock(&slab->lock);
        
        if (slab->free_list) {
            slab_object_t *obj = (slab_object_t *)slab->free_list;
            slab->free_list = obj->next;
            slab->free_objects--;
            pool->alloc_count++;
            
            pthread_mutex_unlock(&slab->lock);
            return obj;
        }
        
        pthread_mutex_unlock(&slab->lock);
    }
    
    /* No free objects, grow the pool */
    if (slab_pool_grow(pool) != NGFW_OK) {
        return NULL;
    }
    
    /* Allocate from new slab */
    slab_header_t *slab = pool->slabs[pool->slab_count - 1];
    pthread_mutex_lock(&slab->lock);
    
    slab_object_t *obj = (slab_object_t *)slab->free_list;
    slab->free_list = obj->next;
    slab->free_objects--;
    pool->alloc_count++;
    
    pthread_mutex_unlock(&slab->lock);
    return obj;
}

void slab_free(slab_pool_t *pool, void *ptr)
{
    if (!pool || !ptr) return;
    
    /* Find which slab this object belongs to */
    for (u32 i = 0; i < pool->slab_count; i++) {
        slab_header_t *slab = pool->slabs[i];
        if (!slab) continue;
        
        u8 *slab_start = (u8 *)slab;
        u8 *slab_end = slab_start + sizeof(slab_header_t) + (slab->object_size * slab->total_objects);
        u8 *obj = (u8 *)ptr;
        
        if (obj >= slab_start + sizeof(slab_header_t) && obj < slab_end) {
            pthread_mutex_lock(&slab->lock);
            
            /* Add to free list */
            slab_object_t *free_obj = (slab_object_t *)obj;
            free_obj->next = (slab_object_t *)slab->free_list;
            slab->free_list = free_obj;
            slab->free_objects++;
            pool->free_count++;
            
            pthread_mutex_unlock(&slab->lock);
            return;
        }
    }
    
    log_err("Invalid pointer freed to slab pool: %p", ptr);
}

void slab_pool_destroy(slab_pool_t *pool)
{
    if (!pool) return;
    
    for (u32 i = 0; i < pool->slab_count; i++) {
        if (pool->slabs[i]) {
            pthread_mutex_destroy(&pool->slabs[i]->lock);
            ngfw_free(pool->slabs[i]);
        }
    }
    
    ngfw_free(pool->slabs);
    ngfw_free(pool);
}

u32 slab_pool_get_used_count(slab_pool_t *pool)
{
    if (!pool) return 0;
    
    u32 used = 0;
    for (u32 i = 0; i < pool->slab_count; i++) {
        if (pool->slabs[i]) {
            used += (pool->slabs[i]->total_objects - pool->slabs[i]->free_objects);
        }
    }
    return used;
}

u32 slab_pool_get_free_count(slab_pool_t *pool)
{
    if (!pool) return 0;
    
    u32 free_count = 0;
    for (u32 i = 0; i < pool->slab_count; i++) {
        if (pool->slabs[i]) {
            free_count += pool->slabs[i]->free_objects;
        }
    }
    return free_count;
}

void slab_pool_get_stats(slab_pool_t *pool, u64 *alloc_count, u64 *free_count, u32 *used, u32 *free_objs)
{
    if (!pool) return;
    
    if (alloc_count) *alloc_count = pool->alloc_count;
    if (free_count) *free_count = pool->free_count;
    if (used) *used = slab_pool_get_used_count(pool);
    if (free_objs) *free_objs = slab_pool_get_free_count(pool);
}
