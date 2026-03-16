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

#include "ngfw/mempool.h"
#include "ngfw/memory.h"
#include <stddef.h>
#include <string.h>

#define MEMPOOL_MAGIC 0xDEADBEEF

typedef struct mem_block {
    struct mem_block *next;
    u32 magic;
} mem_block_t;

struct mem_pool {
    size_t block_size;
    u32 total_blocks;
    u32 available_blocks;
    mem_block_t *free_list;
    u8 *memory;
    u32 magic;
};

static u32 align_size(size_t size)
{
    if (size % 8 == 0) return size;
    return ((size / 8) + 1) * 8;
}

mem_pool_t *mempool_create(size_t block_size, u32 num_blocks)
{
    if (block_size == 0 || num_blocks == 0) return NULL;
    
    size_t aligned_size = align_size(block_size);
    size_t total_size = sizeof(mem_pool_t) + (aligned_size * num_blocks);
    
    mem_pool_t *pool = ngfw_malloc(total_size);
    if (!pool) return NULL;
    
    memset(pool, 0, sizeof(mem_pool_t));
    
    pool->block_size = aligned_size;
    pool->total_blocks = num_blocks;
    pool->available_blocks = num_blocks;
    pool->magic = MEMPOOL_MAGIC;
    pool->memory = (u8 *)pool + sizeof(mem_pool_t);
    
    mem_block_t *prev = NULL;
    for (u32 i = 0; i < num_blocks; i++) {
        mem_block_t *block = (mem_block_t *)(pool->memory + (i * aligned_size));
        block->next = prev;
        block->magic = MEMPOOL_MAGIC;
        prev = block;
    }
    pool->free_list = prev;
    
    return pool;
}

void mempool_destroy(mem_pool_t *pool)
{
    if (!pool || pool->magic != MEMPOOL_MAGIC) return;
    pool->magic = 0;
    ngfw_free(pool);
}

void *mempool_alloc(mem_pool_t *pool)
{
    if (!pool || pool->magic != MEMPOOL_MAGIC) return NULL;
    if (!pool->free_list) return NULL;
    
    mem_block_t *block = pool->free_list;
    pool->free_list = block->next;
    pool->available_blocks--;
    
    block->magic = MEMPOOL_MAGIC;
    return (void *)block;
}

void mempool_free(mem_pool_t *pool, void *ptr)
{
    if (!pool || pool->magic != MEMPOOL_MAGIC || !ptr) return;
    
    mem_block_t *block = (mem_block_t *)ptr;
    if (block->magic != MEMPOOL_MAGIC) return;
    
    block->next = pool->free_list;
    block->magic = 0;
    pool->free_list = block;
    pool->available_blocks++;
}

u32 mempool_available(mem_pool_t *pool)
{
    if (!pool || pool->magic != MEMPOOL_MAGIC) return 0;
    return pool->available_blocks;
}

u32 mempool_used(mem_pool_t *pool)
{
    if (!pool || pool->magic != MEMPOOL_MAGIC) return 0;
    return pool->total_blocks - pool->available_blocks;
}
