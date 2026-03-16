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

#ifndef NGFW_MEMPOOL_H
#define NGFW_MEMPOOL_H

#include "ngfw/types.h"
#include <stddef.h>

typedef struct mem_pool mem_pool_t;

mem_pool_t *mempool_create(size_t block_size, u32 num_blocks);
void mempool_destroy(mem_pool_t *pool);
void *mempool_alloc(mem_pool_t *pool);
void mempool_free(mem_pool_t *pool, void *ptr);
u32 mempool_available(mem_pool_t *pool);
u32 mempool_used(mem_pool_t *pool);

#endif
