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
