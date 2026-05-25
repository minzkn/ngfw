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

#ifndef NGFW_HAL_MEMORY_H
#define NGFW_HAL_MEMORY_H

#include "ngfw/types.h"
#include <stddef.h>

/*
 * Memory Abstraction Layer
 * Provides memory allocation with NUMA awareness and tracking
 */

/* Memory zone types */
typedef enum {
    HAL_MEM_ZONE_DEFAULT,
    HAL_MEM_ZONE_DMA,
    HAL_MEM_ZONE_HUGEPAGE,
    HAL_MEM_ZONE_SHARED
} hal_mem_zone_t;

/* Memory statistics */
typedef struct hal_mem_stats {
    size_t allocated;
    size_t peak;
    size_t free;
    u32 alloc_count;
    u32 free_count;
    u32 fail_count;
} hal_mem_stats_t;

/* Initialize memory subsystem */
ngfw_ret_t hal_mem_init(void);
void hal_mem_shutdown(void);

/* Standard allocation */
void *hal_mem_alloc(size_t size);
void *hal_mem_calloc(size_t nmemb, size_t size);
void *hal_mem_realloc(void *ptr, size_t size);
void hal_mem_free(void *ptr);

/* Aligned allocation */
void *hal_mem_alloc_align(size_t size, size_t align);

/* NUMA-aware allocation */
void *hal_mem_alloc_numa(size_t size, u32 numa_node);
void hal_mem_free_numa(void *ptr);

/* Memory zone allocation */
void *hal_mem_alloc_zone(size_t size, hal_mem_zone_t zone);
void hal_mem_free_zone(void *ptr, hal_mem_zone_t zone);

/* Memory tracking */
hal_mem_stats_t *hal_mem_get_stats(void);
void hal_mem_reset_stats(void);
size_t hal_mem_get_allocated(void);
size_t hal_mem_get_peak(void);

/* Zero memory (secure) */
void hal_mem_zero(void *ptr, size_t len);

#endif
