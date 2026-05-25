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

#ifndef NGFW_HAL_CPU_H
#define NGFW_HAL_CPU_H

#include "ngfw/types.h"

/*
 * CPU Abstraction Layer
 * Provides CPU information, affinity control, and per-CPU operations
 */

#define NGFW_MAX_CPUS 64

/* CPU information */
typedef struct hal_cpu_info {
    u32 cpu_id;
    u32 numa_node;
    u32 core_id;
    u32 thread_id;
    u64 cpu_freq_mhz;
    u64 cache_size[3];  /* L1, L2, L3 */
} hal_cpu_info_t;

/* Initialize CPU subsystem */
ngfw_ret_t hal_cpu_init(void);
void hal_cpu_shutdown(void);

/* Get current CPU ID */
u32 hal_cpu_get_id(void);

/* Get total CPU count */
u32 hal_cpu_get_count(void);

/* Get CPU info */
ngfw_ret_t hal_cpu_get_info(u32 cpu_id, hal_cpu_info_t *info);

/* Set thread affinity to specific CPU */
ngfw_ret_t hal_cpu_set_affinity(u32 cpu_id);

/* Get thread affinity */
ngfw_ret_t hal_cpu_get_affinity(u32 *cpu_id);

/* NUMA awareness */
u32 hal_cpu_get_numa_node(u32 cpu_id);
void *hal_cpu_alloc_numa(size_t size, u32 numa_node);
void hal_cpu_free_numa(void *ptr);

/* Per-CPU variables */
#define DEFINE_PER_CPU(type, name) \
    static __thread type per_cpu_##name

#define get_per_cpu(name) per_cpu_##name
#define set_per_cpu(name, val) (per_cpu_##name = (val))

#endif
