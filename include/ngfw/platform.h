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

#ifndef NGFW_PLATFORM_H
#define NGFW_PLATFORM_H

#include "types.h"

typedef struct cpu_capability {
    bool has_aesni;
    bool has_avx;
    bool has_avx2;
    bool has_avx512;
    bool has_sse42;
    bool has_pclmulqdq;
    bool has_rdrand;
    bool has_neon;
    bool has_arm_crypto;
    bool has_riscv_vector;
    u32 cache_line_size;
    u32 num_cores;
    char cpu_model[128];
    char arch[32];
} cpu_capability_t;

typedef struct system_info {
    u64 total_memory;
    u64 free_memory;
    u32 num_cpus;
    u32 num_numa_nodes;
    char kernel_version[64];
    int kernel_major;
    int kernel_minor;
    int kernel_patch;
} system_info_t;

void cpu_detect(cpu_capability_t *cap);
void sysinfo_get(system_info_t *info);
u64 get_ticks_per_second(void);
u64 get_tick_count(void);
u64 get_ms_time(void);
u64 get_us_time(void);
void sleep_ms(u32 ms);
void sleep_us(u32 us);

#endif
