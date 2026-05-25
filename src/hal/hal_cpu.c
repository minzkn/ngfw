/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#define _GNU_SOURCE
#include "ngfw/hal/cpu.h"
#include "ngfw/hal/memory.h"
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

static u32 cpu_count = 0;
static bool cpu_initialized = false;

ngfw_ret_t hal_cpu_init(void)
{
    if (cpu_initialized) {
        return NGFW_OK;
    }
    
    cpu_count = (u32)sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_count == 0) {
        cpu_count = 1;
    }
    
    cpu_initialized = true;
    return NGFW_OK;
}

void hal_cpu_shutdown(void)
{
    cpu_initialized = false;
}

u32 hal_cpu_get_id(void)
{
    return (u32)syscall(SYS_gettid) % NGFW_MAX_CPUS;
}

u32 hal_cpu_get_count(void)
{
    return cpu_count;
}

ngfw_ret_t hal_cpu_get_info(u32 cpu_id, hal_cpu_info_t *info)
{
    if (!info || cpu_id >= NGFW_MAX_CPUS) {
        return NGFW_ERR_INVALID;
    }
    
    memset(info, 0, sizeof(hal_cpu_info_t));
    info->cpu_id = cpu_id;
    info->numa_node = 0;
    
    return NGFW_OK;
}

ngfw_ret_t hal_cpu_set_affinity(u32 cpu_id)
{
    if (cpu_id >= NGFW_MAX_CPUS) {
        return NGFW_ERR_INVALID;
    }
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        return NGFW_ERR;
    }
    
    return NGFW_OK;
}

ngfw_ret_t hal_cpu_get_affinity(u32 *cpu_id)
{
    if (!cpu_id) {
        return NGFW_ERR_INVALID;
    }
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    
    if (pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        return NGFW_ERR;
    }
    
    for (int i = 0; i < NGFW_MAX_CPUS; i++) {
        if (CPU_ISSET(i, &cpuset)) {
            *cpu_id = i;
            break;
        }
    }
    
    return NGFW_OK;
}

u32 hal_cpu_get_numa_node(u32 cpu_id)
{
    (void)cpu_id;
    return 0;
}

void *hal_cpu_alloc_numa(size_t size, u32 numa_node)
{
    (void)numa_node;
    return hal_mem_alloc(size);
}

void hal_cpu_free_numa(void *ptr)
{
    hal_mem_free(ptr);
}
