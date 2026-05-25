/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#include "ngfw/hal/memory.h"
#include "ngfw/hal/cpu.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define MEM_MAGIC 0xDEAD
#define NGFW_MEM_PERCPU_COUNT 64

typedef struct mem_header {
    u32 size;
    u16 magic;
    u8 padding[2];
} mem_header_t;

typedef struct percpu_mem_counter {
    size_t allocated;
    size_t peak;
    u8 pad[56];
} __attribute__((aligned(64))) percpu_mem_counter_t;

static percpu_mem_counter_t percpu_counters[NGFW_MEM_PERCPU_COUNT];
static pthread_mutex_t mem_lock = PTHREAD_MUTEX_INITIALIZER;
static bool mem_initialized = false;

static inline u32 get_percpu_index(void)
{
    uintptr_t stack_addr = (uintptr_t)&stack_addr;
    return (u32)(stack_addr >> 8) % NGFW_MEM_PERCPU_COUNT;
}

ngfw_ret_t hal_mem_init(void)
{
    pthread_mutex_lock(&mem_lock);
    if (mem_initialized) {
        pthread_mutex_unlock(&mem_lock);
        return NGFW_OK;
    }
    mem_initialized = true;
    memset(percpu_counters, 0, sizeof(percpu_counters));
    pthread_mutex_unlock(&mem_lock);
    return NGFW_OK;
}

void hal_mem_shutdown(void)
{
    pthread_mutex_lock(&mem_lock);
    mem_initialized = false;
    pthread_mutex_unlock(&mem_lock);
}

void *hal_mem_alloc(size_t size)
{
    if (!mem_initialized) hal_mem_init();
    
    mem_header_t *header = malloc(sizeof(mem_header_t) + size);
    if (header) {
        header->size = size;
        header->magic = MEM_MAGIC;
        
        u32 idx = get_percpu_index();
        percpu_counters[idx].allocated += size;
        if (percpu_counters[idx].allocated > percpu_counters[idx].peak) {
            percpu_counters[idx].peak = percpu_counters[idx].allocated;
        }
        
        return (u8 *)header + sizeof(mem_header_t);
    }
    return NULL;
}

void *hal_mem_calloc(size_t nmemb, size_t size)
{
    if (!mem_initialized) hal_mem_init();
    
    size_t total = nmemb * size;
    mem_header_t *header = malloc(sizeof(mem_header_t) + total);
    if (header) {
        memset(header, 0, sizeof(mem_header_t) + total);
        header->size = total;
        header->magic = MEM_MAGIC;
        
        u32 idx = get_percpu_index();
        percpu_counters[idx].allocated += total;
        if (percpu_counters[idx].allocated > percpu_counters[idx].peak) {
            percpu_counters[idx].peak = percpu_counters[idx].allocated;
        }
        
        return (u8 *)header + sizeof(mem_header_t);
    }
    return NULL;
}

void *hal_mem_realloc(void *ptr, size_t size)
{
    if (!mem_initialized) hal_mem_init();
    
    size_t old_size = 0;
    if (ptr) {
        mem_header_t *old_header = (mem_header_t *)((u8 *)ptr - sizeof(mem_header_t));
        if (old_header->magic == MEM_MAGIC) {
            old_size = old_header->size;
        }
    }
    
    mem_header_t *old_header = ptr ? (mem_header_t *)((u8 *)ptr - sizeof(mem_header_t)) : NULL;
    mem_header_t *new_header = realloc(old_header, sizeof(mem_header_t) + size);
    if (new_header) {
        new_header->size = size;
        new_header->magic = MEM_MAGIC;
        
        u32 idx = get_percpu_index();
        percpu_counters[idx].allocated = percpu_counters[idx].allocated - old_size + size;
        if (percpu_counters[idx].allocated > percpu_counters[idx].peak) {
            percpu_counters[idx].peak = percpu_counters[idx].allocated;
        }
        
        return (u8 *)new_header + sizeof(mem_header_t);
    }
    return NULL;
}

void hal_mem_free(void *ptr)
{
    if (ptr) {
        mem_header_t *header = (mem_header_t *)((u8 *)ptr - sizeof(mem_header_t));
        if (header->magic == MEM_MAGIC) {
            u32 idx = get_percpu_index();
            percpu_counters[idx].allocated -= header->size;
        }
        free(header);
    }
}

void *hal_mem_alloc_align(size_t size, size_t align)
{
    if (!mem_initialized) hal_mem_init();
    
    void *ptr = NULL;
    if (posix_memalign(&ptr, align, size) == 0) {
        return ptr;
    }
    return NULL;
}

hal_mem_stats_t *hal_mem_get_stats(void)
{
    static hal_mem_stats_t stats;
    size_t total_allocated = 0;
    size_t total_peak = 0;
    
    for (int i = 0; i < NGFW_MEM_PERCPU_COUNT; i++) {
        total_allocated += percpu_counters[i].allocated;
        total_peak += percpu_counters[i].peak;
    }
    
    stats.allocated = total_allocated;
    stats.peak = total_peak;
    return &stats;
}

size_t hal_mem_get_allocated(void)
{
    size_t total = 0;
    for (int i = 0; i < NGFW_MEM_PERCPU_COUNT; i++) {
        total += percpu_counters[i].allocated;
    }
    return total;
}

size_t hal_mem_get_peak(void)
{
    size_t total = 0;
    for (int i = 0; i < NGFW_MEM_PERCPU_COUNT; i++) {
        total += percpu_counters[i].peak;
    }
    return total;
}

void hal_mem_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = ptr;
    while (len--) {
        *p++ = 0;
    }
}
