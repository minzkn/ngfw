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

#include "ngfw/memory.h"
#include "ngfw/log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define MEM_MAGIC 0xDEADEEF

typedef struct mem_header {
    size_t size;
    u32 magic;
} mem_header_t;

static size_t allocated_memory = 0;
static size_t peak_memory = 0;
static bool mem_initialized = false;
static pthread_mutex_t mem_lock = PTHREAD_MUTEX_INITIALIZER;

static mem_header_t *get_header(void *ptr)
{
    if (!ptr) return NULL;
    return (mem_header_t *)((u8 *)ptr - sizeof(mem_header_t));
}

static void *get_data(mem_header_t *header)
{
    if (!header) return NULL;
    return (u8 *)header + sizeof(mem_header_t);
}

void ngfw_mem_init(void)
{
    pthread_mutex_lock(&mem_lock);
    if (mem_initialized) {
        pthread_mutex_unlock(&mem_lock);
        return;
    }
    mem_initialized = true;
    allocated_memory = 0;
    peak_memory = 0;
    pthread_mutex_unlock(&mem_lock);
}

void *ngfw_malloc(size_t size)
{
    if (!mem_initialized) ngfw_mem_init();
    
    mem_header_t *header = malloc(sizeof(mem_header_t) + size);
    if (header) {
        header->size = size;
        header->magic = MEM_MAGIC;
        
        pthread_mutex_lock(&mem_lock);
        allocated_memory += size;
        if (allocated_memory > peak_memory) {
            peak_memory = allocated_memory;
        }
        pthread_mutex_unlock(&mem_lock);
        
        return get_data(header);
    }
    return NULL;
}

void *ngfw_calloc(size_t nmemb, size_t size)
{
    if (!mem_initialized) ngfw_mem_init();
    
    size_t total = nmemb * size;
    mem_header_t *header = malloc(sizeof(mem_header_t) + total);
    if (header) {
        memset(header, 0, sizeof(mem_header_t) + total);
        header->size = total;
        header->magic = MEM_MAGIC;
        
        pthread_mutex_lock(&mem_lock);
        allocated_memory += total;
        if (allocated_memory > peak_memory) {
            peak_memory = allocated_memory;
        }
        pthread_mutex_unlock(&mem_lock);
        
        return get_data(header);
    }
    return NULL;
}

void *ngfw_realloc(void *ptr, size_t size)
{
    if (!mem_initialized) ngfw_mem_init();
    
    size_t old_size = 0;
    mem_header_t *old_header = get_header(ptr);
    if (old_header && old_header->magic == MEM_MAGIC) {
        old_size = old_header->size;
    }
    
    mem_header_t *new_header = realloc(old_header, sizeof(mem_header_t) + size);
    if (new_header) {
        new_header->size = size;
        new_header->magic = MEM_MAGIC;
        
        pthread_mutex_lock(&mem_lock);
        allocated_memory = allocated_memory - old_size + size;
        if (allocated_memory > peak_memory) {
            peak_memory = allocated_memory;
        }
        pthread_mutex_unlock(&mem_lock);
        
        return get_data(new_header);
    }
    return NULL;
}

void ngfw_free(void *ptr)
{
    if (ptr) {
        mem_header_t *header = get_header(ptr);
        if (header && header->magic == MEM_MAGIC) {
            pthread_mutex_lock(&mem_lock);
            allocated_memory -= header->size;
            pthread_mutex_unlock(&mem_lock);
        }
        free(header);
    }
}

void *ngfw_alloc_align(size_t size, size_t align)
{
    if (!mem_initialized) ngfw_mem_init();
    
    void *ptr = NULL;
    if (posix_memalign(&ptr, align, size) == 0) {
        return ptr;
    }
    return NULL;
}

size_t ngfw_get_allocated_memory(void)
{
    size_t val;
    pthread_mutex_lock(&mem_lock);
    val = allocated_memory;
    pthread_mutex_unlock(&mem_lock);
    return val;
}

size_t ngfw_get_peak_memory(void)
{
    size_t val;
    pthread_mutex_lock(&mem_lock);
    val = peak_memory;
    pthread_mutex_unlock(&mem_lock);
    return val;
}

void ngfw_memzero(void *ptr, size_t len)
{
    volatile unsigned char *p = ptr;
    while (len--) {
        *p++ = 0;
    }
}
