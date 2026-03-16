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

#ifndef NGFW_MEMORY_H
#define NGFW_MEMORY_H

#include "types.h"

void *ngfw_malloc(size_t size);
void *ngfw_calloc(size_t nmemb, size_t size);
void *ngfw_realloc(void *ptr, size_t size);
void ngfw_free(void *ptr);
void *ngfw_alloc_align(size_t size, size_t align);
void ngfw_mem_init(void);

size_t ngfw_get_allocated_memory(void);
size_t ngfw_get_peak_memory(void);

#ifndef NGFW_DISABLE_MEMZERO
void ngfw_memzero(void *ptr, size_t len);
#else
#define ngfw_memzero(ptr, len)
#endif

#endif
