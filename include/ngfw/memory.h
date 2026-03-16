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
