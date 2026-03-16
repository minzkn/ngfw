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

#include "ngfw/packet_alloc.h"
#include "ngfw/memory.h"
#include "ngfw/platform.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#define DEFAULT_MTU 1500

struct packet_chunk {
    struct packet_chunk *next;
    u8 *data;
    u32 size;
    u32 used;
};

struct packet_allocator {
    struct packet_chunk *chunks;
    u32 chunk_size;
    u32 mtu;
    u32 total_allocated;
    u32 total_used;
    pthread_mutex_t lock;
};

packet_allocator_t *packet_allocator_create(u32 pool_size, u32 mtu)
{
    if (mtu == 0) mtu = DEFAULT_MTU;
    if (pool_size == 0) pool_size = 256;
    
    packet_allocator_t *alloc = ngfw_malloc(sizeof(packet_allocator_t));
    if (!alloc) return NULL;
    
    alloc->chunk_size = pool_size * mtu;
    alloc->mtu = mtu;
    alloc->chunks = NULL;
    alloc->total_allocated = 0;
    alloc->total_used = 0;
    pthread_mutex_init(&alloc->lock, NULL);
    
    return alloc;
}

void packet_allocator_destroy(packet_allocator_t *alloc)
{
    if (!alloc) return;
    
    pthread_mutex_lock(&alloc->lock);
    
    struct packet_chunk *chunk = alloc->chunks;
    while (chunk) {
        struct packet_chunk *next = chunk->next;
        ngfw_free(chunk->data);
        ngfw_free(chunk);
        chunk = next;
    }
    
    pthread_mutex_unlock(&alloc->lock);
    pthread_mutex_destroy(&alloc->lock);
    ngfw_free(alloc);
}

static struct packet_chunk *create_chunk(packet_allocator_t *alloc)
{
    struct packet_chunk *chunk = ngfw_malloc(sizeof(struct packet_chunk));
    if (!chunk) return NULL;
    
    chunk->data = ngfw_malloc(alloc->chunk_size);
    if (!chunk->data) {
        ngfw_free(chunk);
        return NULL;
    }
    
    chunk->size = alloc->chunk_size;
    chunk->used = 0;
    chunk->next = alloc->chunks;
    alloc->chunks = chunk;
    alloc->total_allocated += chunk->size;
    
    return chunk;
}

void *packet_alloc(packet_allocator_t *alloc, u32 size)
{
    if (!alloc || size == 0) return NULL;
    
    if (size > alloc->mtu) {
        return ngfw_malloc(size);
    }
    
    pthread_mutex_lock(&alloc->lock);
    
    struct packet_chunk *chunk = alloc->chunks;
    
    while (chunk) {
        if (chunk->used + size <= chunk->size) {
            void *ptr = chunk->data + chunk->used;
            chunk->used += size;
            alloc->total_used += size;
            pthread_mutex_unlock(&alloc->lock);
            return ptr;
        }
        chunk = chunk->next;
    }
    
    chunk = create_chunk(alloc);
    if (!chunk) {
        pthread_mutex_unlock(&alloc->lock);
        return ngfw_malloc(size);
    }
    
    void *ptr = chunk->data;
    chunk->used = size;
    alloc->total_used += size;
    
    pthread_mutex_unlock(&alloc->lock);
    return ptr;
}

void packet_free(packet_allocator_t *alloc, void *ptr)
{
    if (!alloc || !ptr) return;
    
    pthread_mutex_lock(&alloc->lock);
    
    struct packet_chunk *chunk = alloc->chunks;
    while (chunk) {
        u8 *chunk_start = chunk->data;
        u8 *chunk_end = chunk->data + chunk->size;
        if ((u8 *)ptr >= chunk_start && (u8 *)ptr < chunk_end) {
            pthread_mutex_unlock(&alloc->lock);
            return;
        }
        chunk = chunk->next;
    }
    
    pthread_mutex_unlock(&alloc->lock);
    ngfw_free(ptr);
}

u32 packet_allocator_available(packet_allocator_t *alloc)
{
    if (!alloc) return 0;
    u32 available;
    pthread_mutex_lock(&alloc->lock);
    available = alloc->total_allocated - alloc->total_used;
    pthread_mutex_unlock(&alloc->lock);
    return available;
}

u32 packet_allocator_used(packet_allocator_t *alloc)
{
    if (!alloc) return 0;
    u32 used;
    pthread_mutex_lock(&alloc->lock);
    used = alloc->total_used;
    pthread_mutex_unlock(&alloc->lock);
    return used;
}

packet_buf_t *packet_buf_create(packet_allocator_t *alloc)
{
    packet_buf_t *pkt = ngfw_malloc(sizeof(packet_buf_t));
    if (!pkt) return NULL;
    
    pkt->data = packet_alloc(alloc, alloc->mtu);
    if (!pkt->data) {
        ngfw_free(pkt);
        return NULL;
    }
    
    pkt->capacity = alloc->mtu;
    pkt->length = 0;
    pkt->refcount = 1;
    pkt->allocator = alloc;
    
    return pkt;
}

void packet_buf_destroy(packet_buf_t *pkt)
{
    if (!pkt) return;
    
    if (pkt->allocator && pkt->capacity <= pkt->allocator->mtu) {
        packet_free(pkt->allocator, pkt->data);
    } else {
        ngfw_free(pkt->data);
    }
    
    ngfw_free(pkt);
}

void packet_buf_ref(packet_buf_t *pkt)
{
    if (!pkt) return;
    pkt->refcount++;
}

void packet_buf_unref(packet_buf_t *pkt)
{
    if (!pkt) return;
    
    pkt->refcount--;
    if (pkt->refcount == 0) {
        packet_buf_destroy(pkt);
    }
}
