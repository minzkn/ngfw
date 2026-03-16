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

#include "ngfw/ringbuffer.h"
#include "ngfw/memory.h"
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

struct ringbuffer {
    u8 *buffer;
    u32 capacity;
    u32 head;
    u32 tail;
    u32 count;
};

ringbuffer_t *ringbuffer_create(u32 capacity)
{
    if (capacity == 0) return NULL;
    
    ringbuffer_t *rb = ngfw_malloc(sizeof(ringbuffer_t));
    if (!rb) return NULL;
    
    rb->buffer = ngfw_malloc(capacity);
    if (!rb->buffer) {
        ngfw_free(rb);
        return NULL;
    }
    
    rb->capacity = capacity;
    rb->head = 0;
    rb->tail = 0;
    rb->count = 0;
    
    return rb;
}

void ringbuffer_destroy(ringbuffer_t *rb)
{
    if (!rb) return;
    if (rb->buffer) ngfw_free(rb->buffer);
    ngfw_free(rb);
}

bool ringbuffer_push(ringbuffer_t *rb, const void *data, u32 len)
{
    if (!rb || !data || len == 0) return false;
    if (rb->count + len > rb->capacity) return false;
    
    const u8 *src = (const u8 *)data;
    for (u32 i = 0; i < len; i++) {
        rb->buffer[rb->head] = src[i];
        rb->head = (rb->head + 1) % rb->capacity;
        rb->count++;
    }
    
    return true;
}

bool ringbuffer_pop(ringbuffer_t *rb, void *data, u32 len)
{
    if (!rb || !data || len == 0) return false;
    if (rb->count < len) return false;
    
    u8 *dst = (u8 *)data;
    for (u32 i = 0; i < len; i++) {
        dst[i] = rb->buffer[rb->tail];
        rb->tail = (rb->tail + 1) % rb->capacity;
        rb->count--;
    }
    
    return true;
}

bool ringbuffer_peek(ringbuffer_t *rb, void *data, u32 len)
{
    if (!rb || !data || len == 0) return false;
    if (rb->count < len) return false;
    
    u8 *dst = (u8 *)data;
    u32 idx = rb->tail;
    for (u32 i = 0; i < len; i++) {
        dst[i] = rb->buffer[idx];
        idx = (idx + 1) % rb->capacity;
    }
    
    return true;
}

u32 ringbuffer_available(ringbuffer_t *rb)
{
    return rb ? rb->count : 0;
}

u32 ringbuffer_capacity(ringbuffer_t *rb)
{
    return rb ? rb->capacity : 0;
}

void ringbuffer_clear(ringbuffer_t *rb)
{
    if (!rb) return;
    rb->head = 0;
    rb->tail = 0;
    rb->count = 0;
}

bool ringbuffer_is_empty(ringbuffer_t *rb)
{
    return rb ? rb->count == 0 : true;
}

bool ringbuffer_is_full(ringbuffer_t *rb)
{
    return rb ? rb->count >= rb->capacity : false;
}
