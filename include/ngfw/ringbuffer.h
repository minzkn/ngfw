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

#ifndef NGFW_RINGBUFFER_H
#define NGFW_RINGBUFFER_H

#include "ngfw/types.h"
#include <stddef.h>
#include <stdbool.h>

typedef struct ringbuffer ringbuffer_t;

ringbuffer_t *ringbuffer_create(u32 capacity);
void ringbuffer_destroy(ringbuffer_t *rb);
bool ringbuffer_push(ringbuffer_t *rb, const void *data, u32 len);
bool ringbuffer_pop(ringbuffer_t *rb, void *data, u32 len);
bool ringbuffer_peek(ringbuffer_t *rb, void *data, u32 len);
u32 ringbuffer_available(ringbuffer_t *rb);
u32 ringbuffer_capacity(ringbuffer_t *rb);
void ringbuffer_clear(ringbuffer_t *rb);
bool ringbuffer_is_empty(ringbuffer_t *rb);
bool ringbuffer_is_full(ringbuffer_t *rb);

#endif
