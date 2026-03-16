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
