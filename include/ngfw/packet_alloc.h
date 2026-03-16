#ifndef NGFW_PACKET_ALLOC_H
#define NGFW_PACKET_ALLOC_H

#include "ngfw/types.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct packet_allocator packet_allocator_t;

packet_allocator_t *packet_allocator_create(u32 pool_size, u32 mtu);
void packet_allocator_destroy(packet_allocator_t *alloc);
void *packet_alloc(packet_allocator_t *alloc, u32 size);
void packet_free(packet_allocator_t *alloc, void *ptr);
u32 packet_allocator_available(packet_allocator_t *alloc);
u32 packet_allocator_used(packet_allocator_t *alloc);

typedef struct packet_buf {
    void *data;
    u32 capacity;
    u32 length;
    u32 refcount;
    packet_allocator_t *allocator;
} packet_buf_t;

packet_buf_t *packet_buf_create(packet_allocator_t *alloc);
void packet_buf_destroy(packet_buf_t *pkt);
void packet_buf_ref(packet_buf_t *pkt);
void packet_buf_unref(packet_buf_t *pkt);

#endif
