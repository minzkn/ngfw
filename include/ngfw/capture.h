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

#ifndef NGFW_CAPTURE_H
#define NGFW_CAPTURE_H

#include "types.h"
#include "packet.h"

typedef enum {
    CAPTURE_MODE_PROMISCUOUS,
    CAPTURE_MODE_NON_PROMISCUOUS,
    CAPTURE_MODE_KERNEL_BYPASS
} capture_mode_t;

typedef struct capture_stats {
    u64 packets_captured;
    u64 packets_dropped;
    u64 bytes_captured;
    u64 errors;
    u64 start_time;
} capture_stats_t;

typedef struct capture capture_t;

typedef void (*capture_callback_t)(capture_t *capture, packet_t *pkt, void *user_data);

struct capture {
    int socket_fd;
    char interface_name[32];
    capture_mode_t mode;
    bool running;
    capture_callback_t callback;
    void *user_data;
    capture_stats_t stats;
};

capture_t *capture_create(const char *interface_name);
void capture_destroy(capture_t *capture);

ngfw_ret_t capture_set_mode(capture_t *capture, capture_mode_t mode);
ngfw_ret_t capture_set_filter(capture_t *capture, const char *filter_exp);
ngfw_ret_t capture_set_callback(capture_t *capture, capture_callback_t callback, void *user_data);

ngfw_ret_t capture_start(capture_t *capture);
ngfw_ret_t capture_stop(capture_t *capture);

capture_stats_t *capture_get_stats(capture_t *capture);
void capture_reset_stats(capture_t *capture);

typedef struct packet_ring {
    packet_t **packets;
    u32 capacity;
    u32 read_idx;
    u32 write_idx;
    u32 count;
    int fd;
    void *mmap_addr;
    size_t mmap_size;
} packet_ring_t;

packet_ring_t *packet_ring_create(const char *interface, u32 capacity);
void packet_ring_destroy(packet_ring_t *ring);
ngfw_ret_t packet_ring_start(packet_ring_t *ring);
ngfw_ret_t packet_ring_stop(packet_ring_t *ring);
packet_t *packet_ring_read(packet_ring_t *ring);
u32 packet_ring_pending(packet_ring_t *ring);

#endif
