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

#define _GNU_SOURCE
#include "ngfw/capture.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <pthread.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#ifndef IFF_PROMISC
#define IFF_PROMISC 0x100
#endif

#define CAPTURE_BUFFER_SIZE 65536

capture_t *capture_create(const char *interface_name)
{
    if (!interface_name) return NULL;

    capture_t *capture = ngfw_malloc(sizeof(capture_t));
    if (!capture) return NULL;

    memset(capture, 0, sizeof(capture_t));
    strncpy(capture->interface_name, interface_name, sizeof(capture->interface_name) - 1);
    capture->mode = CAPTURE_MODE_PROMISCUOUS;
    capture->socket_fd = -1;
    capture->running = false;

    return capture;
}

void capture_destroy(capture_t *capture)
{
    if (!capture) return;

    if (capture->running) {
        capture_stop(capture);
    }

    if (capture->socket_fd >= 0) {
        close(capture->socket_fd);
    }

    ngfw_free(capture);
}

ngfw_ret_t capture_set_mode(capture_t *capture, capture_mode_t mode)
{
    if (!capture) return NGFW_ERR_INVALID;
    capture->mode = mode;
    return NGFW_OK;
}

ngfw_ret_t capture_set_filter(capture_t *capture, const char *filter_exp)
{
    if (!capture || !filter_exp) return NGFW_ERR_INVALID;
    
    log_info("Capture filter set: %s", filter_exp);
    return NGFW_OK;
}

ngfw_ret_t capture_set_callback(capture_t *capture, capture_callback_t callback, void *user_data)
{
    if (!capture) return NGFW_ERR_INVALID;
    capture->callback = callback;
    capture->user_data = user_data;
    return NGFW_OK;
}

static pthread_t capture_thread_handle;
static bool thread_created = false;

static void *capture_thread(void *arg)
{
    capture_t *capture = (capture_t *)arg;
    u8 buffer[CAPTURE_BUFFER_SIZE];

    log_info("Capture thread started on interface %s", capture->interface_name);

    while (capture->running) {
        ssize_t len = read(capture->socket_fd, buffer, sizeof(buffer));

        if (len < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            capture->stats.errors++;
            log_err("Capture read error: %s", strerror(errno));
            break;
        }

        if (len == 0) {
            continue;
        }

        packet_t *pkt = packet_create(len);
        if (!pkt) {
            capture->stats.packets_dropped++;
            continue;
        }

        packet_append(pkt, buffer, len);
        pkt->timestamp = get_us_time();

        capture->stats.packets_captured++;
        capture->stats.bytes_captured += len;

        if (capture->callback) {
            capture->callback(capture, pkt, capture->user_data);
        } else {
            packet_destroy(pkt);
        }
    }

    log_info("Capture thread stopped on interface %s", capture->interface_name);

    return NULL;
}

ngfw_ret_t capture_start(capture_t *capture)
{
    if (!capture) return NGFW_ERR_INVALID;
    if (capture->running) return NGFW_OK;

    capture->socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (capture->socket_fd < 0) {
        log_err("Failed to create packet socket: %s", strerror(errno));
        return NGFW_ERR;
    }

    int opt = 1;
    if (setsockopt(capture->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_warn("Failed to set SO_REUSEADDR");
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%.15s", capture->interface_name);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(capture->socket_fd, SIOCGIFINDEX, &ifr) < 0) {
        log_err("Failed to get interface index: %s", strerror(errno));
        close(capture->socket_fd);
        capture->socket_fd = -1;
        return NGFW_ERR;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifr.ifr_ifindex;

    if (bind(capture->socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_err("Failed to bind socket: %s", strerror(errno));
        close(capture->socket_fd);
        capture->socket_fd = -1;
        return NGFW_ERR;
    }

    if (capture->mode == CAPTURE_MODE_PROMISCUOUS) {
        if (ioctl(capture->socket_fd, SIOCGIFFLAGS, &ifr) < 0) {
            log_warn("Failed to get interface flags");
        } else {
            ifr.ifr_flags |= IFF_PROMISC;
            if (ioctl(capture->socket_fd, SIOCSIFFLAGS, &ifr) < 0) {
                log_warn("Failed to set promiscuous mode");
            }
        }
    }

    capture->running = true;
    capture->stats.start_time = get_ms_time();

    int ret = pthread_create(&capture_thread_handle, NULL, capture_thread, capture);
    if (ret != 0) {
        log_err("Failed to create capture thread: %s", strerror(ret));
        capture->running = false;
        close(capture->socket_fd);
        capture->socket_fd = -1;
        return NGFW_ERR;
    }
    thread_created = true;

    log_info("Capture started on interface %s", capture->interface_name);

    return NGFW_OK;
}

ngfw_ret_t capture_stop(capture_t *capture)
{
    if (!capture) return NGFW_ERR_INVALID;
    if (!capture->running) return NGFW_OK;

    capture->running = false;

    if (thread_created) {
        pthread_join(capture_thread_handle, NULL);
        thread_created = false;
    }

    if (capture->socket_fd >= 0) {
        close(capture->socket_fd);
        capture->socket_fd = -1;
    }

    log_info("Capture stopped on interface %s", capture->interface_name);

    return NGFW_OK;
}

capture_stats_t *capture_get_stats(capture_t *capture)
{
    return capture ? &capture->stats : NULL;
}

void capture_reset_stats(capture_t *capture)
{
    if (capture) {
        memset(&capture->stats, 0, sizeof(capture_stats_t));
        capture->stats.start_time = get_ms_time();
    }
}

packet_ring_t *packet_ring_create(const char *interface, u32 capacity)
{
    (void)interface;
    (void)capacity;
    return NULL;
}

void packet_ring_destroy(packet_ring_t *ring)
{
    (void)ring;
}

ngfw_ret_t packet_ring_start(packet_ring_t *ring)
{
    (void)ring;
    return NGFW_OK;
}

ngfw_ret_t packet_ring_stop(packet_ring_t *ring)
{
    (void)ring;
    return NGFW_OK;
}

packet_t *packet_ring_read(packet_ring_t *ring)
{
    (void)ring;
    return NULL;
}

u32 packet_ring_pending(packet_ring_t *ring)
{
    (void)ring;
    return 0;
}
