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

#ifndef NGFW_HAL_NETIF_H
#define NGFW_HAL_NETIF_H

#include "ngfw/types.h"

/*
 * Network Interface Abstraction Layer
 * Provides uniform access to network interfaces (kernel, DPDK, AF_PACKET)
 */

#define NGFW_MAX_INTERFACES 32
#define NGFW_IF_NAME_SIZE 64

/* Interface types */
typedef enum {
    HAL_NETIF_TYPE_KERNEL,
    HAL_NETIF_TYPE_DPDK,
    HAL_NETIF_TYPE_AF_PACKET,
    HAL_NETIF_TYPE_NETMAP
} hal_netif_type_t;

/* Interface statistics */
typedef struct hal_netif_stats {
    u64 rx_packets;
    u64 rx_bytes;
    u64 rx_errors;
    u64 rx_dropped;
    u64 tx_packets;
    u64 tx_bytes;
    u64 tx_errors;
    u64 tx_dropped;
} hal_netif_stats_t;

/* Interface configuration */
typedef struct hal_netif_config {
    char name[NGFW_IF_NAME_SIZE];
    hal_netif_type_t type;
    u32 queue_count;
    u32 mtu;
    u8 mac_addr[6];
    u32 ip_addr;
    u32 netmask;
} hal_netif_config_t;

/* Interface handle */
typedef struct hal_netif hal_netif_t;

/* Initialize network interface subsystem */
ngfw_ret_t hal_netif_init(void);
void hal_netif_shutdown(void);

/* Enumerate interfaces */
ngfw_ret_t hal_netif_enumerate(hal_netif_config_t *configs, u32 *count);

/* Open/close interface */
ngfw_ret_t hal_netif_open(const hal_netif_config_t *config, hal_netif_t **netif);
void hal_netif_close(hal_netif_t *netif);

/* Interface operations */
ngfw_ret_t hal_netif_set_promiscuous(hal_netif_t *netif, bool enable);
ngfw_ret_t hal_netif_set_mtu(hal_netif_t *netif, u32 mtu);
ngfw_ret_t hal_netif_get_stats(hal_netif_t *netif, hal_netif_stats_t *stats);

/* Packet I/O */
ngfw_ret_t hal_netif_receive(hal_netif_t *netif, void **pkts, u32 *count, u32 max_pkts);
ngfw_ret_t hal_netif_transmit(hal_netif_t *netif, void **pkts, u32 count);

#endif
