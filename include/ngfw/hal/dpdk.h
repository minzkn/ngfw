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

#ifndef NGFW_HAL_DPDK_H
#define NGFW_HAL_DPDK_H

#include "ngfw/types.h"

/*
 * DPDK Abstraction Layer
 * Optional high-performance packet I/O using DPDK
 */

#ifdef ENABLE_DPDK

/* Initialize DPDK subsystem */
ngfw_ret_t hal_dpdk_init(int argc, char **argv);
void hal_dpdk_shutdown(void);

/* Check if DPDK is available */
bool hal_dpdk_is_available(void);

/* DPDK-specific operations */
ngfw_ret_t hal_dpdk_port_probe(const char *pci_addr);
ngfw_ret_t hal_dpdk_port_configure(u32 port_id, u32 rx_queues, u32 tx_queues);
ngfw_ret_t hal_dpdk_port_start(u32 port_id);
void hal_dpdk_port_stop(u32 port_id);

#else /* ENABLE_DPDK */

static inline ngfw_ret_t hal_dpdk_init(int argc, char **argv) { (void)argc; (void)argv; return NGFW_ERR_NOT_SUPPORTED; }
static inline void hal_dpdk_shutdown(void) {}
static inline bool hal_dpdk_is_available(void) { return false; }
static inline ngfw_ret_t hal_dpdk_port_probe(const char *pci_addr) { (void)pci_addr; return NGFW_ERR_NOT_SUPPORTED; }
static inline ngfw_ret_t hal_dpdk_port_configure(u32 port_id, u32 rx_queues, u32 tx_queues) { (void)port_id; (void)rx_queues; (void)tx_queues; return NGFW_ERR_NOT_SUPPORTED; }
static inline ngfw_ret_t hal_dpdk_port_start(u32 port_id) { (void)port_id; return NGFW_ERR_NOT_SUPPORTED; }
static inline void hal_dpdk_port_stop(u32 port_id) { (void)port_id; }

#endif /* ENABLE_DPDK */

#endif
