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

#include "ngfw/dpdk.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"

#ifdef ENABLE_DPDK

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_launch.h>
#include <pthread.h>
#include <signal.h>

static dpdk_capture_t g_dpdk;
static dpdk_packet_handler_t g_handler;
static void *g_user_data;
static pthread_t g_capture_thread;
static volatile bool g_capture_running;

static int eth_dev_configure_wrap(u16 port_id, u16 nb_rx_q, u16 nb_tx_q,
                                   const struct rte_eth_conf *eth_conf)
{
    if (port_id >= RTE_MAX_ETHPORTS) return -1;
    return rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q, eth_conf);
}

static int eth_rx_queue_setup_wrap(u16 port_id, u16 rx_queue_id, u16 nb_rx_desc,
                                   unsigned int socket_id, const struct rte_eth_rxconf *rx_conf,
                                   struct rte_mempool *mp)
{
    if (port_id >= RTE_MAX_ETHPORTS) return -1;
    return rte_eth_rx_queue_setup(port_id, rx_queue_id, nb_rx_desc, socket_id, rx_conf, mp);
}

static int eth_tx_queue_setup_wrap(u16 port_id, u16 tx_queue_id, u16 nb_tx_desc,
                                   unsigned int socket_id, const struct rte_eth_txconf *tx_conf,
                                   struct rte_mempool *mp)
{
    if (port_id >= RTE_MAX_ETHPORTS) return -1;
    return rte_eth_tx_queue_setup(port_id, tx_queue_id, nb_tx_desc, socket_id, tx_conf, mp);
}

static int eth_dev_start_wrap(u16 port_id)
{
    if (port_id >= RTE_MAX_ETHPORTS) return -1;
    return rte_eth_dev_start(port_id);
}

static int eth_promiscuous_enable_wrap(u16 port_id)
{
    if (port_id >= RTE_MAX_ETHPORTS) return -1;
    return rte_eth_promiscuous_enable(port_id);
}

static int eth_stats_get_wrap(u16 port_id, struct rte_eth_stats *stats)
{
    if (port_id >= RTE_MAX_ETHPORTS) return -1;
    return rte_eth_stats_get(port_id, stats);
}

static int eth_stats_reset_wrap(u16 port_id)
{
    if (port_id >= RTE_MAX_ETHPORTS) return -1;
    return rte_eth_stats_reset(port_id);
}

static int eth_dev_stop_wrap(u16 port_id)
{
    if (port_id >= RTE_MAX_ETHPORTS) return -1;
    return rte_eth_dev_stop(port_id);
}

int dpdk_init(dpdk_config_t *config)
{
    if (g_dpdk.initialized) {
        log_warn("DPDK already initialized");
        return NGFW_OK;
    }

    int ret;
    struct rte_fporc_conf fporc_conf;
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_NONE,
            .offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER,
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
            .offloads = RTE_ETH_TX_OFFLOAD_CHECKSUM | RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
        },
    };

    ret = rte_eal_init(config->argc, config->argv);
    if (ret < 0) {
        log_err("Failed to initialize DPDK EAL");
        return NGFW_ERR;
    }

    u32 nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        log_warn("No Ethernet ports available for DPDK");
        rte_eal_cleanup();
        return NGFW_ERR_NOENT;
    }

    char mbuf_pool_name[32];
    snprintf(mbuf_pool_name, sizeof(mbuf_pool_name), "mbuf_pool_%d", rte_lcore_id());
    
    g_dpdk.mempool = rte_pktmbuf_pool_create(mbuf_pool_name,
                                              config->mbuf_pool_size,
                                              DPDK_MBUF_CACHE_SIZE, 0,
                                              RTE_MBUF_DEFAULT_BUF_SIZE,
                                              rte_socket_id());
    if (!g_dpdk.mempool) {
        log_err("Failed to create mbuf pool");
        rte_eal_cleanup();
        return NGFW_ERR;
    }

    for (u16 port_id = 0; port_id < nb_ports && port_id < DPDK_MAX_PORTS; port_id++) {
        struct rte_eth_dev_info dev_info;
        ret = rte_eth_dev_info_get(port_id, &dev_info);
        if (ret != 0) continue;

        dpdk_port_t *port = &g_dpdk.ports[port_id];
        port->port_id = port_id;
        strncpy(port->name, dev_info.device->name, sizeof(port->name) - 1);
        port->enabled = true;
        port->rx_queues = config->nb_queues;
        port->tx_queues = config->nb_queues;
        port->mempool = g_dpdk.mempool;

        ret = eth_dev_configure_wrap(port_id, config->nb_queues, config->nb_queues, &port_conf);
        if (ret < 0) {
            log_err("Failed to configure port %u", port_id);
            continue;
        }

        for (u16 q = 0; q < config->nb_queues; q++) {
            ret = eth_rx_queue_setup_wrap(port_id, q, config->rx_desc,
                                          rte_socket_id(), NULL, g_dpdk.mempool);
            if (ret < 0) {
                log_err("Failed to setup RX queue %u on port %u", q, port_id);
                continue;
            }

            ret = eth_tx_queue_setup_wrap(port_id, q, config->tx_desc,
                                          rte_socket_id(), NULL, g_dpdk.mempool);
            if (ret < 0) {
                log_err("Failed to setup TX queue %u on port %u", q, port_id);
                continue;
            }
        }

        ret = eth_dev_start_wrap(port_id);
        if (ret < 0) {
            log_err("Failed to start port %u", port_id);
            continue;
        }

        if (config->promiscuous) {
            eth_promiscuous_enable_wrap(port_id);
        }

        log_info("DPDK port %u (%s) started", port_id, port->name);
    }

    g_dpdk.nb_ports = nb_ports;
    g_dpdk.initialized = true;

    log_info("DPDK initialized with %u ports", nb_ports);
    return NGFW_OK;
}

void dpdk_shutdown(void)
{
    if (!g_dpdk.initialized) return;

    g_capture_running = false;

    for (u16 port_id = 0; port_id < g_dpdk.nb_ports; port_id++) {
        eth_dev_stop_wrap(port_id);
        rte_eth_dev_close(port_id);
    }

    if (g_dpdk.mempool) {
        rte_mempool_free(g_dpdk.mempool);
    }

    rte_eal_cleanup();
    g_dpdk.initialized = false;

    log_info("DPDK shutdown complete");
}

int dpdk_port_start(u16 port_id)
{
    if (!g_dpdk.initialized) return NGFW_ERR_INVALID;
    if (port_id >= g_dpdk.nb_ports) return NGFW_ERR_NOENT;
    
    return eth_dev_start_wrap(port_id);
}

int dpdk_port_stop(u16 port_id)
{
    if (!g_dpdk.initialized) return NGFW_ERR_INVALID;
    if (port_id >= g_dpdk.nb_ports) return NGFW_ERR_NOENT;
    
    return eth_dev_stop_wrap(port_id);
}

int dpdk_rx_burst(u16 port_id, u16 queue_id, struct rte_mbuf **rx_pkts, u16 nb_pkts)
{
    if (!g_dpdk.initialized) return 0;
    if (port_id >= g_dpdk.nb_ports) return 0;
    
    return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

int dpdk_tx_burst(u16 port_id, u16 queue_id, struct rte_mbuf **tx_pkts, u16 nb_pkts)
{
    if (!g_dpdk.initialized) return 0;
    if (port_id >= g_dpdk.nb_ports) return 0;
    
    return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

struct rte_mbuf *dpdk_alloc_mbuf(void)
{
    if (!g_dpdk.initialized) return NULL;
    
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(g_dpdk.mempool);
    return mbuf;
}

void dpdk_free_mbuf(struct rte_mbuf *mbuf)
{
    if (mbuf) {
        rte_pktmbuf_free(mbuf);
    }
}

int dpdk_get_port_stats(u16 port_id, struct rte_eth_stats *stats)
{
    if (!g_dpdk.initialized) return NGFW_ERR_INVALID;
    if (port_id >= g_dpdk.nb_ports) return NGFW_ERR_NOENT;
    
    return eth_stats_get_wrap(port_id, stats);
}

void dpdk_clear_port_stats(u16 port_id)
{
    if (!g_dpdk.initialized) return;
    if (port_id >= g_dpdk.nb_ports) return;
    
    eth_stats_reset_wrap(port_id);
}

u16 dpdk_get_nb_ports(void)
{
    return g_dpdk.nb_ports;
}

u16 dpdk_get_port_by_name(const char *name)
{
    if (!g_dpdk.initialized || !name) return RTE_MAX_ETHPORTS;
    
    for (u16 port_id = 0; port_id < g_dpdk.nb_ports; port_id++) {
        if (strcmp(g_dpdk.ports[port_id].name, name) == 0) {
            return port_id;
        }
    }
    
    return RTE_MAX_ETHPORTS;
}

static void *capture_loop(void *arg)
{
    (void)arg;
    
    struct rte_mbuf *pkts[32];
    
    log_info("DPDK capture thread started");
    
    while (g_capture_running) {
        for (u16 port_id = 0; port_id < g_dpdk.nb_ports; port_id++) {
            for (u16 q = 0; q < g_dpdk.ports[port_id].rx_queues; q++) {
                u16 nb_rx = dpdk_rx_burst(port_id, q, pkts, 32);
                
                for (u16 i = 0; i < nb_rx; i++) {
                    if (g_handler) {
                        g_handler(pkts[i], port_id, g_user_data);
                    }
                    dpdk_free_mbuf(pkts[i]);
                }
            }
        }
        
        usleep(1);
    }
    
    log_info("DPDK capture thread stopped");
    return NULL;
}

int dpdk_start_capture(dpdk_packet_handler_t handler, void *user_data)
{
    if (!g_dpdk.initialized) return NGFW_ERR_INVALID;
    if (g_capture_running) return NGFW_ERR_BUSY;
    
    g_handler = handler;
    g_user_data = user_data;
    g_capture_running = true;
    
    pthread_create(&g_capture_thread, NULL, capture_loop, NULL);
    
    return NGFW_OK;
}

void dpdk_stop_capture(void)
{
    g_capture_running = false;
    
    if (g_capture_thread) {
        pthread_join(g_capture_thread, NULL);
    }
}

#endif
