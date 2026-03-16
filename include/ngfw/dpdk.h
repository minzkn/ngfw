#ifndef NGFW_DPDK_H
#define NGFW_DPDK_H

#include "types.h"
#include "packet.h"

#ifdef ENABLE_DPDK

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#define DPDK_MAX_PORTS 16
#define DPDK_MAX_QUEUES 16
#define DPDK_MBUF_CACHE_SIZE 256
#define DPDK_RX_DESC_MAX 512
#define DPDK_TX_DESC_MAX 512
#define DPDK_MBUF_POOL_SIZE 8192

typedef struct dpdk_port {
    u16 port_id;
    char name[RTE_ETH_NAMESIZE];
    bool enabled;
    u16 rx_queues;
    u16 tx_queues;
    struct rte_mempool *mempool;
} dpdk_port_t;

typedef struct dpdk_config {
    int argc;
    char **argv;
    u16 nb_ports;
    u16 nb_queues;
    u32 mbuf_pool_size;
    u16 rx_desc;
    u16 tx_desc;
    bool promiscuous;
    bool rx_offload;
    bool tx_offload;
} dpdk_config_t;

typedef struct dpdk_capture {
    dpdk_port_t ports[DPDK_MAX_PORTS];
    struct rte_mempool *mempool;
    u16 nb_ports;
    bool initialized;
    bool running;
} dpdk_capture_t;

int dpdk_init(dpdk_config_t *config);
void dpdk_shutdown(void);

int dpdk_port_start(u16 port_id);
int dpdk_port_stop(u16 port_id);
int dpdk_port_config(u16 port_id, u16 nb_queues, u16 rx_desc, u16 tx_desc);

int dpdk_rx_burst(u16 port_id, u16 queue_id, struct rte_mbuf **rx_pkts, u16 nb_pkts);
int dpdk_tx_burst(u16 port_id, u16 queue_id, struct rte_mbuf **tx_pkts, u16 nb_pkts);

struct rte_mbuf *dpdk_alloc_mbuf(void);
void dpdk_free_mbuf(struct rte_mbuf *mbuf);

int dpdk_get_port_stats(u16 port_id, struct rte_eth_stats *stats);
void dpdk_clear_port_stats(u16 port_id);

u16 dpdk_get_nb_ports(void);
u16 dpdk_get_port_by_name(const char *name);

typedef int (*dpdk_packet_handler_t)(struct rte_mbuf *mbuf, u16 port_id, void *user_data);

int dpdk_start_capture(dpdk_packet_handler_t handler, void *user_data);
void dpdk_stop_capture(void);

#else

typedef struct dpdk_capture {
    bool initialized;
} dpdk_capture_t;

static inline int dpdk_init(void *config)
{
    (void)config;
    return NGFW_ERR_NOT_SUPPORTED;
}

static inline void dpdk_shutdown(void) {}

static inline int dpdk_port_start(u16 port_id)
{
    (void)port_id;
    return NGFW_ERR_NOT_SUPPORTED;
}

#endif

#endif
