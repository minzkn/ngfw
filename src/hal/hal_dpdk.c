/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#include "ngfw/hal/dpdk.h"

#ifdef ENABLE_DPDK

#include <rte_eal.h>
#include <rte_ethdev.h>

static bool dpdk_initialized = false;

ngfw_ret_t hal_dpdk_init(int argc, char **argv)
{
    int ret;
    
    if (dpdk_initialized) {
        return NGFW_OK;
    }
    
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        return NGFW_ERR;
    }
    
    dpdk_initialized = true;
    return NGFW_OK;
}

void hal_dpdk_shutdown(void)
{
    if (dpdk_initialized) {
        rte_eal_cleanup();
        dpdk_initialized = false;
    }
}

bool hal_dpdk_is_available(void)
{
    return dpdk_initialized;
}

ngfw_ret_t hal_dpdk_port_probe(const char *pci_addr)
{
    (void)pci_addr;
    return NGFW_OK;
}

ngfw_ret_t hal_dpdk_port_configure(u32 port_id, u32 rx_queues, u32 tx_queues)
{
    (void)port_id; (void)rx_queues; (void)tx_queues;
    return NGFW_OK;
}

ngfw_ret_t hal_dpdk_port_start(u32 port_id)
{
    int ret = rte_eth_dev_start(port_id);
    return (ret == 0) ? NGFW_OK : NGFW_ERR;
}

void hal_dpdk_port_stop(u32 port_id)
{
    rte_eth_dev_stop(port_id);
}

#else /* ENABLE_DPDK */

/* Stubs defined in header */

#endif /* ENABLE_DPDK */
