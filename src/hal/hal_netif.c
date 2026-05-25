/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#include "ngfw/hal/netif.h"
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

ngfw_ret_t hal_netif_init(void)
{
    return NGFW_OK;
}

void hal_netif_shutdown(void)
{
}

ngfw_ret_t hal_netif_enumerate(hal_netif_config_t *configs, u32 *count)
{
    if (!configs || !count) {
        return NGFW_ERR_INVALID;
    }
    
    struct ifaddrs *ifaddr, *ifa;
    u32 idx = 0;
    
    if (getifaddrs(&ifaddr) == -1) {
        return NGFW_ERR;
    }
    
    for (ifa = ifaddr; ifa != NULL && idx < NGFW_MAX_INTERFACES; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        
        strncpy(configs[idx].name, ifa->ifa_name, NGFW_IF_NAME_SIZE - 1);
        configs[idx].name[NGFW_IF_NAME_SIZE - 1] = '\0';
        configs[idx].type = HAL_NETIF_TYPE_KERNEL;
        configs[idx].queue_count = 1;
        configs[idx].mtu = 1500;
        
        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        configs[idx].ip_addr = sin->sin_addr.s_addr;
        
        idx++;
    }
    
    freeifaddrs(ifaddr);
    *count = idx;
    
    return NGFW_OK;
}

ngfw_ret_t hal_netif_open(const hal_netif_config_t *config, hal_netif_t **netif)
{
    if (!config || !netif) {
        return NGFW_ERR_INVALID;
    }
    
    *netif = NULL;
    return NGFW_ERR_NOT_SUPPORTED;
}

void hal_netif_close(hal_netif_t *netif)
{
    (void)netif;
}

ngfw_ret_t hal_netif_set_promiscuous(hal_netif_t *netif, bool enable)
{
    (void)netif; (void)enable;
    return NGFW_ERR_NOT_SUPPORTED;
}

ngfw_ret_t hal_netif_set_mtu(hal_netif_t *netif, u32 mtu)
{
    (void)netif; (void)mtu;
    return NGFW_ERR_NOT_SUPPORTED;
}

ngfw_ret_t hal_netif_get_stats(hal_netif_t *netif, hal_netif_stats_t *stats)
{
    (void)netif; (void)stats;
    return NGFW_ERR_NOT_SUPPORTED;
}

ngfw_ret_t hal_netif_receive(hal_netif_t *netif, void **pkts, u32 *count, u32 max_pkts)
{
    (void)netif; (void)pkts; (void)count; (void)max_pkts;
    return NGFW_ERR_NOT_SUPPORTED;
}

ngfw_ret_t hal_netif_transmit(hal_netif_t *netif, void **pkts, u32 count)
{
    (void)netif; (void)pkts; (void)count;
    return NGFW_ERR_NOT_SUPPORTED;
}
