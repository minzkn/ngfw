/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_NETWORK_IFACE_H
#define NGFW_NETWORK_IFACE_H

#include "ngfw/types.h"

/*
 * Network Interface Management
 */

#define NGFW_IF_NAME_SIZE 64

/* Interface information */
typedef struct netif_info {
    char name[NGFW_IF_NAME_SIZE];
    u32 ifindex;
    u8 mac_addr[6];
    u32 ip_addr;
    u32 netmask;
    u32 mtu;
    bool up;
    bool running;
    bool promiscuous;
} netif_info_t;

/* Interface enumeration */
ngfw_ret_t netif_enumerate(netif_info_t *ifaces, u32 *count, u32 max_ifaces);

/* Interface queries */
ngfw_ret_t netif_get_info_by_name(const char *name, netif_info_t *info);
ngfw_ret_t netif_get_info_by_index(u32 ifindex, netif_info_t *info);

/* Interface configuration */
ngfw_ret_t netif_set_up(const char *name, bool up);
ngfw_ret_t netif_set_promiscuous(const char *name, bool enable);
ngfw_ret_t netif_set_mtu(const char *name, u32 mtu);

#endif
