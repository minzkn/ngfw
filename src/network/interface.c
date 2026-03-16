#include "ngfw/packet.h"
#include "ngfw/types.h"
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef IFF_UP
#define IFF_UP 0x1
#endif

#ifndef IFF_LOOPBACK
#define IFF_LOOPBACK 0x8
#endif

typedef struct network_interface {
    u32 ifindex;
    char name[16];
    u8 mac[ETH_ALEN];
    u32 ip;
    u32 netmask;
    u32 mtu;
    bool up;
    bool loopback;
} network_interface_t;

static network_interface_t interfaces[NGFW_MAX_INTERFACES];
static u32 interface_count = 0;

int interface_get_count(void)
{
    return interface_count;
}

const char *interface_get_name(u32 idx)
{
    if (idx == 0 || idx > interface_count) return NULL;
    return interfaces[idx - 1].name;
}

u32 interface_get_ifindex(const char *name)
{
    return if_nametoindex(name);
}

const char *interface_get_ifname(u32 ifindex)
{
    if (ifindex == 0 || ifindex > interface_count) return NULL;
    return interfaces[ifindex - 1].name;
}

int interface_refresh(void)
{
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }
    
    interface_count = 0;
    
    for (ifa = ifaddr; ifa != NULL && interface_count < NGFW_MAX_INTERFACES; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        bool found = false;
        for (u32 i = 0; i < interface_count; i++) {
            if (strcmp(interfaces[i].name, ifa->ifa_name) == 0) {
                found = true;
                break;
            }
        }
        
        if (!found) {
            strncpy(interfaces[interface_count].name, ifa->ifa_name, 15);
            interfaces[interface_count].name[15] = '\0';
            interfaces[interface_count].ifindex = if_nametoindex(ifa->ifa_name);
            interfaces[interface_count].up = (ifa->ifa_flags & IFF_UP) != 0;
            interfaces[interface_count].loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
            memset(interfaces[interface_count].mac, 0, ETH_ALEN);
            interfaces[interface_count].ip = 0;
            interfaces[interface_count].netmask = 0;
            interfaces[interface_count].mtu = 1500;
            interface_count++;
        }
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            for (u32 i = 0; i < interface_count; i++) {
                if (strcmp(interfaces[i].name, ifa->ifa_name) == 0) {
                    interfaces[i].ip = addr->sin_addr.s_addr;
                    break;
                }
            }
            
            if (ifa->ifa_netmask) {
                struct sockaddr_in *nm = (struct sockaddr_in *)ifa->ifa_netmask;
                for (u32 i = 0; i < interface_count; i++) {
                    if (strcmp(interfaces[i].name, ifa->ifa_name) == 0) {
                        interfaces[i].netmask = nm->sin_addr.s_addr;
                        break;
                    }
                }
            }
        }
    }
    
    freeifaddrs(ifaddr);
    return interface_count;
}

u32 interface_get_ip(u32 ifindex)
{
    if (ifindex == 0 || ifindex > interface_count) return 0;
    return interfaces[ifindex - 1].ip;
}

u32 interface_get_netmask(u32 ifindex)
{
    if (ifindex == 0 || ifindex > interface_count) return 0;
    return interfaces[ifindex - 1].netmask;
}

u32 interface_get_mtu(u32 ifindex)
{
    if (ifindex == 0 || ifindex > interface_count) return 0;
    return interfaces[ifindex - 1].mtu;
}

bool interface_is_up(u32 ifindex)
{
    if (ifindex == 0 || ifindex > interface_count) return false;
    return interfaces[ifindex - 1].up;
}

const u8 *interface_get_mac(u32 ifindex)
{
    if (ifindex == 0 || ifindex > interface_count) return NULL;
    return interfaces[ifindex - 1].mac;
}
