/*
 * NGFW Kernel Module
 * High-performance packet processing module for Linux kernel
 *
 * This module provides:
 * - Fast packet interception
 * - Hardware packet acceleration
 * - Netfilter integration
 * - Flow table management
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

#define NGFW_MODULE_NAME "ngfw"
#define NGFW_MODULE_VERSION "2.0.0"
#define NGFW_FLOW_TABLE_SIZE 65536
#define NGFW_MAX_PACKET_SIZE 9000
#define NGFW_HASH_BUCKET_SIZE 256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NGFW Team");
MODULE_DESCRIPTION("Next-Generation Firewall Kernel Module");
MODULE_VERSION(NGFW_MODULE_VERSION);

struct ngfw_flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
    __u8 direction;
};

struct ngfw_flow_entry {
    struct ngfw_flow_key key;
    unsigned long timestamp;
    u64 packet_count;
    u64 byte_count;
    u32 action;
    u32 mark;
    struct rcu_head rcu;
};

struct ngfw_stats {
    atomic64_t packets_total;
    atomic64_t packets_allowed;
    atomic64_t packets_dropped;
    atomic64_t bytes_total;
    atomic64_t connections_tracked;
    atomic64_t flow_entries;
};

static struct ngfw_stats ngfw_statistics = {0};
static struct kmem_cache *ngfw_flow_cache __read_mostly;
static struct hlist_head *ngfw_flow_table __read_mostly;
static bool ngfw_enabled = true;
static bool bypass_enabled = false;
static int flow_table_size = NGFW_FLOW_TABLE_SIZE;

module_param(enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable NGFW packet processing");
module_param(bypass, bool, 0644);
MODULE_PARM_DESC(bypass, "Enable packet bypass mode");

static inline u32 flow_hash(struct ngfw_flow_key *key)
{
    u32 hash = 0;
    hash ^= key->src_ip >> 16;
    hash ^= key->dst_ip;
    hash ^= key->src_port << 8;
    hash ^= key->dst_port;
    hash ^= key->proto << 2;
    return hash % flow_table_size;
}

static struct ngfw_flow_entry *flow_lookup(struct sk_buff *skb)
{
    struct iphdr *iph = ip_hdr(skb);
    struct ngfw_flow_key key = {0};

    if (!iph)
        return NULL;

    key.src_ip = iph->saddr;
    key.dst_ip = iph->daddr;
    key.proto = iph->protocol;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = tcp_hdr(skb);
        key.src_port = tcph->source;
        key.dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = udp_hdr(skb);
        key.src_port = udph->source;
        key.dst_port = udph->dest;
    }

    u32 hash = flow_hash(&key);
    struct ngfw_flow_entry *entry;

    rcu_read_lock();
    hlist_for_each_entry_rcu(entry, &ngfw_flow_table[hash], rcu) {
        if (entry->key.src_ip == key.src_ip &&
            entry->key.dst_ip == key.dst_ip &&
            entry->key.src_port == key.src_port &&
            entry->key.dst_port == key.dst_port &&
            entry->key.proto == key.proto) {
            rcu_read_unlock();
            return entry;
        }
    }
    rcu_read_unlock();

    return NULL;
}

static void flow_add(struct sk_buff *skb, u32 action)
{
    struct iphdr *iph = ip_hdr(skb);
    struct ngfw_flow_key key = {0};

    if (!iph)
        return;

    key.src_ip = iph->saddr;
    key.dst_ip = iph->daddr;
    key.proto = iph->protocol;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = tcp_hdr(skb);
        key.src_port = tcph->source;
        key.dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = udp_hdr(skb);
        key.src_port = udph->source;
        key.dst_port = udph->dest;
    }

    struct ngfw_flow_entry *entry = kmem_cache_alloc(ngfw_flow_cache, GFP_ATOMIC);
    if (!entry)
        return;

    memcpy(&entry->key, &key, sizeof(key));
    entry->timestamp = jiffies;
    entry->packet_count = 1;
    entry->byte_count = skb->len;
    entry->action = action;
    entry->mark = 0;

    u32 hash = flow_hash(&key);
    hlist_add_head_rcu(&entry->rcu, &ngfw_flow_table[hash]);

    atomic64_inc(&ngfw_statistics.flow_entries);
}

static unsigned int ngfw_nf_hook(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    if (!ngfw_enabled)
        return NF_ACCEPT;

    if (bypass_enabled)
        return NF_ACCEPT;

    if (!skb)
        return NF_DROP;

    struct iphdr *iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    atomic64_inc(&ngfw_statistics.packets_total);
    atomic64_add(skb->len, &ngfw_statistics.bytes_total);

    if (iph->version != 4 && iph->version != 6)
        return NF_ACCEPT;

    struct ngfw_flow_entry *flow = flow_lookup(skb);
    if (flow) {
        flow->packet_count++;
        flow->timestamp = jiffies;

        if (flow->action == NF_DROP) {
            atomic64_inc(&ngfw_statistics.packets_dropped);
            return NF_DROP;
        }

        if (flow->mark)
            skb->mark = flow->mark;

        atomic64_inc(&ngfw_statistics.packets_allowed);
        return NF_ACCEPT;
    }

    struct nf_conn *ct = nf_ct_get(skb, NULL);
    if (ct) {
        atomic64_inc(&ngfw_statistics.connections_tracked);

        if (nf_ct_is_confirmed(ct)) {
            if (ct->status & IPS_SEEN_REPLY) {
                flow_add(skb, NF_ACCEPT);
                atomic64_inc(&ngfw_statistics.packets_allowed);
                return NF_ACCEPT;
            }
        }
    }

    atomic64_inc(&ngfw_statistics.packets_allowed);
    flow_add(skb, NF_ACCEPT);

    return NF_ACCEPT;
}

static struct nf_hook_ops ngfw_nf_ops[] = {
    {
        .hook = ngfw_nf_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = ngfw_nf_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = ngfw_nf_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = ngfw_nf_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_FORWARD,
        .priority = NF_IP_PRI_FIRST,
    },
};

static int ngfw_netdev_open(struct net_device *dev)
{
    netif_start_queue(dev);
    pr_info("ngfw: device %s opened\n", dev->name);
    return 0;
}

static int ngfw_netdev_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    pr_info("ngfw: device %s stopped\n", dev->name);
    return 0;
}

static netdev_tx_t ngfw_netdev_xmit(struct sk_buff *skb,
                                      struct net_device *dev)
{
    struct iphdr *iph = ip_hdr(skb);

    if (!iph)
        goto drop;

    atomic64_inc(&ngfw_statistics.packets_total);
    atomic64_add(skb->len, &ngfw_statistics.bytes_total);

    flow_add(skb, NF_ACCEPT);

    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;

drop:
    dev->stats.tx_errors++;
    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

static int ngfw_netdev_change_mtu(struct net_device *dev, int new_mtu)
{
    if (new_mtu < 68 || new_mtu > NGFW_MAX_PACKET_SIZE)
        return -EINVAL;
    dev->mtu = new_mtu;
    return 0;
}

static int ngfw_netdev_set_mac(struct net_device *dev, void *addr)
{
    struct sockaddr *sa = addr;
    if (!is_valid_ether_addr(sa->sa_data))
        return -EADDRNOTAVAIL;
    memcpy(dev->dev_addr, sa->sa_data, ETH_ALEN);
    return 0;
}

static struct net_device_stats *ngfw_netdev_get_stats(struct net_device *dev)
{
    return &dev->stats;
}

static const struct net_device_ops ngfw_netdev_ops = {
    .ndo_open = ngfw_netdev_open,
    .ndo_stop = ngfw_netdev_stop,
    .ndo_start_xmit = ngfw_netdev_xmit,
    .ndo_change_mtu = ngfw_netdev_change_mtu,
    .ndo_set_mac_address = ngfw_netdev_set_mac,
    .ndo_get_stats = ngfw_netdev_get_stats,
};

static void ngfw_setup(struct net_device *dev)
{
    dev->netdev_ops = &ngfw_netdev_ops;
    dev->type = ARPHRD_NONE;
    dev->hard_header_len = 0;
    dev->addr_len = 0;
    dev->mtu = ETH_DATA_LEN;
    dev->tx_queue_len = 1000;
    dev->flags = IFF_NOARP | IFF_POINTOPOINT | IFF_MULTICAST;
    dev->features = NETIF_F_HW_CSUM | NETIF_F_TSO | NETIF_F_TSO6;
}

static struct net_device *ngfw_dev;

static int __init ngfw_init(void)
{
    int ret;
    int i;

    pr_info("NGFW: Initializing kernel module v%s\n", NGFW_MODULE_VERSION);

    ngfw_flow_cache = kmem_cache_create("ngfw_flow_cache",
                                          sizeof(struct ngfw_flow_entry),
                                          0,
                                          SLAB_HWCACHE_ALIGN | SLAB_PANIC,
                                          NULL);
    if (!ngfw_flow_cache) {
        pr_err("ngfw: failed to create flow cache\n");
        return -ENOMEM;
    }

    ngfw_flow_table = kmalloc(sizeof(struct hlist_head) * flow_table_size,
                               GFP_KERNEL);
    if (!ngfw_flow_table) {
        pr_err("ngfw: failed to allocate flow table\n");
        ret = -ENOMEM;
        goto err_flow_table;
    }

    for (i = 0; i < flow_table_size; i++)
        INIT_HLIST_HEAD(&ngfw_flow_table[i]);

    ret = nf_register_net_hooks(&init_net, ngfw_nf_ops, ARRAY_SIZE(ngfw_nf_ops));
    if (ret < 0) {
        pr_err("ngfw: failed to register netfilter hooks\n");
        goto err_nf_hooks;
    }

    ngfw_dev = alloc_netdev(0, "ngfw%d", NET_NAME_UNKNOWN, ngfw_setup);
    if (!ngfw_dev) {
        pr_err("ngfw: failed to allocate netdev\n");
        ret = -ENOMEM;
        goto err_netdev;
    }

    ret = register_netdev(ngfw_dev);
    if (ret) {
        pr_err("ngfw: failed to register netdev\n");
        goto err_register;
    }

    pr_info("NGFW: Module initialized successfully\n");
    pr_info("NGFW: Flow table size: %d entries\n", flow_table_size);

    return 0;

err_register:
    free_netdev(ngfw_dev);
err_netdev:
    nf_unregister_net_hooks(&init_net, ngfw_nf_ops, ARRAY_SIZE(ngfw_nf_ops));
err_nf_hooks:
    kfree(ngfw_flow_table);
err_flow_table:
    kmem_cache_destroy(ngfw_flow_cache);
    return ret;
}

static void __exit ngfw_exit(void)
{
    int i;

    pr_info("NGFW: Shutting down kernel module\n");

    unregister_netdev(ngfw_dev);
    free_netdev(ngfw_dev);

    nf_unregister_net_hooks(&init_net, ngfw_nf_ops, ARRAY_SIZE(ngfw_nf_ops));

    for (i = 0; i < flow_table_size; i++) {
        struct ngfw_flow_entry *entry;
        struct hlist_node *tmp;
        hlist_for_each_entry_safe(entry, tmp, &ngfw_flow_table[i], rcu) {
            hlist_del_rcu(&entry->rcu);
            kmem_cache_free(ngfw_flow_cache, entry);
        }
    }

    synchronize_rcu();
    kfree(ngfw_flow_table);
    kmem_cache_destroy(ngfw_flow_cache);

    pr_info("NGFW: Module unloaded\n");
    pr_info("NGFW: Total packets: %lld\n",
            (long long)atomic64_read(&ngfw_statistics.packets_total));
    pr_info("NGFW: Allowed: %lld, Dropped: %lld\n",
            (long long)atomic64_read(&ngfw_statistics.packets_allowed),
            (long long)atomic64_read(&ngfw_statistics.packets_dropped));
}

module_init(ngfw_init);
module_exit(ngfw_exit);