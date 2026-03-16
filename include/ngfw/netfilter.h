#ifndef NGFW_NETFILTER_H
#define NGFW_NETFILTER_H

#include "types.h"
#include "filter.h"
#include "packet.h"
#include "nf.h"

#define NGFW_CHAIN_MAX 16
#define NGFW_RULE_MAX 1024

typedef enum {
    NF_TABLE_FILTER,
    NF_TABLE_NAT,
    NF_TABLE_MANGLE,
    NF_TABLE_RAW,
    NF_TABLE_MAX
} nf_table_t;

typedef enum {
    NF_TARGET_ACCEPT,
    NF_TARGET_DROP,
    NF_TARGET_REJECT,
    NF_TARGET_LOG,
    NF_TARGET_DNAT,
    NF_TARGET_SNAT,
    NF_TARGET_MASQUERADE,
    NF_TARGET_MAX
} nf_target_t;

typedef enum {
    NF_PROTO_ALL,
    NF_PROTO_TCP,
    NF_PROTO_UDP,
    NF_PROTO_ICMP,
    NF_PROTO_ESP,
    NF_PROTO_AH,
    NF_PROTO_MAX
} nf_protocol_t;

typedef enum {
    NF_IP_ANY,
    NF_IP_V4,
    NF_IP_V6
} nf_ip_version_t;

typedef struct netfilter_rule {
    u32 id;
    char name[64];
    nf_table_t table;
    nf_chain_t chain;
    nf_protocol_t protocol;
    char src_ip[48];
    char dst_ip[48];
    u16 src_port_min;
    u16 src_port_max;
    u16 dst_port_min;
    u16 dst_port_max;
    u8 tos;
    u8 ttl;
    bool established;
    bool related;
    bool new;
    bool invalid;
    nf_target_t target;
    char target_param[128];
    bool enabled;
    u32 priority;
    u64 packet_count;
    u64 byte_count;
} netfilter_rule_t;

typedef struct nf_stats {
    u64 packets_total;
    u64 packets_accepted;
    u64 packets_dropped;
    u64 packets_rejected;
    u64 bytes_total;
    u64 errors;
    u32 active_rules;
} nf_stats_t;

typedef struct netfilter netfilter_t;

netfilter_t *netfilter_create(void);
void netfilter_destroy(netfilter_t *nf);

ngfw_ret_t netfilter_init(netfilter_t *nf);
ngfw_ret_t netfilter_shutdown(netfilter_t *nf);

ngfw_ret_t netfilter_add_rule(netfilter_t *nf, netfilter_rule_t *rule);
ngfw_ret_t netfilter_del_rule(netfilter_t *nf, u32 rule_id);
ngfw_ret_t netfilter_clear_rules(netfilter_t *nf);

ngfw_ret_t netfilter_set_policy(netfilter_t *nf, nf_table_t table, nf_chain_t chain, nf_target_t target);

ngfw_ret_t netfilter_enable_ip_forwarding(netfilter_t *nf, bool enable);

ngfw_ret_t netfilter_flush_table(netfilter_t *nf, nf_table_t table);
ngfw_ret_t netfilter_flush_chain(netfilter_t *nf, nf_chain_t chain);

nf_stats_t *netfilter_get_stats(netfilter_t *nf);
void netfilter_reset_stats(netfilter_t *nf);

ngfw_ret_t netfilter_sync_to_kernel(netfilter_t *nf);
ngfw_ret_t netfilter_load_from_kernel(netfilter_t *nf);

int netfilter_check_packet(netfilter_t *nf, packet_t *pkt);

typedef ngfw_ret_t (*netfilter_callback_t)(packet_t *pkt, void *context);

ngfw_ret_t netfilter_register_callback(netfilter_t *nf, netfilter_callback_t callback, void *context);

#endif
