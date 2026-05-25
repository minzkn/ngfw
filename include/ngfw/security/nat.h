/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_SECURITY_NAT_H
#define NGFW_SECURITY_NAT_H

#include "ngfw/types.h"
#include "ngfw/network/packet.h"
#include "ngfw/hash.h"

/*
 * Network Address Translation
 * SNAT, DNAT, and MASQUERADE support
 */

#define MAX_NAT_RULES 1024
#define MAX_NAT_ENTRIES 65536

typedef enum {
    NAT_TYPE_SNAT,
    NAT_TYPE_DNAT,
    NAT_TYPE_MASQUERADE,
    NAT_TYPE_BOTH
} nat_type_t;

typedef struct nat_rule {
    u32 id;
    nat_type_t type;
    char name[64];
    u32 src_ip;
    u32 src_mask;
    u32 dst_ip;
    u32 dst_mask;
    u16 src_port_min;
    u16 src_port_max;
    u16 dst_port_min;
    u16 dst_port_max;
    u32 nat_ip;
    u32 new_src_ip;
    u32 new_dst_ip;
    u16 new_src_port;
    u16 new_dst_port;
    u16 nat_port_min;
    u16 nat_port_max;
    bool enabled;
    u64 hits;
    u64 last_hit;
} nat_rule_t;

typedef struct nat_entry {
    u32 id;
    u32 original_src_ip;
    u32 original_dst_ip;
    u16 original_src_port;
    u16 original_dst_port;
    u32 translated_src_ip;
    u32 translated_dst_ip;
    u16 translated_src_port;
    u16 translated_dst_port;
    u8 protocol;
    u64 created;
    u64 last_activity;
    u64 expires;
    u32 ref_count;
    nat_type_t type;
    u32 rule_id;
} nat_entry_t;

typedef struct nat_stats {
    u64 translations_active;
    u64 translations_created;
    u64 translations_expired;
    u64 packets_translated;
    u64 rules_hits;
    u64 snat_translations;
    u64 dnat_translations;
    u64 bytes_translated;
} nat_stats_t;

/* Forward declaration - full definition in nat.c */
typedef struct nat nat_t;

nat_t *nat_create(void);
void nat_destroy(nat_t *nat);
ngfw_ret_t nat_init(nat_t *nat);
ngfw_ret_t nat_start(nat_t *nat);
ngfw_ret_t nat_stop(nat_t *nat);

ngfw_ret_t nat_add_rule(nat_t *nat, nat_rule_t *rule);
ngfw_ret_t nat_del_rule(nat_t *nat, u32 rule_id);
ngfw_ret_t nat_enable_rule(nat_t *nat, u32 rule_id);
ngfw_ret_t nat_disable_rule(nat_t *nat, u32 rule_id);

ngfw_ret_t nat_translate_packet(nat_t *nat, packet_t *pkt, nat_entry_t *entry);
ngfw_ret_t nat_cleanup_entry(nat_t *nat, nat_entry_t *entry);

nat_stats_t *nat_get_stats(nat_t *nat);
void nat_reset_stats(nat_t *nat);

#endif
