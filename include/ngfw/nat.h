#ifndef NGFW_NAT_H
#define NGFW_NAT_H

#include "types.h"
#include "packet.h"

typedef enum {
    NAT_TYPE_NONE,
    NAT_TYPE_SNAT,
    NAT_TYPE_DNAT,
    NAT_TYPE_BOTH
} nat_type_t;

typedef enum {
    NAT_RULE_FORWARD,
    NAT_RULE_INBOUND,
    NAT_RULE_OUTBOUND
} nat_direction_t;

typedef struct nat_rule {
    u32 id;
    char name[128];
    nat_type_t type;
    nat_direction_t direction;
    bool enabled;
    u32 src_ip;
    u32 src_mask;
    u32 dst_ip;
    u32 dst_mask;
    u16 src_port_min;
    u16 src_port_max;
    u16 dst_port_min;
    u16 dst_port_max;
    u32 new_src_ip;
    u32 new_dst_ip;
    u16 new_src_port;
    u16 new_dst_port;
    u32 hits;
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
    bool tcp_established;
} nat_entry_t;

typedef struct nat_stats {
    u64 snat_translations;
    u64 dnat_translations;
    u64 translations_active;
    u64 translations_expired;
    u64 packets_translated;
    u64 bytes_translated;
    u64 rule_hits[256];
} nat_stats_t;

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

ngfw_ret_t nat_lookup(nat_t *nat, u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 proto, nat_entry_t *entry);

ngfw_ret_t nat_add_mapping(nat_t *nat, nat_entry_t *entry);
ngfw_ret_t nat_delete_mapping(nat_t *nat, u32 entry_id);

nat_stats_t *nat_get_stats(nat_t *nat);
void nat_reset_stats(nat_t *nat);

ngfw_ret_t nat_get_mappings(nat_t *nat, nat_entry_t **entries, u32 *count);

#endif
