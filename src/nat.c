#include "ngfw/nat.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include "ngfw/packet.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAX_NAT_RULES 1024
#define MAX_NAT_ENTRIES 65536

struct nat {
    hash_table_t *rules;
    hash_table_t *mappings;
    nat_rule_t *rule_list[ MAX_NAT_RULES];
    u32 rule_count;
    nat_stats_t stats;
    bool initialized;
    bool running;
};

static u32 nat_mapping_hash(const void *key, u32 size)
{
    const u64 *k = (const u64 *)key;
    return (u32)(*k % size);
}

static bool nat_mapping_match(const void *key1, const void *key2)
{
    return (*(const u64 *)key1) == (*(const u64 *)key2);
}

static u64 create_nat_key(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 proto)
{
    (void)dst_port;
    return ((u64)src_ip << 32) | ((u64)dst_ip << 16) | ((u64)src_port << 8) | proto;
}

nat_t *nat_create(void)
{
    nat_t *nat = ngfw_malloc(sizeof(nat_t));
    if (!nat) return NULL;

    memset(nat, 0, sizeof(nat_t));

    nat->rules = hash_create(256, NULL, NULL, NULL);
    nat->mappings = hash_create(8192, nat_mapping_hash, nat_mapping_match, NULL);

    if (!nat->rules || !nat->mappings) {
        if (nat->rules) hash_destroy(nat->rules);
        if (nat->mappings) hash_destroy(nat->mappings);
        ngfw_free(nat);
        return NULL;
    }

    nat->rule_count = 0;

    log_info("NAT created");

    return nat;
}

void nat_destroy(nat_t *nat)
{
    if (!nat) return;

    if (nat->running) {
        nat_stop(nat);
    }

    for (u32 i = 0; i < nat->rule_count; i++) {
        if (nat->rule_list[i]) {
            ngfw_free(nat->rule_list[i]);
        }
    }

    hash_destroy(nat->rules);
    hash_destroy(nat->mappings);
    ngfw_free(nat);

    log_info("NAT destroyed");
}

ngfw_ret_t nat_init(nat_t *nat)
{
    if (!nat) return NGFW_ERR_INVALID;

    nat->initialized = true;
    log_info("NAT initialized");

    return NGFW_OK;
}

ngfw_ret_t nat_start(nat_t *nat)
{
    if (!nat || !nat->initialized) return NGFW_ERR_INVALID;

    nat->running = true;
    log_info("NAT started");

    return NGFW_OK;
}

ngfw_ret_t nat_stop(nat_t *nat)
{
    if (!nat) return NGFW_ERR_INVALID;

    nat->running = false;
    log_info("NAT stopped");

    return NGFW_OK;
}

ngfw_ret_t nat_add_rule(nat_t *nat, nat_rule_t *rule)
{
    if (!nat || !rule) return NGFW_ERR_INVALID;

    if (nat->rule_count >= MAX_NAT_RULES) {
        return NGFW_ERR_NO_RESOURCE;
    }

    nat_rule_t *r = ngfw_malloc(sizeof(nat_rule_t));
    if (!r) return NGFW_ERR_NO_MEM;

    *r = *rule;
    r->id = nat->rule_count + 1;
    r->hits = 0;
    r->last_hit = 0;

    hash_insert(nat->rules, (void *)(uintptr_t)r->id, r);
    nat->rule_list[nat->rule_count++] = r;

    log_info("NAT rule added: %s (ID: %u, Type: %d)", r->name, r->id, r->type);

    return NGFW_OK;
}

ngfw_ret_t nat_del_rule(nat_t *nat, u32 rule_id)
{
    if (!nat) return NGFW_ERR_INVALID;

    hash_remove(nat->rules, (void *)(uintptr_t)rule_id);

    for (u32 i = 0; i < nat->rule_count; i++) {
        if (nat->rule_list[i] && nat->rule_list[i]->id == rule_id) {
            ngfw_free(nat->rule_list[i]);
            nat->rule_list[i] = NULL;
            break;
        }
    }

    log_info("NAT rule deleted: %u", rule_id);

    return NGFW_OK;
}

ngfw_ret_t nat_enable_rule(nat_t *nat, u32 rule_id)
{
    if (!nat) return NGFW_ERR_INVALID;

    nat_rule_t *r = hash_lookup(nat->rules, (void *)(uintptr_t)rule_id);
    if (!r) return NGFW_ERR_INVALID;

    r->enabled = true;

    return NGFW_OK;
}

ngfw_ret_t nat_disable_rule(nat_t *nat, u32 rule_id)
{
    if (!nat) return NGFW_ERR_INVALID;

    nat_rule_t *r = hash_lookup(nat->rules, (void *)(uintptr_t)rule_id);
    if (!r) return NGFW_ERR_INVALID;

    r->enabled = false;

    return NGFW_OK;
}

static bool match_nat_rule(nat_rule_t *rule, u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 proto)
{
    (void)proto;
    
    if (!rule || !rule->enabled) return false;

    if (rule->src_ip && (src_ip & rule->src_mask) != (rule->src_ip & rule->src_mask)) {
        return false;
    }

    if (rule->dst_ip && (dst_ip & rule->dst_mask) != (rule->dst_ip & rule->dst_mask)) {
        return false;
    }

    if (rule->src_port_min && (src_port < rule->src_port_min || src_port > rule->src_port_max)) {
        return false;
    }

    if (rule->dst_port_min && (dst_port < rule->dst_port_min || dst_port > rule->dst_port_max)) {
        return false;
    }

    return true;
}

ngfw_ret_t nat_translate_packet(nat_t *nat, packet_t *pkt, nat_entry_t *entry)
{
    if (!nat || !pkt || !entry) return NGFW_ERR_INVALID;

    ip_header_t *ip = packet_get_ip(pkt);
    if (!ip) return NGFW_ERR_INVALID;

    u32 src_ip = ip->src;
    u32 dst_ip = ip->dst;
    u16 src_port = 0;
    u16 dst_port = 0;
    u8 proto = ip->protocol;

    tcp_header_t *tcp = packet_get_tcp(pkt);
    if (tcp) {
        src_port = tcp->src_port;
        dst_port = tcp->dst_port;
    }

    udp_header_t *udp = packet_get_udp(pkt);
    if (udp) {
        src_port = udp->src_port;
        dst_port = udp->dst_port;
    }

    nat_rule_t *matched_rule = NULL;

    for (u32 i = 0; i < nat->rule_count; i++) {
        nat_rule_t *rule = nat->rule_list[i];
        if (!rule) continue;

        if (match_nat_rule(rule, src_ip, dst_ip, src_port, dst_port, proto)) {
            matched_rule = rule;
            rule->hits++;
            rule->last_hit = get_ms_time();
            break;
        }
    }

    if (!matched_rule) {
        return NGFW_ERR;
    }

    memset(entry, 0, sizeof(nat_entry_t));
    entry->id = (u32)(uintptr_t)(nat->mappings->count + 1);
    entry->original_src_ip = src_ip;
    entry->original_dst_ip = dst_ip;
    entry->original_src_port = src_port;
    entry->original_dst_port = dst_port;
    entry->protocol = proto;
    entry->created = get_ms_time();
    entry->last_activity = entry->created;
    entry->expires = entry->created + 3600000;

    bool translated = false;

    if (matched_rule->type == NAT_TYPE_SNAT || matched_rule->type == NAT_TYPE_BOTH) {
        if (matched_rule->new_src_ip) {
            entry->translated_src_ip = matched_rule->new_src_ip;
            entry->translated_dst_ip = dst_ip;
            ip->src = matched_rule->new_src_ip;
            translated = true;
            nat->stats.snat_translations++;
        }

        if (matched_rule->new_src_port) {
            entry->translated_src_port = matched_rule->new_src_port;
            if (tcp) tcp->src_port = matched_rule->new_src_port;
            if (udp) udp->src_port = matched_rule->new_src_port;
        }
    }

    if (matched_rule->type == NAT_TYPE_DNAT || matched_rule->type == NAT_TYPE_BOTH) {
        if (matched_rule->new_dst_ip) {
            entry->translated_dst_ip = matched_rule->new_dst_ip;
            entry->translated_src_ip = src_ip;
            ip->dst = matched_rule->new_dst_ip;
            translated = true;
            nat->stats.dnat_translations++;
        }

        if (matched_rule->new_dst_port) {
            entry->translated_dst_port = matched_rule->new_dst_port;
            if (tcp) tcp->dst_port = matched_rule->new_dst_port;
            if (udp) udp->dst_port = matched_rule->new_dst_port;
        }
    }

    if (translated) {
        ip->checksum = 0;
        ip->checksum = ip_checksum(ip, IP_HEADER_LEN(ip));

        if (tcp) {
            tcp->checksum = 0;
            tcp->checksum = tcp_calculate_checksum(ip, tcp);
        }

        if (udp) {
            udp->checksum = 0;
            udp->checksum = udp_calculate_checksum(ip, udp);
        }

        nat->stats.packets_translated++;
        nat->stats.bytes_translated += pkt->len;

        u64 key = create_nat_key(src_ip, dst_ip, src_port, dst_port, proto);
        hash_insert(nat->mappings, &key, entry);
    }

    return NGFW_OK;
}

ngfw_ret_t nat_lookup(nat_t *nat, u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 proto, nat_entry_t *entry)
{
    if (!nat || !entry) return NGFW_ERR_INVALID;

    u64 key = create_nat_key(src_ip, dst_ip, src_port, dst_port, proto);
    nat_entry_t *e = hash_lookup(nat->mappings, &key);

    if (!e) return NGFW_ERR_INVALID;

    *entry = *e;
    e->last_activity = get_ms_time();

    return NGFW_OK;
}

ngfw_ret_t nat_add_mapping(nat_t *nat, nat_entry_t *entry)
{
    if (!nat || !entry) return NGFW_ERR_INVALID;

    u64 key = create_nat_key(entry->original_src_ip, entry->original_dst_ip,
                            entry->original_src_port, entry->original_dst_port, entry->protocol);

    hash_insert(nat->mappings, &key, entry);
    nat->stats.translations_active = nat->mappings->count;

    return NGFW_OK;
}

ngfw_ret_t nat_delete_mapping(nat_t *nat, u32 entry_id)
{
    if (!nat) return NGFW_ERR_INVALID;
    
    void **iter = hash_iterate_start(nat->mappings);
    while (hash_iterate_has_next(iter)) {
        nat_entry_t *entry = (nat_entry_t *)hash_iterate_next(nat->mappings, iter);
        if (entry && entry->id == entry_id) {
            hash_remove(nat->mappings, entry);
            ngfw_free(entry);
            return NGFW_OK;
        }
    }
    
    return NGFW_ERR;
}

nat_stats_t *nat_get_stats(nat_t *nat)
{
    if (!nat) return NULL;

    nat->stats.translations_active = nat->mappings->count;

    return &nat->stats;
}

void nat_reset_stats(nat_t *nat)
{
    if (!nat) return;

    memset(&nat->stats, 0, sizeof(nat_stats_t));
}

ngfw_ret_t nat_get_mappings(nat_t *nat, nat_entry_t **entries, u32 *count)
{
    if (!nat || !count) return NGFW_ERR_INVALID;
    
    u32 total = hash_size(nat->mappings);
    if (entries) {
        *entries = ngfw_malloc(total * sizeof(nat_entry_t));
        if (!*entries) return NGFW_ERR_NO_MEM;
        
        u32 i = 0;
        void **iter = hash_iterate_start(nat->mappings);
        while (hash_iterate_has_next(iter)) {
            nat_entry_t *entry = (nat_entry_t *)hash_iterate_next(nat->mappings, iter);
            if (entry) {
                memcpy(&(*entries)[i++], entry, sizeof(nat_entry_t));
            }
        }
    }
    
    *count = total;
    return NGFW_OK;
}
