/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "ngfw/filter.h"
#include "ngfw/memory.h"
#include "ngfw/list.h"
#include "ngfw/log.h"
#include "ngfw/packet.h"
#include <string.h>

typedef struct filter_rule_internal {
    filter_rule_t rule;
} filter_rule_internal_t;

struct filter {
    list_t *rules;
    filter_stats_t stats;
    u32 next_rule_id;
};

filter_t *filter_create(void)
{
    filter_t *filter = ngfw_malloc(sizeof(filter_t));
    if (!filter) return NULL;
    
    filter->rules = list_create(NULL);
    if (!filter->rules) {
        ngfw_free(filter);
        return NULL;
    }
    
    filter->next_rule_id = 1;
    memset(&filter->stats, 0, sizeof(filter_stats_t));
    
    return filter;
}

void filter_destroy(filter_t *filter)
{
    if (!filter) return;
    
    if (filter->rules) {
        list_destroy(filter->rules);
    }
    
    ngfw_free(filter);
}

ngfw_ret_t filter_add_rule(filter_t *filter, filter_rule_t *rule)
{
    if (!filter || !rule) return NGFW_ERR_INVALID;
    
    rule->id = filter->next_rule_id++;
    
    filter_rule_internal_t *internal = ngfw_malloc(sizeof(filter_rule_internal_t));
    if (!internal) return NGFW_ERR_NO_MEM;
    
    memcpy(&internal->rule, rule, sizeof(filter_rule_t));
    
    if (list_append(filter->rules, internal) != NGFW_OK) {
        ngfw_free(internal);
        return NGFW_ERR_NO_MEM;
    }
    
    return NGFW_OK;
}

ngfw_ret_t filter_remove_rule(filter_t *filter, u32 rule_id)
{
    if (!filter) return NGFW_ERR_INVALID;
    
    list_node_t *node;
    list_for_each(filter->rules, node) {
        filter_rule_internal_t *internal = (filter_rule_internal_t *)node->data;
        if (internal && internal->rule.id == rule_id) {
            list_remove(filter->rules, internal);
            ngfw_free(internal);
            return NGFW_OK;
        }
    }
    
    return NGFW_ERR_INVALID;
}

ngfw_ret_t filter_enable_rule(filter_t *filter, u32 rule_id)
{
    if (!filter) return NGFW_ERR_INVALID;
    
    list_node_t *node;
    list_for_each(filter->rules, node) {
        filter_rule_internal_t *internal = (filter_rule_internal_t *)node->data;
        if (internal && internal->rule.id == rule_id) {
            internal->rule.enabled = true;
            return NGFW_OK;
        }
    }
    
    return NGFW_ERR_INVALID;
}

ngfw_ret_t filter_disable_rule(filter_t *filter, u32 rule_id)
{
    if (!filter) return NGFW_ERR_INVALID;
    
    list_node_t *node;
    list_for_each(filter->rules, node) {
        filter_rule_internal_t *internal = (filter_rule_internal_t *)node->data;
        if (internal && internal->rule.id == rule_id) {
            internal->rule.enabled = false;
            return NGFW_OK;
        }
    }
    
    return NGFW_ERR_INVALID;
}

int filter_match_rule(filter_rule_t *rule, packet_t *pkt)
{
    if (!rule || !pkt || !rule->enabled) return 0;
    
    ip_header_t *ip = packet_get_ip(pkt);
    if (!ip) return 0;
    
    if (rule->ip_type != FILTER_IP_ANY) {
        if (rule->ip_type == FILTER_IP_IPV4 && (ip->version_ihl >> 4) != 4) return 0;
        if (rule->ip_type == FILTER_IP_IPV6 && (ip->version_ihl >> 4) != 6) return 0;
    }
    
    if (rule->proto != FILTER_PROTO_ANY) {
        if (rule->proto == FILTER_PROTO_TCP && ip->protocol != IP_PROTO_TCP) return 0;
        if (rule->proto == FILTER_PROTO_UDP && ip->protocol != IP_PROTO_UDP) return 0;
        if (rule->proto == FILTER_PROTO_ICMP && ip->protocol != IP_PROTO_ICMP) return 0;
    }
    
    if (rule->src_ip != 0) {
        if ((ip->src & rule->src_mask) != (rule->src_ip & rule->src_mask)) return 0;
    }
    
    if (rule->dst_ip != 0) {
        if ((ip->dst & rule->dst_mask) != (rule->dst_ip & rule->dst_mask)) return 0;
    }
    
    if (rule->proto == FILTER_PROTO_TCP || rule->proto == FILTER_PROTO_UDP) {
        u16 src_port = packet_get_src_port(pkt);
        u16 dst_port = packet_get_dst_port(pkt);
        
        if (rule->src_port_start > 0) {
            if (src_port < rule->src_port_start || src_port > rule->src_port_end) return 0;
        }
        
        if (rule->dst_port_start > 0) {
            if (dst_port < rule->dst_port_start || dst_port > rule->dst_port_end) return 0;
        }
    }
    
    return 1;
}

filter_action_t filter_process_packet(filter_t *filter, packet_t *pkt, session_t *session)
{
    (void)session;
    
    if (!filter || !pkt) return FILTER_ACTION_DROP;
    
    list_node_t *node;
    filter_rule_t *best_rule = NULL;
    u32 best_priority = 0;
    
    list_for_each(filter->rules, node) {
        filter_rule_internal_t *internal = (filter_rule_internal_t *)node->data;
        if (!internal) continue;
        
        if (!internal->rule.enabled) continue;
        
        if (filter_match_rule(&internal->rule, pkt)) {
            if (!best_rule || internal->rule.priority > best_priority) {
                best_rule = &internal->rule;
                best_priority = internal->rule.priority;
            }
        }
    }
    
    if (best_rule) {
        switch (best_rule->action) {
            case FILTER_ACTION_ACCEPT:
                filter->stats.packets_accepted++;
                filter->stats.bytes_accepted += pkt->len;
                return FILTER_ACTION_ACCEPT;
            case FILTER_ACTION_DROP:
                filter->stats.packets_dropped++;
                filter->stats.bytes_dropped += pkt->len;
                return FILTER_ACTION_DROP;
            case FILTER_ACTION_REJECT:
                filter->stats.packets_rejected++;
                return FILTER_ACTION_REJECT;
            case FILTER_ACTION_LOG:
                filter->stats.packets_accepted++;
                log_info("Packet logged: %u bytes", pkt->len);
                return FILTER_ACTION_ACCEPT;
            default:
                break;
        }
    }
    
    filter->stats.packets_accepted++;
    filter->stats.bytes_accepted += pkt->len;
    return FILTER_ACTION_ACCEPT;
}

filter_stats_t *filter_get_stats(filter_t *filter)
{
    return filter ? &filter->stats : NULL;
}

void filter_reset_stats(filter_t *filter)
{
    if (filter) {
        memset(&filter->stats, 0, sizeof(filter_stats_t));
    }
}
