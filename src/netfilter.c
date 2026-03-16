#include "ngfw/netfilter.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/list.h"
#include "ngfw/hash.h"
#include "ngfw/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>

struct netfilter {
    list_t *rules;
    nf_stats_t stats;
    bool initialized;
    bool ip_forward;
    netfilter_callback_t callbacks[8];
    void *callback_contexts[8];
    u32 callback_count;
};

static const char *nf_table_names[] = {
    "filter", "nat", "mangle", "raw"
};

static const char *nf_chain_names[] = {
    "PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"
};

static const char *nf_target_names[] = {
    "ACCEPT", "DROP", "REJECT", "LOG", "DNAT", "SNAT", "MASQUERADE"
};

static const char *nf_proto_names[] = {
    "all", "tcp", "udp", "icmp", "esp", "ah"
};

static u32 __attribute__((unused)) rule_hash(const void *key, u32 size)
{
    const netfilter_rule_t *rule = (const netfilter_rule_t *)key;
    return (rule->id % size);
}

static bool __attribute__((unused)) rule_match(const void *key1, const void *key2)
{
    return ((const netfilter_rule_t *)key1)->id == ((const netfilter_rule_t *)key2)->id;
}

netfilter_t *netfilter_create(void)
{
    netfilter_t *nf = ngfw_malloc(sizeof(netfilter_t));
    if (!nf) return NULL;

    memset(nf, 0, sizeof(netfilter_t));
    nf->rules = list_create(NULL);
    if (!nf->rules) {
        ngfw_free(nf);
        return NULL;
    }

    return nf;
}

void netfilter_destroy(netfilter_t *nf)
{
    if (!nf) return;

    if (nf->rules) {
        list_node_t *node;
        list_for_each(nf->rules, node) {
            netfilter_rule_t *rule = (netfilter_rule_t *)node->data;
            if (rule) ngfw_free(rule);
        }
        list_destroy(nf->rules);
    }

    ngfw_free(nf);
}

ngfw_ret_t netfilter_init(netfilter_t *nf)
{
    if (!nf || nf->initialized) return NGFW_ERR_INVALID;

    memset(&nf->stats, 0, sizeof(nf_stats_t));
    nf->initialized = true;
    nf->ip_forward = false;

    FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    if (fp) {
        char buf[8];
        if (fgets(buf, sizeof(buf), fp)) {
            nf->ip_forward = (buf[0] == '1');
        }
        fclose(fp);
    }

    log_info("Netfilter initialized");
    return NGFW_OK;
}

ngfw_ret_t netfilter_shutdown(netfilter_t *nf)
{
    if (!nf || !nf->initialized) return NGFW_ERR_INVALID;

    netfilter_clear_rules(nf);
    nf->initialized = false;

    log_info("Netfilter shutdown");
    return NGFW_OK;
}

ngfw_ret_t netfilter_add_rule(netfilter_t *nf, netfilter_rule_t *rule)
{
    if (!nf || !rule) return NGFW_ERR_INVALID;

    netfilter_rule_t *new_rule = ngfw_malloc(sizeof(netfilter_rule_t));
    if (!new_rule) return NGFW_ERR_NO_MEM;

    memcpy(new_rule, rule, sizeof(netfilter_rule_t));
    list_append(nf->rules, new_rule);
    nf->stats.active_rules++;

    return NGFW_OK;
}

ngfw_ret_t netfilter_del_rule(netfilter_t *nf, u32 rule_id)
{
    if (!nf) return NGFW_ERR_INVALID;

    list_node_t *node;
    list_for_each(nf->rules, node) {
        netfilter_rule_t *rule = (netfilter_rule_t *)node->data;
        if (rule && rule->id == rule_id) {
            list_remove(nf->rules, rule);
            ngfw_free(rule);
            nf->stats.active_rules--;
            return NGFW_OK;
        }
    }

    return NGFW_ERR;
}

ngfw_ret_t netfilter_clear_rules(netfilter_t *nf)
{
    if (!nf) return NGFW_ERR_INVALID;

    list_node_t *node;
    list_for_each(nf->rules, node) {
        netfilter_rule_t *rule = (netfilter_rule_t *)node->data;
        if (rule) ngfw_free(rule);
    }
    
    while (!list_empty(nf->rules)) {
        list_remove(nf->rules, list_first(nf->rules));
    }
    nf->stats.active_rules = 0;

    return NGFW_OK;
}

ngfw_ret_t netfilter_set_policy(netfilter_t *nf, nf_table_t table, nf_chain_t chain, nf_target_t target)
{
    (void)nf;
    (void)table;
    (void)chain;
    (void)target;
    return NGFW_OK;
}

ngfw_ret_t netfilter_enable_ip_forwarding(netfilter_t *nf, bool enable)
{
    if (!nf) return NGFW_ERR_INVALID;

    FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (!fp) {
        log_err("Failed to enable IP forwarding: %s", strerror(errno));
        return NGFW_ERR;
    }

    fprintf(fp, "%d", enable ? 1 : 0);
    fclose(fp);

    nf->ip_forward = enable;
    log_info("IP forwarding %s", enable ? "enabled" : "disabled");

    return NGFW_OK;
}

ngfw_ret_t netfilter_flush_table(netfilter_t *nf, nf_table_t table)
{
    if (!nf) return NGFW_ERR_INVALID;
    if (table >= NF_TABLE_MAX) return NGFW_ERR_INVALID;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iptables -t %s -F", nf_table_names[table]);
    int ret = system(cmd);

    if (ret != 0) {
        log_warn("Failed to flush table %s", nf_table_names[table]);
    }

    return (ret == 0) ? NGFW_OK : NGFW_ERR;
}

ngfw_ret_t netfilter_flush_chain(netfilter_t *nf, nf_chain_t chain)
{
    (void)nf;
    (void)chain;
    return NGFW_OK;
}

nf_stats_t *netfilter_get_stats(netfilter_t *nf)
{
    if (!nf) return NULL;
    return &nf->stats;
}

void netfilter_reset_stats(netfilter_t *nf)
{
    if (!nf) return;
    memset(&nf->stats, 0, sizeof(nf_stats_t));
}

static bool match_protocol(netfilter_rule_t *rule, packet_t *pkt)
{
    if (rule->protocol == NF_PROTO_ALL) return true;

    (void)pkt;
    return true;
}

static bool match_ip(netfilter_rule_t *rule, packet_t *pkt)
{
    if (rule->src_ip[0] == 0 && rule->dst_ip[0] == 0) return true;

    (void)rule;
    (void)pkt;
    return true;
}

static bool match_port(netfilter_rule_t *rule, packet_t *pkt)
{
    if (rule->src_port_min == 0 && rule->src_port_max == 0 &&
        rule->dst_port_min == 0 && rule->dst_port_max == 0) {
        return true;
    }

    (void)rule;
    (void)pkt;
    return true;
}

int netfilter_check_packet(netfilter_t *nf, packet_t *pkt)
{
    if (!nf || !nf->initialized || !pkt) return NF_TARGET_ACCEPT;

    nf->stats.packets_total++;

    list_node_t *node;
    list_for_each(nf->rules, node) {
        netfilter_rule_t *rule = (netfilter_rule_t *)node->data;
        if (rule && rule->enabled) {
            if (match_protocol(rule, pkt) && match_ip(rule, pkt) && match_port(rule, pkt)) {
                rule->packet_count++;
                nf->stats.bytes_total += pkt->len;

                if (rule->target == NF_TARGET_DROP || rule->target == NF_TARGET_REJECT) {
                    nf->stats.packets_dropped++;
                    return rule->target;
                }

                nf->stats.packets_accepted++;
                return rule->target;
            }
        }
    }

    nf->stats.packets_accepted++;
    return NF_TARGET_ACCEPT;
}

ngfw_ret_t netfilter_register_callback(netfilter_t *nf, netfilter_callback_t callback, void *context)
{
    if (!nf || !callback) return NGFW_ERR_INVALID;
    if (nf->callback_count >= 8) return NGFW_ERR_NO_MEM;

    nf->callbacks[nf->callback_count] = callback;
    nf->callback_contexts[nf->callback_count] = context;
    nf->callback_count++;

    return NGFW_OK;
}

static int run_iptables(const char *table, const char *chain, const char *rule_str)
{
    char cmd[1024];
    if (table && table[0]) {
        snprintf(cmd, sizeof(cmd), "iptables -t %s -A %s %s", table, chain, rule_str);
    } else {
        snprintf(cmd, sizeof(cmd), "iptables -A %s %s", chain, rule_str);
    }
    
    return system(cmd);
}

ngfw_ret_t netfilter_sync_to_kernel(netfilter_t *nf)
{
    if (!nf) return NGFW_ERR_INVALID;

    { int r = system("iptables -F"); (void)r; }
    { int r = system("iptables -X"); (void)r; }
    { int r = system("iptables -Z"); (void)r; }

    list_node_t *node;
    list_for_each(nf->rules, node) {
        netfilter_rule_t *rule = (netfilter_rule_t *)node->data;
        if (rule && rule->enabled) {
            char rule_str[512] = "";
            
            if (rule->protocol != NF_PROTO_ALL) {
                strcat(rule_str, " -p ");
                strcat(rule_str, nf_proto_names[rule->protocol]);
            }

            if (rule->src_ip[0] != 0) {
                strcat(rule_str, " -s ");
                strcat(rule_str, rule->src_ip);
            }

            if (rule->dst_ip[0] != 0) {
                strcat(rule_str, " -d ");
                strcat(rule_str, rule->dst_ip);
            }

            if (rule->dst_port_min > 0) {
                char port_str[32];
                snprintf(port_str, sizeof(port_str), " --dport %d", rule->dst_port_min);
                strcat(rule_str, port_str);
            }

            char target[32];
            snprintf(target, sizeof(target), " -j %s", nf_target_names[rule->target]);
            strcat(rule_str, target);

            run_iptables(nf_table_names[rule->table], nf_chain_names[rule->chain], rule_str);
        }
    }

    log_info("Synced %u rules to kernel", nf->stats.active_rules);
    return NGFW_OK;
}

ngfw_ret_t netfilter_load_from_kernel(netfilter_t *nf)
{
    if (!nf) return NGFW_ERR_INVALID;

    netfilter_clear_rules(nf);

    FILE *fp = popen("iptables -L -n -v -x", "r");
    if (!fp) return NGFW_ERR;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "Chain")) continue;
        
        netfilter_rule_t rule = {0};
        rule.id = nf->stats.active_rules + 1;
        rule.enabled = true;
        
        if (strstr(line, "ACCEPT")) rule.target = NF_TARGET_ACCEPT;
        else if (strstr(line, "DROP")) rule.target = NF_TARGET_DROP;
        else if (strstr(line, "REJECT")) rule.target = NF_TARGET_REJECT;
        else continue;

        char *p = line;
        while (*p == ' ') p++;
        if (isdigit(*p)) {
            sscanf(p, "%lu", &rule.packet_count);
        }

        netfilter_add_rule(nf, &rule);
    }

    pclose(fp);
    log_info("Loaded %u rules from kernel", nf->stats.active_rules);
    return NGFW_OK;
}
