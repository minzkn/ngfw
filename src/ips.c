#include "ngfw/ips.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include "ngfw/list.h"
#include "ngfw/log.h"
#include "ngfw/crypto.h"
#include "ngfw/platform.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define MAX_SIGNATURES 4096
#define MAX_ALERTS 1024

typedef struct ips_signature_impl {
    ips_signature_t sig;
    struct ips_signature_impl *next;
} ips_signature_impl_t;

typedef struct ips_alert_impl {
    ips_alert_t alert;
    struct ips_alert_impl *next;
} ips_alert_impl_t;

struct ips {
    hash_table_t *signatures;
    ips_signature_impl_t *sig_list;
    ips_alert_impl_t *alert_list;
    ips_alert_impl_t *alert_tail;
    hash_table_t *blocked_ips;
    ips_action_t severity_actions[5];
    u32 next_alert_id;
    ips_stats_t stats;
    bool initialized;
    bool running;
};

static u32 sig_hash(const void *key, u32 size)
{
    return (*(const u32 *)key) % size;
}

static bool sig_match(const void *key1, const void *key2)
{
    return (*(const u32 *)key1) == (*(const u32 *)key2);
}

static void load_default_signatures(ips_t *ips)
{
    ips_signature_t default_sigs[] = {
        {1, "SQL Injection Attempt", "union.*select", IPS_SEVERITY_HIGH, IPS_CLASSIFICATION_EXPLOIT, "SQL injection attack attempt", "Sanitize input", 6, 0, 80, true, 1},
        {2, "XSS Attack", "<script>", IPS_SEVERITY_HIGH, IPS_CLASSIFICATION_EXPLOIT, "Cross-site scripting attempt", "Sanitize input", 6, 0, 80, true, 1},
        {3, "Port Scan - SYN", "SYN.*FIN", IPS_SEVERITY_MEDIUM, IPS_CLASSIFICATION_SCAN, "SYN FIN port scan", "Block scanner", 6, 0, 0, true, 1},
        {4, "Ping of Death", "frag.*offset", IPS_SEVERITY_CRITICAL, IPS_CLASSIFICATION_EXPLOIT, "Ping of death attack", "Block attacker", 1, 0, 0, true, 1},
        {5, "SYN Flood", "TCP.*SYN.*100/sec", IPS_SEVERITY_HIGH, IPS_CLASSIFICATION_DOS, "SYN flood attack", "Enable rate limiting", 6, 0, 0, true, 1},
        {6, "IP Spoofing", "ip.*src.*0\\.0\\.0\\.0", IPS_SEVERITY_MEDIUM, IPS_CLASSIFICATION_INTRUSION, "IP spoofing attempt", "Verify source IP", 0, 0, 0, true, 1},
        {7, "Land Attack", "src.*eq.*dst", IPS_SEVERITY_CRITICAL, IPS_CLASSIFICATION_EXPLOIT, "Land attack", "Block attacker", 6, 0, 0, true, 1},
        {8, "Teardrop Attack", "frag.*overlap", IPS_SEVERITY_CRITICAL, IPS_CLASSIFICATION_EXPLOIT, "Teardrop attack fragment", "Block attacker", 0, 0, 0, true, 1},
        {9, "SSH Brute Force", "ssh.*failed.*login", IPS_SEVERITY_HIGH, IPS_CLASSIFICATION_INTRUSION, "SSH brute force attempt", "Enable fail2ban", 6, 0, 22, true, 1},
        {10, "FTP Brute Force", "ftp.*530.*failed", IPS_SEVERITY_HIGH, IPS_CLASSIFICATION_INTRUSION, "FTP brute force attempt", "Enable fail2ban", 6, 0, 21, true, 1},
        {11, "HTTP Flood", "http.*1000/sec", IPS_SEVERITY_HIGH, IPS_CLASSIFICATION_DOS, "HTTP flood attack", "Enable rate limiting", 6, 0, 80, true, 1},
        {12, "DNS Amplification", "dns.*response.*large", IPS_SEVERITY_HIGH, IPS_CLASSIFICATION_DOS, "DNS amplification attack", "Block amplifier", 17, 0, 53, true, 1},
        {13, "NTP Amplification", "ntp.*monlist", IPS_SEVERITY_HIGH, IPS_CLASSIFICATION_DOS, "NTP amplification attack", "Disable monlist", 17, 0, 123, true, 1},
        {14, "Heartbleed", " heartbeat", IPS_SEVERITY_CRITICAL, IPS_CLASSIFICATION_EXPLOIT, "Heartbleed vulnerability", "Update OpenSSL", 6, 0, 443, true, 1},
        {15, "Shellshock", ".*\\(\\).*\\{.*:", IPS_SEVERITY_CRITICAL, IPS_CLASSIFICATION_EXPLOIT, "Shellshock bash vulnerability", "Update bash", 6, 0, 80, true, 1},
        {16, "SQL Injection - OR", ".*or.*1.*=.*1", IPS_SEVERITY_HIGH, IPS_CLASSIFICATION_EXPLOIT, "SQL injection OR attack", "Sanitize input", 6, 0, 80, true, 1},
        {17, "CMD Injection", ".*\\|.*ls", IPS_SEVERITY_CRITICAL, IPS_CLASSIFICATION_EXPLOIT, "Command injection", "Sanitize input", 6, 0, 80, true, 1},
        {18, "Directory Traversal", "\\.\\./", IPS_SEVERITY_MEDIUM, IPS_CLASSIFICATION_EXPLOIT, "Directory traversal attempt", "Restrict access", 6, 0, 80, true, 1},
        {19, "Remote File Inclusion", "http://", IPS_SEVERITY_HIGH, IPS_CLASSIFICATION_EXPLOIT, "RFI attempt", "Disable include", 6, 0, 80, true, 1},
        {20, "CSRF Token Missing", "POST.*no.*token", IPS_SEVERITY_MEDIUM, IPS_CLASSIFICATION_INTRUSION, "CSRF protection missing", "Add CSRF token", 6, 0, 80, true, 1},
    };

    int num_sigs = sizeof(default_sigs) / sizeof(ips_signature_t);

    for (int i = 0; i < num_sigs; i++) {
        ips_add_signature(ips, &default_sigs[i]);
    }

    log_info("Loaded %d default signatures", num_sigs);
}

ips_t *ips_create(void)
{
    ips_t *ips = ngfw_malloc(sizeof(ips_t));
    if (!ips) return NULL;

    memset(ips, 0, sizeof(ips_t));

    ips->signatures = hash_create(512, sig_hash, sig_match, NULL);
    if (!ips->signatures) {
        ngfw_free(ips);
        return NULL;
    }

    ips->sig_list = NULL;
    ips->alert_list = NULL;
    ips->alert_tail = NULL;
    ips->next_alert_id = 1;

    load_default_signatures(ips);

    log_info("IPS created with default signatures");

    return ips;
}

void ips_destroy(ips_t *ips)
{
    if (!ips) return;

    if (ips->signatures) {
        hash_destroy(ips->signatures);
    }

    ips_signature_impl_t *sig = ips->sig_list;
    while (sig) {
        ips_signature_impl_t *next = sig->next;
        ngfw_free(sig);
        sig = next;
    }

    ips_alert_impl_t *alert = ips->alert_list;
    while (alert) {
        ips_alert_impl_t *next = alert->next;
        ngfw_free(alert);
        alert = next;
    }

    ngfw_free(ips);
}

ngfw_ret_t ips_init(ips_t *ips)
{
    if (!ips) return NGFW_ERR_INVALID;

    ips->initialized = true;

    log_info("IPS initialized");

    return NGFW_OK;
}

ngfw_ret_t ips_start(ips_t *ips)
{
    if (!ips || !ips->initialized) return NGFW_ERR_INVALID;

    ips->running = true;

    log_info("IPS started");

    return NGFW_OK;
}

ngfw_ret_t ips_stop(ips_t *ips)
{
    if (!ips) return NGFW_ERR_INVALID;

    ips->running = false;

    log_info("IPS stopped");

    return NGFW_OK;
}

ngfw_ret_t ips_add_signature(ips_t *ips, ips_signature_t *sig)
{
    if (!ips || !sig) return NGFW_ERR_INVALID;

    ips_signature_impl_t *impl = ngfw_malloc(sizeof(ips_signature_impl_t));
    if (!impl) return NGFW_ERR_NO_MEM;

    impl->sig = *sig;
    impl->next = NULL;

    hash_insert(ips->signatures, &sig->id, impl);

    impl->next = ips->sig_list;
    ips->sig_list = impl;

    ips->stats.signatures_loaded++;
    if (sig->enabled) {
        ips->stats.signatures_enabled++;
    }

    log_debug("IPS signature added: %s (ID: %u)", sig->name, sig->id);

    return NGFW_OK;
}

ngfw_ret_t ips_del_signature(ips_t *ips, u32 sig_id)
{
    if (!ips) return NGFW_ERR_INVALID;

    hash_remove(ips->signatures, &sig_id);

    log_debug("IPS signature deleted: %u", sig_id);

    return NGFW_OK;
}

ngfw_ret_t ips_enable_signature(ips_t *ips, u32 sig_id)
{
    if (!ips) return NGFW_ERR_INVALID;

    ips_signature_impl_t *impl = hash_lookup(ips->signatures, &sig_id);
    if (!impl) return NGFW_ERR_INVALID;

    if (!impl->sig.enabled) {
        impl->sig.enabled = true;
        ips->stats.signatures_enabled++;
    }

    return NGFW_OK;
}

ngfw_ret_t ips_disable_signature(ips_t *ips, u32 sig_id)
{
    if (!ips) return NGFW_ERR_INVALID;

    ips_signature_impl_t *impl = hash_lookup(ips->signatures, &sig_id);
    if (!impl) return NGFW_ERR_INVALID;

    if (impl->sig.enabled) {
        impl->sig.enabled = false;
        ips->stats.signatures_enabled--;
    }

    return NGFW_OK;
}

ngfw_ret_t ips_load_signatures(ips_t *ips, const char *filename)
{
    if (!ips || !filename) return NGFW_ERR_INVALID;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        log_err("Failed to open signature file: %s", filename);
        return NGFW_ERR;
    }

    char line[1024];
    int loaded = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        ips_signature_t sig = {0};
        if (sscanf(line, "%u|%[^|]|%[^|]|%d|%d",
                   &sig.id, sig.name, sig.pattern,
                   (int*)&sig.severity, (int*)&sig.classification) >= 3) {
            sig.enabled = true;
            sig.rev = 1;
            ips_add_signature(ips, &sig);
            loaded++;
        }
    }

    fclose(fp);

    log_info("Loaded %d signatures from %s", loaded, filename);

    return NGFW_OK;
}

ngfw_ret_t ips_save_signatures(ips_t *ips, const char *filename)
{
    if (!ips || !filename) return NGFW_ERR_INVALID;

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        return NGFW_ERR;
    }

    fprintf(fp, "# NGFW IPS Signatures\n");
    fprintf(fp, "# Format: id|name|pattern|severity|classification\n\n");

    ips_signature_impl_t *sig = ips->sig_list;
    while (sig) {
        fprintf(fp, "%u|%s|%s|%d|%d\n",
                sig->sig.id, sig->sig.name, sig->sig.pattern,
                sig->sig.severity, sig->sig.classification);
        sig = sig->next;
    }

    fclose(fp);

    return NGFW_OK;
}

static int pattern_match(const char *pattern, const char *data, u32 data_len)
{
    if (!pattern || !data) return 0;

    const char *p = pattern;

    while (*p && data_len > 0) {
        if (*p == '.') {
            p++;
            if (*p == '*') {
                p++;
                return 1;
            }
            if (*p == '+') {
                p++;
                if (data_len > 0) {
                    data++;
                    data_len--;
                }
            }
        } else if (*p == *data) {
            p++;
            data++;
            data_len--;
        } else {
            return 0;
        }
    }

    return (*p == '\0') ? 1 : 0;
}

ngfw_ret_t ips_check_packet(ips_t *ips, packet_t *pkt, ips_alert_t *alert)
{
    if (!ips || !pkt) return NGFW_ERR_INVALID;

    u8 *data = pkt->data;
    u32 data_len = pkt->len;

    if (!data || data_len == 0) {
        return NGFW_ERR;
    }

    ips_signature_impl_t *sig = ips->sig_list;
    while (sig) {
        if (!sig->sig.enabled) {
            sig = sig->next;
            continue;
        }

        if (data_len > 0) {
            if (pattern_match(sig->sig.pattern, (const char*)data, data_len)) {
                ips->stats.matches++;
                ips->stats.total_alerts++;

                switch (sig->sig.severity) {
                    case IPS_SEVERITY_LOW: ips->stats.alerts_low++; break;
                    case IPS_SEVERITY_MEDIUM: ips->stats.alerts_medium++; break;
                    case IPS_SEVERITY_HIGH: ips->stats.alerts_high++; break;
                    case IPS_SEVERITY_CRITICAL: ips->stats.alerts_critical++; break;
                }

                if (alert) {
                    alert->id = ips->next_alert_id++;
                    alert->signature_id = sig->sig.id;
                    strncpy(alert->signature_name, sig->sig.name, sizeof(alert->signature_name) - 1);
                    alert->severity = sig->sig.severity;
                    alert->classification = sig->sig.classification;
                    alert->timestamp = get_ms_time();
                    snprintf(alert->message, sizeof(alert->message),
                             "%s - %s", sig->sig.name, sig->sig.description);

                    ips_alert_impl_t *impl = ngfw_malloc(sizeof(ips_alert_impl_t));
                    if (impl) {
                        impl->alert = *alert;
                        impl->next = NULL;

                        if (ips->alert_tail) {
                            ips->alert_tail->next = impl;
                            ips->alert_tail = impl;
                        } else {
                            ips->alert_list = impl;
                            ips->alert_tail = impl;
                        }
                    }
                }

                log_warn("IPS Alert: %s (Severity: %d)", sig->sig.name, sig->sig.severity);

                return NGFW_OK;
            }
        }

        sig = sig->next;
    }

    return NGFW_ERR;
}

ips_stats_t *ips_get_stats(ips_t *ips)
{
    if (!ips) return NULL;
    return &ips->stats;
}

void ips_reset_stats(ips_t *ips)
{
    if (!ips) return;
    memset(&ips->stats, 0, sizeof(ips_stats_t));
}

void ips_reset_alerts(ips_t *ips)
{
    if (!ips) return;

    ips_alert_impl_t *alert = ips->alert_list;
    while (alert) {
        ips_alert_impl_t *next = alert->next;
        ngfw_free(alert);
        alert = next;
    }

    ips->alert_list = NULL;
    ips->alert_tail = NULL;
    ips->next_alert_id = 1;
}

ngfw_ret_t ips_get_alerts(ips_t *ips, ips_alert_t **alerts, u32 *count)
{
    if (!ips || !alerts || !count) return NGFW_ERR_INVALID;

    *alerts = NULL;
    *count = 0;

    u32 num_alerts = 0;
    ips_alert_impl_t *impl = ips->alert_list;
    while (impl) {
        num_alerts++;
        impl = impl->next;
    }

    if (num_alerts == 0) return NGFW_OK;

    *alerts = ngfw_malloc(num_alerts * sizeof(ips_alert_t));
    if (!*alerts) return NGFW_ERR_NO_MEM;

    *count = num_alerts;
    impl = ips->alert_list;
    u32 idx = 0;
    while (impl && idx < num_alerts) {
        (*alerts)[idx++] = impl->alert;
        impl = impl->next;
    }

    return NGFW_OK;
}

ngfw_ret_t ips_check_packet_with_action(ips_t *ips, packet_t *pkt, ips_alert_t *alert, bool *drop)
{
    if (!ips || !pkt) return NGFW_ERR_INVALID;
    
    *drop = false;
    
    if (!ips->running) {
        ips->stats.packets_passed++;
        return NGFW_OK;
    }

    ip_header_t *ip = packet_get_ip(pkt);
    if (ip) {
        if (ips_is_ip_blocked(ips, ip->src)) {
            *drop = true;
            ips->stats.packets_dropped++;
            log_warn("IPS: Dropping packet from blocked IP");
            return NGFW_OK;
        }
    }

    ips_alert_t temp_alert = {0};
    ngfw_ret_t ret = ips_check_packet(ips, pkt, &temp_alert);
    
    if (ret == NGFW_OK && temp_alert.signature_id > 0) {
        ips_action_t action = ips->severity_actions[temp_alert.severity];
        
        switch (action) {
            case IPS_ACTION_DROP:
                *drop = true;
                ips->stats.packets_dropped++;
                log_warn("IPS: Dropping malicious packet - %s", temp_alert.signature_name);
                
                if (ip) {
                    ips_block_ip(ips, ip->src, 300);
                }
                break;
                
            case IPS_ACTION_REJECT:
                *drop = true;
                ips->stats.packets_dropped++;
                log_warn("IPS: Rejecting malicious packet - %s", temp_alert.signature_name);
                
                if (ip) {
                    ips_block_ip(ips, ip->src, 300);
                }
                break;
                
            case IPS_ACTION_LOG:
                log_warn("IPS: Logged malicious packet - %s", temp_alert.signature_name);
                ips->stats.packets_passed++;
                break;
                
            case IPS_ACTION_ALERT:
            default:
                log_warn("IPS: Alert for malicious packet - %s", temp_alert.signature_name);
                ips->stats.packets_passed++;
                break;
        }
        
        if (alert) {
            *alert = temp_alert;
        }
    } else {
        ips->stats.packets_passed++;
    }
    
    return NGFW_OK;
}

ngfw_ret_t ips_set_default_action(ips_t *ips, ips_severity_t severity, ips_action_t action)
{
    if (!ips || severity < IPS_SEVERITY_LOW || severity > IPS_SEVERITY_CRITICAL) {
        return NGFW_ERR_INVALID;
    }
    
    ips->severity_actions[severity] = action;
    log_info("IPS: Set default action for severity %d to %d", severity, action);
    
    return NGFW_OK;
}

ngfw_ret_t ips_set_signature_action(ips_t *ips, u32 sig_id, ips_action_t action)
{
    if (!ips) return NGFW_ERR_INVALID;
    
    ips_signature_impl_t *impl = hash_lookup(ips->signatures, &sig_id);
    if (!impl) return NGFW_ERR_INVALID;
    
    log_info("IPS: Set action for signature %u to %d", sig_id, action);
    
    return NGFW_OK;
}

typedef struct blocked_ip_entry {
    u32 ip;
    u64 blocked_at;
    u32 duration_sec;
} blocked_ip_entry_t;

static u32 blocked_ip_hash(const void *key, u32 size)
{
    return (*(const u32 *)key) % size;
}

static bool blocked_ip_match(const void *key1, const void *key2)
{
    return (*(const u32 *)key1) == (*(const u32 *)key2);
}

ngfw_ret_t ips_block_ip(ips_t *ips, u32 ip, u32 duration_sec)
{
    if (!ips || ip == 0) return NGFW_ERR_INVALID;
    
    blocked_ip_entry_t *entry = ngfw_malloc(sizeof(blocked_ip_entry_t));
    if (!entry) return NGFW_ERR_NO_MEM;
    
    entry->ip = ip;
    entry->blocked_at = get_ms_time();
    entry->duration_sec = duration_sec;
    
    hash_insert(ips->blocked_ips, &ip, entry);
    
    log_warn("IPS: Blocked IP %u.%u.%u.%u for %u seconds",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF, duration_sec);
    
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iptables -I INPUT -s %u.%u.%u.%u -j DROP 2>/dev/null",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
    { int r = system(cmd); (void)r; }
    
    return NGFW_OK;
}

ngfw_ret_t ips_unblock_ip(ips_t *ips, u32 ip)
{
    if (!ips || ip == 0) return NGFW_ERR_INVALID;
    
    hash_remove(ips->blocked_ips, &ip);
    
    log_info("IPS: Unblocked IP %u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
    
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iptables -D INPUT -s %u.%u.%u.%u -j DROP 2>/dev/null",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
    { int r = system(cmd); (void)r; }
    
    return NGFW_OK;
}

ngfw_ret_t ips_get_blocked_ips(ips_t *ips, u32 **ips_list, u32 *count)
{
    if (!ips || !ips_list || !count) return NGFW_ERR_INVALID;
    
    *ips_list = NULL;
    *count = 0;
    
    return NGFW_OK;
}

bool ips_is_ip_blocked(ips_t *ips, u32 ip)
{
    if (!ips || ip == 0) return false;
    
    blocked_ip_entry_t *entry = hash_lookup(ips->blocked_ips, &ip);
    if (!entry) return false;
    
    u64 elapsed = get_ms_time() - entry->blocked_at;
    if (elapsed > (u64)entry->duration_sec * 1000) {
        ips_unblock_ip(ips, ip);
        return false;
    }
    
    return true;
}
