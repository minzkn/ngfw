#include "ngfw/ips.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include "ngfw/log.h"
#include "ngfw/packet.h"
#include <string.h>

struct ips {
    hash_table_t *signatures;
    ips_stats_t stats;
};

ips_t *ips_create(void)
{
    ips_t *ips = ngfw_malloc(sizeof(ips_t));
    if (!ips) return NULL;
    
    ips->signatures = hash_create(1024, NULL, NULL, NULL);
    if (!ips->signatures) {
        ngfw_free(ips);
        return NULL;
    }
    
    memset(&ips->stats, 0, sizeof(ips_stats_t));
    
    return ips;
}

void ips_destroy(ips_t *ips)
{
    if (!ips) return;
    if (ips->signatures) {
        hash_destroy(ips->signatures);
    }
    ngfw_free(ips);
}

ngfw_ret_t ips_add_signature(ips_t *ips, ips_signature_t *sig)
{
    if (!ips || !sig) return NGFW_ERR_INVALID;
    
    return hash_insert(ips->signatures, (void *)(uintptr_t)sig->id, sig);
}

ngfw_ret_t ips_remove_signature(ips_t *ips, u32 sig_id)
{
    if (!ips) return NGFW_ERR_INVALID;
    
    hash_remove(ips->signatures, (void *)(uintptr_t)sig_id);
    return NGFW_OK;
}

ngfw_ret_t ips_enable_signature(ips_t *ips, u32 sig_id)
{
    if (!ips) return NGFW_ERR_INVALID;
    
    ips_signature_t *sig = (ips_signature_t *)hash_lookup(ips->signatures, (void *)(uintptr_t)sig_id);
    if (sig) {
        sig->enabled = true;
        return NGFW_OK;
    }
    return NGFW_ERR_INVALID;
}

ngfw_ret_t ips_disable_signature(ips_t *ips, u32 sig_id)
{
    if (!ips) return NGFW_ERR_INVALID;
    
    ips_signature_t *sig = (ips_signature_t *)hash_lookup(ips->signatures, (void *)(uintptr_t)sig_id);
    if (sig) {
        sig->enabled = false;
        return NGFW_OK;
    }
    return NGFW_ERR_INVALID;
}

static int pattern_match(const u8 *data, u32 len, const u8 *pattern, u32 pattern_len)
{
    if (!data || !pattern || len < pattern_len) return 0;
    
    for (u32 i = 0; i <= len - pattern_len; i++) {
        bool match = true;
        for (u32 j = 0; j < pattern_len; j++) {
            if (pattern[j] != 0xFF && data[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return 1;
    }
    
    return 0;
}

ips_action_t ips_process_packet(ips_t *ips, packet_t *pkt)
{
    if (!ips || !pkt) return IPS_ACTION_ALLOW;
    
    ips->stats.total_checked++;
    
    if (!pkt->data || pkt->len == 0) {
        return IPS_ACTION_ALLOW;
    }
    
    void **iter = hash_iterate_start(ips->signatures);
    while (hash_iterate_has_next(iter)) {
        ips_signature_t *sig = (ips_signature_t *)hash_iterate_next(ips->signatures, iter);
        if (sig && sig->enabled) {
            if (sig->pattern_len > 0 && sig->pattern_len <= pkt->len) {
                if (pattern_match(pkt->data, pkt->len, sig->pattern, sig->pattern_len)) {
                    ips->stats.threats_detected++;
                    
                    switch (sig->action) {
                        case IPS_ACTION_DROP:
                            ips->stats.threats_blocked++;
                            log_warn("IPS: Blocked threat %s (sig_id=%u)", sig->name, sig->id);
                            ngfw_free(iter);
                            return IPS_ACTION_DROP;
                        case IPS_ACTION_BLOCK:
                            ips->stats.threats_blocked++;
                            log_warn("IPS: Blocked threat %s (sig_id=%u)", sig->name, sig->id);
                            ngfw_free(iter);
                            return IPS_ACTION_BLOCK;
                        case IPS_ACTION_LOG:
                            ips->stats.alerts_generated++;
                            log_warn("IPS: Alert - threat %s detected (sig_id=%u)", sig->name, sig->id);
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }
    ngfw_free(iter);
    
    return IPS_ACTION_ALLOW;
}

ips_stats_t *ips_get_stats(ips_t *ips)
{
    return ips ? &ips->stats : NULL;
}

void ips_reset_stats(ips_t *ips)
{
    if (ips) {
        memset(&ips->stats, 0, sizeof(ips_stats_t));
    }
}

ngfw_ret_t ips_load_signatures(ips_t *ips, const char *path)
{
    (void)ips;
    (void)path;
    log_info("IPS: Signature loading from %s not implemented yet", path);
    return NGFW_OK;
}

ngfw_ret_t ips_save_signatures(ips_t *ips, const char *path)
{
    (void)ips;
    (void)path;
    return NGFW_OK;
}
