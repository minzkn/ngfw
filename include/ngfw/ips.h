#ifndef NGFW_IPS_H
#define NGFW_IPS_H

#include "types.h"
#include "packet.h"

typedef enum {
    IPS_SEVERITY_LOW = 1,
    IPS_SEVERITY_MEDIUM = 2,
    IPS_SEVERITY_HIGH = 3,
    IPS_SEVERITY_CRITICAL = 4
} ips_severity_t;

typedef enum {
    IPS_CLASSIFICATION_UNKNOWN,
    IPS_CLASSIFICATION_MALWARE,
    IPS_CLASSIFICATION_EXPLOIT,
    IPS_CLASSIFICATION_SCAN,
    IPS_CLASSIFICATION_DOS,
    IPS_CLASSIFICATION_INTRUSION,
    IPS_CLASSIFICATION_WORM,
    IPS_CLASSIFICATION_TROJAN,
    IPS_CLASSIFICATION_BACKDOOR,
    IPS_CLASSIFICATION_Ransomware
} ips_classification_t;

typedef struct ips_signature {
    u32 id;
    char name[128];
    char pattern[256];
    ips_severity_t severity;
    ips_classification_t classification;
    char description[512];
    char solution[512];
    u8 proto;
    u16 src_port;
    u16 dst_port;
    bool enabled;
    u32 rev;
} ips_signature_t;

typedef struct ips_alert {
    u32 id;
    u32 signature_id;
    char signature_name[128];
    ips_severity_t severity;
    ips_classification_t classification;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 proto;
    u64 timestamp;
    char message[512];
} ips_alert_t;

typedef struct ips_stats {
    u64 total_alerts;
    u64 alerts_low;
    u64 alerts_medium;
    u64 alerts_high;
    u64 alerts_critical;
    u64 packets_dropped;
    u64 packets_passed;
    u64 signatures_loaded;
    u64 signatures_enabled;
    u64 matches;
} ips_stats_t;

typedef struct ips ips_t;

ips_t *ips_create(void);
void ips_destroy(ips_t *ips);

ngfw_ret_t ips_init(ips_t *ips);
ngfw_ret_t ips_start(ips_t *ips);
ngfw_ret_t ips_stop(ips_t *ips);

ngfw_ret_t ips_add_signature(ips_t *ips, ips_signature_t *sig);
ngfw_ret_t ips_del_signature(ips_t *ips, u32 sig_id);
ngfw_ret_t ips_enable_signature(ips_t *ips, u32 sig_id);
ngfw_ret_t ips_disable_signature(ips_t *ips, u32 sig_id);

ngfw_ret_t ips_load_signatures(ips_t *ips, const char *filename);
ngfw_ret_t ips_save_signatures(ips_t *ips, const char *filename);

ngfw_ret_t ips_check_packet(ips_t *ips, packet_t *pkt, ips_alert_t *alert);
ngfw_ret_t ips_check_packet_with_action(ips_t *ips, packet_t *pkt, ips_alert_t *alert, bool *drop);

typedef enum {
    IPS_ACTION_ALERT,
    IPS_ACTION_DROP,
    IPS_ACTION_LOG,
    IPS_ACTION_REJECT
} ips_action_t;

ngfw_ret_t ips_set_default_action(ips_t *ips, ips_severity_t severity, ips_action_t action);
ngfw_ret_t ips_set_signature_action(ips_t *ips, u32 sig_id, ips_action_t action);
ngfw_ret_t ips_block_ip(ips_t *ips, u32 ip, u32 duration_sec);
ngfw_ret_t ips_unblock_ip(ips_t *ips, u32 ip);
ngfw_ret_t ips_get_blocked_ips(ips_t *ips, u32 **ips_list, u32 *count);
bool ips_is_ip_blocked(ips_t *ips, u32 ip);

ips_stats_t *ips_get_stats(ips_t *ips);
void ips_reset_stats(ips_t *ips);
void ips_reset_alerts(ips_t *ips);

ngfw_ret_t ips_get_alerts(ips_t *ips, ips_alert_t **alerts, u32 *count);

#endif
