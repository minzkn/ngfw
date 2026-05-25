/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_SECURITY_ANTIVIRUS_H
#define NGFW_SECURITY_ANTIVIRUS_H

#include "ngfw/types.h"
#include "ngfw/network/packet.h"
#include "ngfw/hash.h"

/*
 * Anti-Virus
 * Signature-based malware detection
 */

/* Threat types */
typedef enum {
    AV_THREAT_VIRUS,
    AV_THREAT_TROJAN,
    AV_THREAT_BACKDOOR,
    AV_THREAT_Ransomware,
    AV_THREAT_EXPLOIT,
    AV_THREAT_SPYWARE,
    AV_THREAT_ADWARE
} av_threat_type_t;

/* Scan result */
typedef enum {
    AV_SCAN_RESULT_CLEAN,
    AV_SCAN_RESULT_INFECTED,
    AV_SCAN_RESULT_SUSPICIOUS,
    AV_SCAN_RESULT_ERROR
} av_scan_result_t;

/* Alert */
typedef struct av_alert {
    u32 id;
    u32 signature_id;
    char signature_name[64];
    char threat_name[64];
    av_threat_type_t threat_type;
    u64 timestamp;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    char message[256];
} av_alert_t;

/* Signature */
typedef struct av_signature {
    u32 id;
    char name[64];
    char pattern[256];
    av_threat_type_t threat_type;
    char threat_name[64];
    char description[256];
    bool enabled;
    int rev;
} av_signature_t;

/* Statistics */
typedef struct av_stats {
    u64 scans_performed;
    u64 threats_detected;
    u64 files_clean;
    u64 files_infected;
    u64 signatures_loaded;
    u64 signatures_enabled;
    u64 files_scanned;
    u64 bytes_scanned;
    u64 files_blocked;
    u64 scans_passed;
} av_stats_t;

/* Forward declaration - full definition in antivirus.c */
typedef struct antivirus antivirus_t;

antivirus_t *antivirus_create(void);
void antivirus_destroy(antivirus_t *av);
ngfw_ret_t antivirus_init(antivirus_t *av);
ngfw_ret_t antivirus_start(antivirus_t *av);
ngfw_ret_t antivirus_stop(antivirus_t *av);

ngfw_ret_t antivirus_scan_packet(antivirus_t *av, packet_t *pkt, av_scan_result_t *result, av_alert_t *alert);
ngfw_ret_t antivirus_scan_buffer(antivirus_t *av, const u8 *buffer, u32 len, av_scan_result_t *result, av_alert_t *alert);
ngfw_ret_t antivirus_load_signatures(antivirus_t *av, const char *filename);
ngfw_ret_t antivirus_add_signature(antivirus_t *av, av_signature_t *sig);
ngfw_ret_t antivirus_del_signature(antivirus_t *av, u32 sig_id);
ngfw_ret_t antivirus_get_alerts(antivirus_t *av, av_alert_t **alerts, u32 *count);

av_stats_t *antivirus_get_stats(antivirus_t *av);
void antivirus_reset_stats(antivirus_t *av);

#endif
