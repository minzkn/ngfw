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

#ifndef NGFW_ANTIVIRUS_H
#define NGFW_ANTIVIRUS_H

#include "types.h"
#include "packet.h"

typedef enum {
    AV_SCAN_RESULT_CLEAN,
    AV_SCAN_RESULT_INFECTED,
    AV_SCAN_RESULT_SUSPICIOUS,
    AV_SCAN_RESULT_ERROR
} av_scan_result_t;

typedef enum {
    AV_THREAT_TROJAN,
    AV_THREAT_WORM,
    AV_THREAT_VIRUS,
    AV_THREAT_Ransomware,
    AV_THREAT_ADWARE,
    AV_THREAT_SPYWARE,
    AV_THREAT_BACKDOOR,
    AV_THREAT_KEYLOGGER,
    AV_THREAT_ROOTKIT,
    AV_THREAT_EXPLOIT,
    AV_THREAT_UNKNOWN
} av_threat_type_t;

typedef struct av_signature {
    u32 id;
    char name[128];
    char pattern[256];
    av_threat_type_t threat_type;
    char threat_name[128];
    char description[512];
    bool enabled;
    u32 rev;
} av_signature_t;

typedef struct av_alert {
    u32 id;
    u32 signature_id;
    char signature_name[128];
    av_threat_type_t threat_type;
    char threat_name[128];
    u64 timestamp;
    char message[512];
} av_alert_t;

typedef struct av_stats {
    u64 files_scanned;
    u64 files_infected;
    u64 files_blocked;
    u64 bytes_scanned;
    u64 signatures_loaded;
    u64 signatures_enabled;
    u64 scans_passed;
    u64 scans_failed;
} av_stats_t;

typedef struct antivirus antivirus_t;

antivirus_t *antivirus_create(void);
void antivirus_destroy(antivirus_t *av);

ngfw_ret_t antivirus_init(antivirus_t *av);
ngfw_ret_t antivirus_start(antivirus_t *av);
ngfw_ret_t antivirus_stop(antivirus_t *av);

ngfw_ret_t antivirus_add_signature(antivirus_t *av, av_signature_t *sig);
ngfw_ret_t antivirus_del_signature(antivirus_t *av, u32 sig_id);
ngfw_ret_t antivirus_enable_signature(antivirus_t *av, u32 sig_id);
ngfw_ret_t antivirus_disable_signature(antivirus_t *av, u32 sig_id);

ngfw_ret_t antivirus_load_signatures(antivirus_t *av, const char *filename);
ngfw_ret_t antivirus_save_signatures(antivirus_t *av, const char *filename);

ngfw_ret_t antivirus_scan_buffer(antivirus_t *av, const u8 *buffer, u32 len, av_scan_result_t *result, av_alert_t *alert);
ngfw_ret_t antivirus_scan_packet(antivirus_t *av, packet_t *pkt, av_scan_result_t *result, av_alert_t *alert);

av_stats_t *antivirus_get_stats(antivirus_t *av);
void antivirus_reset_stats(antivirus_t *av);
void antivirus_reset_alerts(antivirus_t *av);

ngfw_ret_t antivirus_get_alerts(antivirus_t *av, av_alert_t **alerts, u32 *count);

#endif
