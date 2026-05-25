/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_APP_ENGINE_H
#define NGFW_APP_ENGINE_H

#include "ngfw/types.h"
#include "ngfw/security/security.h"

/*
 * NGFW Engine
 * Main packet processing engine
 */

typedef enum {
    NGFW_STATE_INIT,
    NGFW_STATE_STARTING,
    NGFW_STATE_RUNNING,
    NGFW_STATE_STOPPING,
    NGFW_STATE_STOPPED,
    NGFW_STATE_ERROR
} ngfw_state_t;

/* Engine configuration */
typedef struct ngfw_engine_config {
    char pid_file[256];
    char config_file[256];
    char log_file[256];
    bool daemon_mode;
    bool debug;
    u32 worker_threads;
    u32 packet_queue_size;
    char ips_db[256];
    char url_db[256];
    bool enable_nat;
    bool enable_antivirus;
    bool enable_ddos;
    bool enable_snmp;
    bool enable_prometheus;
} ngfw_engine_config_t;

/* Engine statistics */
typedef struct ngfw_stats {
    u64 packets_processed;
    u64 packets_dropped;
    u64 packets_forwarded;
    u64 bytes_processed;
    u64 sessions_active;
    u64 sessions_created;
    u64 ips_threats_detected;
    u64 ips_threats_blocked;
    u64 errors;
    u64 uptime;
} ngfw_stats_t;

/* Engine handle */
typedef struct ngfw_engine ngfw_engine_t;

ngfw_engine_t *ngfw_engine_create(void);
void ngfw_engine_destroy(ngfw_engine_t *engine);

ngfw_ret_t ngfw_engine_init(ngfw_engine_t *engine, const ngfw_engine_config_t *config);
ngfw_ret_t ngfw_engine_start(ngfw_engine_t *engine);
ngfw_ret_t ngfw_engine_stop(ngfw_engine_t *engine);
ngfw_ret_t ngfw_engine_reload(ngfw_engine_t *engine);

ngfw_state_t ngfw_engine_get_state(ngfw_engine_t *engine);
ngfw_stats_t *ngfw_engine_get_stats(ngfw_engine_t *engine);

/* Component accessors */
session_table_t *ngfw_engine_get_sessions(ngfw_engine_t *engine);
filter_t *ngfw_engine_get_filter(ngfw_engine_t *engine);
ips_t *ngfw_engine_get_ips(ngfw_engine_t *engine);

/* Packet processing */
ngfw_ret_t ngfw_engine_process_packet(ngfw_engine_t *engine, packet_t *pkt);

#endif
