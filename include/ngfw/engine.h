#ifndef NGFW_ENGINE_H
#define NGFW_ENGINE_H

#include "types.h"
#include "config.h"
#include "session.h"
#include "filter.h"
#include "ips.h"
#include "nf.h"
#include "vpn.h"
#include "urlfilter.h"
#include "qos.h"
#include "nat.h"
#include "antivirus.h"
#include "ddos.h"
#include "threadpool.h"
#include "logger.h"
#include "snmp.h"
#include "prometheus.h"
#include "netfilter.h"
#include "hwaccel.h"
#include "dpdk.h"

typedef enum {
    NGFW_STATE_INIT,
    NGFW_STATE_STARTING,
    NGFW_STATE_RUNNING,
    NGFW_STATE_STOPPING,
    NGFW_STATE_STOPPED,
    NGFW_STATE_ERROR
} ngfw_state_t;

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
    bool enable_netfilter;
    bool enable_hwaccel;
    bool enable_dpdk;
    char dpdk_args[512];
} ngfw_engine_config_t;

typedef struct ngfw_stats {
    u64 packets_processed;
    u64 packets_dropped;
    u64 packets_forwarded;
    u64 bytes_processed;
    u64 sessions_active;
    u64 sessions_created;
    u64 sessions_expired;
    u64 ips_threats_detected;
    u64 ips_threats_blocked;
    u64 filter_rules_match;
    u64 nat_translations;
    u64 ddos_blocked;
    u64 antivirus_blocked;
    u64 errors;
    u64 start_time;
    u64 uptime;
} ngfw_stats_t;

typedef struct ngfw_engine ngfw_engine_t;

ngfw_engine_t *ngfw_engine_create(void);
void ngfw_engine_destroy(ngfw_engine_t *engine);

ngfw_ret_t ngfw_engine_init(ngfw_engine_t *engine, const ngfw_engine_config_t *config);
ngfw_ret_t ngfw_engine_start(ngfw_engine_t *engine);
ngfw_ret_t ngfw_engine_stop(ngfw_engine_t *engine);
ngfw_ret_t ngfw_engine_reload(ngfw_engine_t *engine);

ngfw_state_t ngfw_engine_get_state(ngfw_engine_t *engine);
ngfw_stats_t *ngfw_engine_get_stats(ngfw_engine_t *engine);

session_table_t *ngfw_engine_get_sessions(ngfw_engine_t *engine);
filter_t *ngfw_engine_get_filter(ngfw_engine_t *engine);
ips_t *ngfw_engine_get_ips(ngfw_engine_t *engine);
vpn_t *ngfw_engine_get_vpn(ngfw_engine_t *engine);
urlfilter_t *ngfw_engine_get_urlfilter(ngfw_engine_t *engine);
qos_t *ngfw_engine_get_qos(ngfw_engine_t *engine);
nat_t *ngfw_engine_get_nat(ngfw_engine_t *engine);
antivirus_t *ngfw_engine_get_antivirus(ngfw_engine_t *engine);
ddos_t *ngfw_engine_get_ddos(ngfw_engine_t *engine);
snmp_t *ngfw_engine_get_snmp(ngfw_engine_t *engine);
prometheus_t *ngfw_engine_get_prometheus(ngfw_engine_t *engine);
netfilter_t *ngfw_engine_get_netfilter(ngfw_engine_t *engine);
hwaccel_t *ngfw_engine_get_hwaccel(ngfw_engine_t *engine);

typedef struct ngfw_packet_context {
    packet_t *pkt;
    session_t *session;
    u32 in_interface;
    u32 out_interface;
    u8 direction;
    ngfw_ret_t filter_result;
    ngfw_ret_t ips_result;
    bool dropped;
    bool forwarded;
} ngfw_packet_context_t;

typedef ngfw_ret_t (*ngfw_packet_handler_t)(ngfw_engine_t *engine, ngfw_packet_context_t *ctx);

ngfw_ret_t ngfw_engine_register_handler(ngfw_engine_t *engine, ngfw_packet_handler_t handler);

ngfw_ret_t ngfw_engine_process_packet(ngfw_engine_t *engine, packet_t *pkt);

#endif
