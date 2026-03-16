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

#include "ngfw/engine.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

struct ngfw_engine {
    ngfw_engine_config_t config;
    ngfw_state_t state;

    session_table_t *sessions;
    filter_t *filter;
    ips_t *ips;
    vpn_t *vpn;
    urlfilter_t *urlfilter;
    qos_t *qos;
    nat_t *nat;
    antivirus_t *antivirus;
    ddos_t *ddos;
    snmp_t *snmp;
    prometheus_t *prometheus;
    netfilter_t *netfilter;
    hwaccel_t *hwaccel;
    nf_handle_t *nf;
    thread_pool_t *pool;
    logger_t *logger;

    ngfw_stats_t stats;
    u64 last_stats_update;

    bool initialized;
};

static ngfw_engine_t *global_engine = NULL;

static void signal_handler(int sig)
{
    if (global_engine) {
        log_info("Received signal %d, initiating shutdown", sig);
        global_engine->state = NGFW_STATE_STOPPING;
    }
}

static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        exit(1);
    }
    if (pid > 0) {
        exit(0);
    }

    setsid();

    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) {
        exit(1);
    }
    if (pid > 0) {
        exit(0);
    }

    umask(0);

    { int r = chdir("/"); (void)r; }

    for (int i = 0; i < 1024; i++) {
        close(i);
    }

    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_RDWR);
}

static void write_pid_file(const char *pid_file)
{
    FILE *fp = fopen(pid_file, "w");
    if (fp) {
        fprintf(fp, "%d\n", getpid());
        fclose(fp);
    }
}

ngfw_engine_t *ngfw_engine_create(void)
{
    ngfw_engine_t *engine = ngfw_malloc(sizeof(ngfw_engine_t));
    if (!engine) return NULL;

    memset(engine, 0, sizeof(ngfw_engine_t));
    engine->state = NGFW_STATE_INIT;

    strcpy(engine->config.pid_file, "/var/run/ngfw.pid");
    strcpy(engine->config.config_file, "/etc/ngfw/ngfw.conf");
    strcpy(engine->config.log_file, "/var/log/ngfw.log");
    strcpy(engine->config.ips_db, "/etc/ngfw/ips_signatures.db");
    strcpy(engine->config.url_db, "/etc/ngfw/url_categories.db");
    engine->config.daemon_mode = false;
    engine->config.debug = false;
    engine->config.worker_threads = 4;
    engine->config.packet_queue_size = 4096;
    engine->config.enable_nat = true;
    engine->config.enable_antivirus = false;
    engine->config.enable_ddos = true;
    engine->config.enable_snmp = true;
    engine->config.enable_prometheus = true;

    global_engine = engine;

    return engine;
}

void ngfw_engine_destroy(ngfw_engine_t *engine)
{
    if (!engine) return;

    if (engine->initialized) {
        ngfw_engine_stop(engine);
    }

    if (engine->sessions) session_table_destroy(engine->sessions);
    if (engine->filter) filter_destroy(engine->filter);
    if (engine->ips) ips_destroy(engine->ips);
    if (engine->vpn) vpn_destroy(engine->vpn);
    if (engine->urlfilter) urlfilter_destroy(engine->urlfilter);
    if (engine->qos) qos_destroy(engine->qos);
    if (engine->nat) nat_destroy(engine->nat);
    if (engine->antivirus) antivirus_destroy(engine->antivirus);
    if (engine->ddos) ddos_destroy(engine->ddos);
    if (engine->snmp) snmp_destroy(engine->snmp);
    if (engine->prometheus) prometheus_destroy(engine->prometheus);
    if (engine->nf) nf_destroy(engine->nf);
    if (engine->pool) thread_pool_destroy(engine->pool);
    if (engine->logger) logger_destroy(engine->logger);

    ngfw_free(engine);
    global_engine = NULL;
}

ngfw_ret_t ngfw_engine_init(ngfw_engine_t *engine, const ngfw_engine_config_t *config)
{
    if (!engine) return NGFW_ERR_INVALID;

    if (config) {
        memcpy(&engine->config, config, sizeof(ngfw_engine_config_t));
    }

    if (engine->config.daemon_mode) {
        daemonize();
    }

    write_pid_file(engine->config.pid_file);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    logger_config_t logger_config = {
        .target = LOG_TARGET_FILE,
        .level = engine->config.debug ? LOG_DEBUG : LOG_INFO,
        .timestamp = true,
        .max_size = 10 * 1024 * 1024,
        .max_files = 5
    };
    strcpy(logger_config.filename, engine->config.log_file);

    engine->logger = logger_create(&logger_config);
    if (!engine->logger) {
        return NGFW_ERR_NO_MEM;
    }
    logger_init(engine->logger);

    log_info("NGFW Engine initializing...");
    log_info("  Version: 1.0.0");
    log_info("  Worker threads: %u", engine->config.worker_threads);

    engine->sessions = session_table_create(100000);
    if (!engine->sessions) {
        log_err("Failed to create session table");
        return NGFW_ERR_NO_MEM;
    }
    log_info("Session table created (max: 100000)");

    engine->filter = filter_create();
    if (!engine->filter) {
        log_err("Failed to create filter");
        return NGFW_ERR_NO_MEM;
    }
    log_info("Filter created");

    engine->ips = ips_create();
    if (!engine->ips) {
        log_err("Failed to create IPS");
        return NGFW_ERR_NO_MEM;
    }
    ips_init(engine->ips);
    if (engine->config.ips_db[0]) {
        ips_load_signatures(engine->ips, engine->config.ips_db);
    }
    ips_start(engine->ips);
    log_info("IPS initialized");

    engine->vpn = vpn_create(VPN_TYPE_IPSEC);
    if (!engine->vpn) {
        log_err("Failed to create VPN");
        return NGFW_ERR_NO_MEM;
    }
    vpn_init(engine->vpn);
    log_info("VPN initialized");

    engine->urlfilter = urlfilter_create();
    if (!engine->urlfilter) {
        log_err("Failed to create URL filter");
        return NGFW_ERR_NO_MEM;
    }
    urlfilter_init(engine->urlfilter);
    if (engine->config.url_db[0]) {
        urlfilter_load_db(engine->urlfilter, engine->config.url_db);
    }
    log_info("URL filter initialized");

    engine->qos = qos_create();
    if (!engine->qos) {
        log_err("Failed to create QoS");
        return NGFW_ERR_NO_MEM;
    }
    qos_init(engine->qos, QOS_SCHEDULER_HTB);
    log_info("QoS initialized");

    if (engine->config.enable_nat) {
        engine->nat = nat_create();
        if (!engine->nat) {
            log_warn("Failed to create NAT, continuing without NAT");
        } else {
            nat_init(engine->nat);
            nat_start(engine->nat);
            log_info("NAT initialized");
        }
    }

    if (engine->config.enable_antivirus) {
        engine->antivirus = antivirus_create();
        if (!engine->antivirus) {
            log_warn("Failed to create Anti-Virus, continuing without AV");
        } else {
            antivirus_init(engine->antivirus);
            antivirus_start(engine->antivirus);
            log_info("Anti-Virus initialized");
        }
    }

    if (engine->config.enable_ddos) {
        engine->ddos = ddos_create();
        if (!engine->ddos) {
            log_warn("Failed to create DDoS mitigation");
        } else {
            ddos_init(engine->ddos);
            ddos_start(engine->ddos);
            log_info("DDoS mitigation initialized");
        }
    }

    if (engine->config.enable_snmp) {
        engine->snmp = snmp_create();
        if (!engine->snmp) {
            log_warn("Failed to create SNMP");
        } else {
            snmp_init(engine->snmp);
            snmp_start(engine->snmp);
            log_info("SNMP initialized");
        }
    }

    if (engine->config.enable_prometheus) {
        engine->prometheus = prometheus_create();
        if (!engine->prometheus) {
            log_warn("Failed to create Prometheus");
        } else {
            prometheus_init(engine->prometheus);
            prometheus_set_web_context(engine->prometheus, engine);
            prometheus_start(engine->prometheus);
            log_info("Prometheus initialized");
        }
    }

    engine->nf = nf_create(NF_FAMILY_INET);
    if (!engine->nf) {
        log_warn("Failed to create netfilter, continuing without kernel integration");
    } else {
        nf_init_tables(engine->nf);
        log_info("Netfilter initialized");
    }

    if (engine->config.enable_netfilter) {
        engine->netfilter = netfilter_create();
        if (!engine->netfilter) {
            log_warn("Failed to create netfilter rules engine");
        } else {
            netfilter_init(engine->netfilter);
            log_info("Netfilter rules engine initialized");
        }
    }

    if (engine->config.enable_hwaccel) {
        engine->hwaccel = hwaccel_create();
        if (!engine->hwaccel) {
            log_warn("Failed to create hardware acceleration");
        } else {
            hwaccel_init(engine->hwaccel);
            log_info("Hardware acceleration initialized");
        }
    }

    engine->pool = thread_pool_create(engine->config.worker_threads);
    if (!engine->pool) {
        log_err("Failed to create thread pool");
        return NGFW_ERR_NO_MEM;
    }
    thread_pool_init(engine->pool);
    log_info("Thread pool created (%u threads)", engine->config.worker_threads);

    engine->stats.start_time = get_ms_time();
    engine->initialized = true;
    engine->state = NGFW_STATE_RUNNING;

    log_info("NGFW Engine initialized successfully");
    log_info("========================================");
    log_info("  Sessions:     %s", engine->sessions ? "OK" : "FAIL");
    log_info("  Filter:      %s", engine->filter ? "OK" : "FAIL");
    log_info("  IPS:         %s", engine->ips ? "OK" : "FAIL");
    log_info("  VPN:         %s", engine->vpn ? "OK" : "FAIL");
    log_info("  URL Filter:  %s", engine->urlfilter ? "OK" : "FAIL");
    log_info("  QoS:         %s", engine->qos ? "OK" : "FAIL");
    log_info("  NAT:         %s", engine->nat ? "OK" : "DISABLED");
    log_info("  Anti-Virus:  %s", engine->antivirus ? "OK" : "DISABLED");
    log_info("  DDoS:        %s", engine->ddos ? "OK" : "DISABLED");
    log_info("  SNMP:        %s", engine->snmp ? "OK" : "DISABLED");
    log_info("  Prometheus:  %s", engine->prometheus ? "OK" : "DISABLED");
    log_info("========================================");

    return NGFW_OK;
}

ngfw_ret_t ngfw_engine_start(ngfw_engine_t *engine)
{
    if (!engine) return NGFW_ERR_INVALID;
    if (!engine->initialized) return NGFW_ERR_INVALID;

    log_info("NGFW Engine starting...");

    engine->state = NGFW_STATE_RUNNING;

    log_info("NGFW Engine started successfully");

    return NGFW_OK;
}

ngfw_ret_t ngfw_engine_stop(ngfw_engine_t *engine)
{
    if (!engine) return NGFW_ERR_INVALID;

    log_info("NGFW Engine stopping...");

    engine->state = NGFW_STATE_STOPPING;

    if (engine->pool) {
        thread_pool_shutdown(engine->pool);
    }

    if (engine->nat && engine->config.enable_nat) {
        nat_stop(engine->nat);
    }

    if (engine->ddos && engine->config.enable_ddos) {
        ddos_stop(engine->ddos);
    }

    if (engine->snmp && engine->config.enable_snmp) {
        snmp_stop(engine->snmp);
    }

    if (engine->prometheus && engine->config.enable_prometheus) {
        prometheus_stop(engine->prometheus);
    }

    if (engine->sessions) {
        session_table_destroy(engine->sessions);
        engine->sessions = NULL;
    }

    if (engine->config.pid_file[0]) {
        unlink(engine->config.pid_file);
    }

    engine->state = NGFW_STATE_STOPPED;

    log_info("NGFW Engine stopped");

    return NGFW_OK;
}

ngfw_ret_t ngfw_engine_reload(ngfw_engine_t *engine)
{
    if (!engine) return NGFW_ERR_INVALID;

    log_info("NGFW Engine reloading configuration...");

    if (engine->ips && engine->config.ips_db[0]) {
        ips_load_signatures(engine->ips, engine->config.ips_db);
    }

    if (engine->urlfilter && engine->config.url_db[0]) {
        urlfilter_load_db(engine->urlfilter, engine->config.url_db);
    }

    log_info("NGFW Engine configuration reloaded");

    return NGFW_OK;
}

ngfw_state_t ngfw_engine_get_state(ngfw_engine_t *engine)
{
    return engine ? engine->state : NGFW_STATE_INIT;
}

ngfw_stats_t *ngfw_engine_get_stats(ngfw_engine_t *engine)
{
    if (!engine) return NULL;

    engine->stats.uptime = get_ms_time() - engine->stats.start_time;
    if (engine->sessions) {
        engine->stats.sessions_active = session_table_count(engine->sessions);
    }
    if (engine->ips) {
        ips_stats_t *ips_stats = ips_get_stats(engine->ips);
        if (ips_stats) {
            engine->stats.ips_threats_blocked = ips_stats->alerts_high + ips_stats->alerts_critical;
        }
    }
    if (engine->nat) {
        nat_stats_t *nat_stats = nat_get_stats(engine->nat);
        if (nat_stats) {
            engine->stats.nat_translations = nat_stats->translations_active;
        }
    }
    if (engine->ddos) {
        ddos_stats_t *ddos_stats = ddos_get_stats(engine->ddos);
        if (ddos_stats) {
            engine->stats.ddos_blocked = ddos_stats->blocked_ips;
        }
    }

    return &engine->stats;
}

session_table_t *ngfw_engine_get_sessions(ngfw_engine_t *engine)
{
    return engine ? engine->sessions : NULL;
}

filter_t *ngfw_engine_get_filter(ngfw_engine_t *engine)
{
    return engine ? engine->filter : NULL;
}

ips_t *ngfw_engine_get_ips(ngfw_engine_t *engine)
{
    return engine ? engine->ips : NULL;
}

vpn_t *ngfw_engine_get_vpn(ngfw_engine_t *engine)
{
    return engine ? engine->vpn : NULL;
}

urlfilter_t *ngfw_engine_get_urlfilter(ngfw_engine_t *engine)
{
    return engine ? engine->urlfilter : NULL;
}

qos_t *ngfw_engine_get_qos(ngfw_engine_t *engine)
{
    return engine ? engine->qos : NULL;
}

nat_t *ngfw_engine_get_nat(ngfw_engine_t *engine)
{
    return engine ? engine->nat : NULL;
}

antivirus_t *ngfw_engine_get_antivirus(ngfw_engine_t *engine)
{
    return engine ? engine->antivirus : NULL;
}

ddos_t *ngfw_engine_get_ddos(ngfw_engine_t *engine)
{
    return engine ? engine->ddos : NULL;
}

snmp_t *ngfw_engine_get_snmp(ngfw_engine_t *engine)
{
    return engine ? engine->snmp : NULL;
}

prometheus_t *ngfw_engine_get_prometheus(ngfw_engine_t *engine)
{
    return engine ? engine->prometheus : NULL;
}

netfilter_t *ngfw_engine_get_netfilter(ngfw_engine_t *engine)
{
    return engine ? engine->netfilter : NULL;
}

hwaccel_t *ngfw_engine_get_hwaccel(ngfw_engine_t *engine)
{
    return engine ? engine->hwaccel : NULL;
}

ngfw_ret_t ngfw_engine_register_handler(ngfw_engine_t *engine, ngfw_packet_handler_t handler)
{
    (void)engine;
    (void)handler;
    return NGFW_ERR;
}

ngfw_ret_t ngfw_engine_process_packet(ngfw_engine_t *engine, packet_t *pkt)
{
    if (!engine || !pkt) return NGFW_ERR_INVALID;

    engine->stats.packets_processed++;
    engine->stats.bytes_processed += pkt->len;

    if (engine->ddos) {
        bool should_drop = false;
        ddos_check_packet(engine->ddos, pkt, &should_drop);
        if (should_drop) {
            engine->stats.packets_dropped++;
            engine->stats.ddos_blocked++;
            return NGFW_OK;
        }
    }

    session_key_t key = {
        .src_ip = 0,
        .dst_ip = 0,
        .src_port = 0,
        .dst_port = 0,
        .protocol = 0
    };

    ip_header_t *ip = packet_get_ip(pkt);
    if (ip) {
        key.src_ip = ip->src;
        key.dst_ip = ip->dst;
        key.protocol = ip->protocol;

        tcp_header_t *tcp = packet_get_tcp(pkt);
        if (tcp) {
            key.src_port = tcp->src_port;
            key.dst_port = tcp->dst_port;
        }

        udp_header_t *udp = packet_get_udp(pkt);
        if (udp) {
            key.src_port = udp->src_port;
            key.dst_port = udp->dst_port;
        }
    }

    session_t *session = session_table_lookup(engine->sessions, &key);
    if (!session) {
        session = session_create(&key);
        if (session) {
            session_table_insert(engine->sessions, session);
            engine->stats.sessions_created++;
        }
    }

    if (session) {
        session_update(session, pkt);
    }

    filter_action_t filter_result = filter_process_packet(engine->filter, pkt, session);

    if (filter_result == FILTER_ACTION_DROP) {
        engine->stats.packets_dropped++;
        return NGFW_OK;
    }

    if (engine->ips) {
        ips_alert_t alert;
        ngfw_ret_t ret = ips_check_packet(engine->ips, pkt, &alert);
        if (ret == NGFW_OK) {
            engine->stats.ips_threats_blocked++;
            engine->stats.packets_dropped++;
            log_warn("IPS blocked packet: %s", alert.signature_name);

            if (engine->snmp) {
                snmp_send_trap(engine->snmp, "1.3.6.1.4.1.NGFW.1.0.1", alert.signature_name);
            }

            return NGFW_OK;
        }
    }

    if (engine->nat) {
        nat_entry_t entry;
        ngfw_ret_t ret = nat_translate_packet(engine->nat, pkt, &entry);
        if (ret == NGFW_OK) {
            engine->stats.nat_translations++;
        }
    }

    if (engine->antivirus && pkt->len > 0) {
        av_scan_result_t av_result;
        ngfw_ret_t ret = antivirus_scan_packet(engine->antivirus, pkt, &av_result, NULL);
        if (ret == NGFW_OK && av_result == AV_SCAN_RESULT_INFECTED) {
            engine->stats.antivirus_blocked++;
            engine->stats.packets_dropped++;
            log_warn("Anti-Virus blocked packet");
            return NGFW_OK;
        }
    }

    engine->stats.packets_forwarded++;

    return NGFW_OK;
}
