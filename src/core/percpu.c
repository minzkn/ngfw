/*
 * NGFW - Per-CPU Session Tables
 * Multi-core scalable session management
 * Copyright (C) 2024 NGFW Project
 */

#define _GNU_SOURCE
#include "ngfw/percpu.h"
#include "ngfw/session.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include <string.h>
#include <sched.h>
#include <unistd.h>

percpu_session_mgr_t *percpu_session_create(u32 max_sessions_per_cpu)
{
    percpu_session_mgr_t *mgr = ngfw_malloc(sizeof(percpu_session_mgr_t));
    if (!mgr) return NULL;

    memset(mgr, 0, sizeof(percpu_session_mgr_t));

    /* Detect number of CPUs */
    mgr->num_cpus = (u32)sysconf(_SC_NPROCESSORS_ONLN);
    if (mgr->num_cpus == 0 || mgr->num_cpus > NGFW_MAX_CPUS) {
        mgr->num_cpus = NGFW_MAX_CPUS;
    }

    mgr->max_sessions_per_cpu = max_sessions_per_cpu;
    pthread_mutex_init(&mgr->lock, NULL);

    /* Create per-CPU session tables */
    for (u32 i = 0; i < mgr->num_cpus; i++) {
        mgr->cpus[i].cpu_id = i;
        mgr->cpus[i].table = session_table_create(max_sessions_per_cpu);
        if (!mgr->cpus[i].table) {
            log_err("Failed to create session table for CPU %u", i);
            /* Cleanup already created tables */
            for (u32 j = 0; j < i; j++) {
                if (mgr->cpus[j].table) {
                    session_table_destroy(mgr->cpus[j].table);
                }
            }
            pthread_mutex_destroy(&mgr->lock);
            ngfw_free(mgr);
            return NULL;
        }
    }

    mgr->initialized = true;

    log_info("Per-CPU session manager created: %u CPUs, %u sessions/CPU",
             mgr->num_cpus, max_sessions_per_cpu);

    return mgr;
}

void percpu_session_destroy(percpu_session_mgr_t *mgr)
{
    if (!mgr) return;

    for (u32 i = 0; i < mgr->num_cpus; i++) {
        if (mgr->cpus[i].table) {
            session_table_destroy(mgr->cpus[i].table);
        }
    }

    pthread_mutex_destroy(&mgr->lock);
    ngfw_free(mgr);

    log_info("Per-CPU session manager destroyed");
}

u32 percpu_get_cpu_id(void)
{
    /* Use CPU affinity or scheduler to get current CPU */
    cpu_set_t mask;
    if (sched_getaffinity(0, sizeof(mask), &mask) == 0) {
        for (u32 i = 0; i < NGFW_MAX_CPUS; i++) {
            if (CPU_ISSET(i, &mask)) {
                return i;
            }
        }
    }

    /* Fallback: use hash of thread ID */
    return (u32)(pthread_self() % NGFW_MAX_CPUS);
}

u32 percpu_get_cpu_id_for_key(percpu_session_mgr_t *mgr, const session_key_t *key)
{
    if (!mgr || !key) return 0;
    
    /* Jenkins hash for consistent CPU mapping */
    u32 hash = key->src_ip;
    hash ^= key->dst_ip + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    hash ^= key->src_port + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    hash ^= key->dst_port + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    hash ^= key->protocol + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    
    return hash % mgr->num_cpus;
}

session_t *percpu_session_lookup(percpu_session_mgr_t *mgr, const session_key_t *key)
{
    if (!mgr || !key) return NULL;

    u32 cpu_id = percpu_get_cpu_id_for_key(mgr, key);
    if (cpu_id >= mgr->num_cpus) {
        cpu_id = 0;
    }

    percpu_session_t *percpu = &mgr->cpus[cpu_id];
    __sync_fetch_and_add(&percpu->lookups, 1);

    session_t *session = session_table_lookup(percpu->table, key);
    
    return session;
}

ngfw_ret_t percpu_session_insert(percpu_session_mgr_t *mgr, session_t *session)
{
    if (!mgr || !session) return NGFW_ERR_INVALID;

    u32 cpu_id = percpu_get_cpu_id_for_key(mgr, &session->key);
    if (cpu_id >= mgr->num_cpus) {
        cpu_id = 0;
    }

    percpu_session_t *percpu = &mgr->cpus[cpu_id];
    ngfw_ret_t ret = session_table_insert(percpu->table, session);

    if (ret == NGFW_OK) {
        __sync_fetch_and_add(&percpu->inserts, 1);
    } else {
        __sync_fetch_and_add(&percpu->collisions, 1);
    }

    return ret;
}

void percpu_session_remove(percpu_session_mgr_t *mgr, session_t *session)
{
    if (!mgr || !session) return;

    /* Use consistent hashing to find the correct CPU */
    u32 cpu_id = percpu_get_cpu_id_for_key(mgr, &session->key);
    if (cpu_id < mgr->num_cpus) {
        session_table_remove(mgr->cpus[cpu_id].table, session);
        __sync_fetch_and_add(&mgr->cpus[cpu_id].removes, 1);
    }
}

u32 percpu_session_count(percpu_session_mgr_t *mgr)
{
    if (!mgr) return 0;

    u32 total = 0;
    for (u32 i = 0; i < mgr->num_cpus; i++) {
        total += session_table_count(mgr->cpus[i].table);
    }

    return total;
}

void percpu_session_cleanup(percpu_session_mgr_t *mgr)
{
    if (!mgr) return;

    u32 cpu_id = percpu_get_cpu_id();
    if (cpu_id >= mgr->num_cpus) {
        cpu_id = 0;
    }

    u64 now = get_ms_time();
    session_table_cleanup(mgr->cpus[cpu_id].table, now);
}

void percpu_session_get_stats(percpu_session_mgr_t *mgr, u64 *total_lookups, u64 *total_inserts, u64 *total_removes)
{
    if (!mgr) return;

    u64 lookups = 0, inserts = 0, removes = 0;

    for (u32 i = 0; i < mgr->num_cpus; i++) {
        lookups += mgr->cpus[i].lookups;
        inserts += mgr->cpus[i].inserts;
        removes += mgr->cpus[i].removes;
    }

    if (total_lookups) *total_lookups = lookups;
    if (total_inserts) *total_inserts = inserts;
    if (total_removes) *total_removes = removes;
}
