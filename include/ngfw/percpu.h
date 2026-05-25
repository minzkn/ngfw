#ifndef NGFW_PERCPU_H
#define NGFW_PERCPU_H

#include "ngfw/types.h"
#include "ngfw/network/packet.h"
#include <pthread.h>

/* Forward declarations - actual typedefs are in session.h which includes this file */
struct session;
struct session_key;
struct session_table;

#define NGFW_MAX_CPUS 64

/* Per-CPU session table partition */
typedef struct percpu_session {
    struct session_table *table;
    u32 cpu_id;
    u64 lookups;
    u64 inserts;
    u64 removes;
    u64 collisions;
    u8 pad[56];  /* Cache line alignment */
} __attribute__((aligned(64))) percpu_session_t;

/* Per-CPU session manager */
typedef struct percpu_session_mgr {
    percpu_session_t cpus[NGFW_MAX_CPUS];
    u32 num_cpus;
    u32 max_sessions_per_cpu;
    bool initialized;
    pthread_mutex_t lock;
} percpu_session_mgr_t;

/* Create per-CPU session manager */
percpu_session_mgr_t *percpu_session_create(u32 max_sessions_per_cpu);

/* Destroy per-CPU session manager */
void percpu_session_destroy(percpu_session_mgr_t *mgr);

/* Get current CPU ID */
u32 percpu_get_cpu_id(void);

/* Get CPU ID for a session key (consistent hashing) */
u32 percpu_get_cpu_id_for_key(percpu_session_mgr_t *mgr, const struct session_key *key);

/* Lookup session in current CPU's table */
struct session *percpu_session_lookup(percpu_session_mgr_t *mgr, const struct session_key *key);

/* Insert session into current CPU's table */
ngfw_ret_t percpu_session_insert(percpu_session_mgr_t *mgr, struct session *session);

/* Remove session from current CPU's table */
void percpu_session_remove(percpu_session_mgr_t *mgr, struct session *session);

/* Get total session count across all CPUs */
u32 percpu_session_count(percpu_session_mgr_t *mgr);

/* Cleanup expired sessions on current CPU */
void percpu_session_cleanup(percpu_session_mgr_t *mgr);

/* Get per-CPU stats */
void percpu_session_get_stats(percpu_session_mgr_t *mgr, u64 *total_lookups, u64 *total_inserts, u64 *total_removes);

/* Generic per-CPU utilities */
u32 cpu_get_id(void);
u32 cpu_get_num_cores(void);

#endif
