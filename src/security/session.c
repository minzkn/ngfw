#include "ngfw/session.h"
#include "ngfw/hash.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include <string.h>
#include <stddef.h>

#define SESSION_TIMEOUT_DEFAULT 300000

session_t *session_create(const session_key_t *key)
{
    session_t *session = ngfw_malloc(sizeof(session_t));
    if (!session) return NULL;
    
    memcpy(&session->key, key, sizeof(session_key_t));
    session->state = SESSION_STATE_NEW;
    session->created = get_ms_time();
    session->last_access = session->created;
    session->timeout = SESSION_TIMEOUT_DEFAULT;
    session->packets_in = 0;
    session->packets_out = 0;
    session->bytes_in = 0;
    session->bytes_out = 0;
    session->ifindex_in = 0;
    session->ifindex_out = 0;
    session->data = NULL;
    
    return session;
}

void session_destroy(session_t *session)
{
    if (session) {
        ngfw_free(session);
    }
}

void session_update(session_t *session, packet_t *pkt)
{
    if (!session || !pkt) return;
    
    session->last_access = get_ms_time();
    
    if (pkt->direction == PKT_DIR_IN) {
        session->packets_in++;
        session->bytes_in += pkt->len;
    } else {
        session->packets_out++;
        session->bytes_out += pkt->len;
    }
    
    if (session->state == SESSION_STATE_NEW) {
        session->state = SESSION_STATE_ESTABLISHED;
    }
}

bool session_expired(session_t *session, u64 now)
{
    if (!session) return true;
    return (now - session->last_access) > session->timeout;
}

u32 session_key_hash(const void *key, u32 size)
{
    const session_key_t *k = (const session_key_t *)key;
    u32 hash = k->src_ip;
    hash ^= k->dst_ip + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    hash ^= k->src_port + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    hash ^= k->dst_port + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    hash ^= k->protocol + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    (void)size;
    return hash;
}

bool session_key_equal(const void *a, const void *b)
{
    const session_key_t *x = (const session_key_t *)a;
    const session_key_t *y = (const session_key_t *)b;
    return (x->src_ip == y->src_ip &&
            x->dst_ip == y->dst_ip &&
            x->src_port == y->src_port &&
            x->dst_port == y->dst_port &&
            x->protocol == y->protocol);
}

static u32 hash_session_key_wrapper(const void *key, u32 size)
{
    return session_key_hash(key, size);
}

static bool equal_session_key(const void *a, const void *b)
{
    return session_key_equal(a, b);
}

static void destroy_session(void *key, void *value)
{
    (void)key;
    session_destroy((session_t *)value);
}

session_table_t *session_table_create(u32 max_sessions)
{
    session_table_t *table = ngfw_malloc(sizeof(session_table_t));
    if (!table) return NULL;
    
    table->hash = hash_create(max_sessions, hash_session_key_wrapper, equal_session_key, destroy_session);
    if (!table->hash) {
        ngfw_free(table);
        return NULL;
    }
    
    table->max_sessions = max_sessions;
    table->cleanup_time = get_ms_time();
    
    return table;
}

void session_table_destroy(session_table_t *table)
{
    if (!table) return;
    hash_destroy(table->hash);
    ngfw_free(table);
}

session_t *session_table_lookup(session_table_t *table, const session_key_t *key)
{
    if (!table || !key) return NULL;
    return (session_t *)hash_lookup(table->hash, key);
}

ngfw_ret_t session_table_insert(session_table_t *table, session_t *session)
{
    if (!table || !session) return NGFW_ERR_INVALID;
    
    if (hash_size(table->hash) >= table->max_sessions) {
        session_table_cleanup(table, get_ms_time());
        
        if (hash_size(table->hash) >= table->max_sessions) {
            log_warn("Session table full");
            return NGFW_ERR_NO_RESOURCE;
        }
    }
    
    return hash_insert(table->hash, &session->key, session);
}

void session_table_remove(session_table_t *table, session_t *session)
{
    if (!table || !session) return;
    hash_remove(table->hash, &session->key);
}

u32 session_table_count(session_table_t *table)
{
    return table ? hash_size(table->hash) : 0;
}

void session_table_cleanup(session_table_t *table, u64 now)
{
    if (!table) return;
    
    u64 cleanup_interval = 60000;
    if (now - table->cleanup_time < cleanup_interval) return;
    
    table->cleanup_time = now;
}
