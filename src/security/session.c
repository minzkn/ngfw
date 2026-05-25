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

#include "ngfw/security/session.h"
#include "ngfw/hash.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include <string.h>
#include <stddef.h>

#define SESSION_TIMEOUT_DEFAULT 300000

/* Session table implementation */
struct session_table {
    hash_table_t *hash;
    u32 max_sessions;
    u64 cleanup_time;
};

session_t *session_create(const session_key_t *key)
{
    if (!key) return NULL;
    
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
    refcount_init(&session->refcnt, 1);  /* Initial reference */
    
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
        __sync_fetch_and_add(&session->packets_in, 1);
        __sync_fetch_and_add(&session->bytes_in, pkt->len);
    } else {
        __sync_fetch_and_add(&session->packets_out, 1);
        __sync_fetch_and_add(&session->bytes_out, pkt->len);
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
    u32 a, b, c;
    
    /* Jenkins hash for better distribution */
    a = 0x9e3779b9;  /* Golden ratio */
    b = 0x9e3779b9;
    c = 0x9e3779b9;
    
    a += k->src_ip;
    b += k->dst_ip;
    c += k->src_port;
    
    a += k->dst_port;
    b += k->protocol;
    c += size;
    
    /* Mix the bits */
    a -= b; a -= c; a ^= (c >> 13);
    b -= c; b -= a; b ^= (a << 8);
    c -= a; c -= b; c ^= (b >> 13);
    a -= b; a -= c; a ^= (c >> 12);
    b -= c; b -= a; b ^= (a << 16);
    c -= a; c -= b; c ^= (b >> 5);
    a -= b; a -= c; a ^= (c >> 3);
    b -= c; b -= a; b ^= (a << 10);
    c -= a; c -= b; c ^= (b >> 15);
    
    if (size == 0) return 0;
    return c % size;
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
    session_put((session_t *)value);  /* Release hash table's reference */
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
    
    session_t *session = (session_t *)hash_lookup(table->hash, key);
    if (session) {
        session_get(session);  /* Acquire reference */
    }
    
    return session;  /* Caller must call session_put() */
}

ngfw_ret_t session_table_insert(session_table_t *table, session_t *session)
{
    if (!table || !session) return NGFW_ERR_INVALID;
    
    u32 current_count = hash_size(table->hash);
    if (current_count >= table->max_sessions) {
        session_table_cleanup(table, get_ms_time());
        
        current_count = hash_size(table->hash);
        if (current_count >= table->max_sessions) {
            log_warn("Session table full");
            return NGFW_ERR_NO_RESOURCE;
        }
    }
    
    session_get(session);  /* Hold reference for hash table */
    ngfw_ret_t ret = hash_insert(table->hash, &session->key, session);
    
    return ret;
}

void session_table_remove(session_table_t *table, session_t *session)
{
    if (!table || !session) return;
    
    hash_remove(table->hash, &session->key);
    /* hash_remove calls destroy_session which calls session_put */
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

    /* Collect expired session keys first to avoid iterator invalidation */
    session_key_t *expired_keys = NULL;
    u32 expired_count = 0;
    u32 expired_capacity = 64;
    
    expired_keys = ngfw_malloc(sizeof(session_key_t) * expired_capacity);
    if (!expired_keys) {
        return;
    }

    void **iter = hash_iterate_start(table->hash);
    if (!iter) {
        ngfw_free(expired_keys);
        return;
    }

    while (hash_iterate_has_next(iter)) {
        session_t *session = (session_t *)hash_iterate_next(table->hash, iter);
        if (session && session_expired(session, now)) {
            if (expired_count >= expired_capacity) {
                expired_capacity *= 2;
                session_key_t *new_keys = ngfw_realloc(expired_keys, 
                                        sizeof(session_key_t) * expired_capacity);
                if (!new_keys) {
                    ngfw_free(iter);
                    ngfw_free(expired_keys);
                    return;
                }
                expired_keys = new_keys;
            }
            expired_keys[expired_count++] = session->key;
        }
    }

    ngfw_free(iter);

    /* Now remove expired sessions safely */
    for (u32 i = 0; i < expired_count; i++) {
        hash_remove(table->hash, &expired_keys[i]);
    }

    ngfw_free(expired_keys);
}
