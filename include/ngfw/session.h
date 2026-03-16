#ifndef NGFW_SESSION_H
#define NGFW_SESSION_H

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

#include "types.h"
#include "packet.h"
#include "hash.h"

typedef enum {
    SESSION_STATE_NEW,
    SESSION_STATE_ESTABLISHED,
    SESSION_STATE_CLOSING,
    SESSION_STATE_CLOSED
} session_state_t;

typedef struct session_key {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
} session_key_t;

typedef struct session {
    session_key_t key;
    session_state_t state;
    u64 created;
    u64 last_access;
    u64 timeout;
    u32 packets_in;
    u32 packets_out;
    u64 bytes_in;
    u64 bytes_out;
    u32 ifindex_in;
    u32 ifindex_out;
    void *data;
} session_t;

typedef struct session_table {
    hash_table_t *hash;
    u32 max_sessions;
    u64 cleanup_time;
} session_table_t;

session_table_t *session_table_create(u32 max_sessions);
void session_table_destroy(session_table_t *table);
session_t *session_table_lookup(session_table_t *table, const session_key_t *key);
ngfw_ret_t session_table_insert(session_table_t *table, session_t *session);
void session_table_remove(session_table_t *table, session_t *session);
u32 session_table_count(session_table_t *table);
void session_table_cleanup(session_table_t *table, u64 now);

session_t *session_create(const session_key_t *key);
void session_destroy(session_t *session);
void session_update(session_t *session, packet_t *pkt);
bool session_expired(session_t *session, u64 now);

u32 session_key_hash(const void *key, u32 size);
bool session_key_equal(const void *a, const void *b);

#endif
