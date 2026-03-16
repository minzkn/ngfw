#ifndef NGFW_SNMP_H
#define NGFW_SNMP_H

#include "types.h"

typedef enum {
    SNMP_VERSION_1,
    SNMP_VERSION_2C,
    SNMP_VERSION_3
} snmp_version_t;

typedef enum {
    SNMP_RETRIEVE_OK,
    SNMP_RETRIEVE_ERROR,
    SNMP_RETRIEVE_TIMEOUT,
    SNMP_RETRIEVE_NOSUCHOBJECT,
    SNMP_RETRIEVE_NOSUCHINSTANCE,
    SNMP_RETRIEVE_ENDOFMIBVIEW
} snmp_retrieve_status_t;

typedef struct snmp_oid {
    u8 oid[32];
    u8 oid_len;
} snmp_oid_t;

typedef struct snmp_value {
    snmp_oid_t oid;
    u8 type;
    union {
        s32 integer;
        u32 unsigned_int;
        char str[256];
        u8 bytes[256];
    } value;
    u32 value_len;
} snmp_value_t;

typedef struct snmp_stats {
    u64 requests_received;
    u64 requests_processed;
    u64 requests_failed;
    u64 traps_sent;
    u64 inform_sent;
    u64 inform_acknowledged;
    u64 bytes_sent;
    u64 bytes_received;
} snmp_stats_t;

typedef struct snmp snmp_t;

snmp_t *snmp_create(void);
void snmp_destroy(snmp_t *snmp);

ngfw_ret_t snmp_init(snmp_t *snmp);
ngfw_ret_t snmp_start(snmp_t *snmp);
ngfw_ret_t snmp_stop(snmp_t *snmp);

ngfw_ret_t snmp_set_community(snmp_t *snmp, const char *community);
ngfw_ret_t snmp_set_port(snmp_t *snmp, u16 port);
ngfw_ret_t snmp_set_version(snmp_t *snmp, snmp_version_t version);

ngfw_ret_t snmp_register_oid(snmp_t *snmp, const char *oid_str, const char *name,
                             u8 type, void (*callback)(snmp_value_t *value));

ngfw_ret_t snmp_send_trap(snmp_t *snmp, const char *oid, const char *value);
ngfw_ret_t snmp_send_inform(snmp_t *snmp, const char *oid, const char *value);

snmp_stats_t *snmp_get_stats(snmp_t *snmp);

#endif
