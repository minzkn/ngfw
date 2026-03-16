#ifndef NGFW_IPC_H
#define NGFW_IPC_H

#include "types.h"

#define NGFW_NETLINK_FAMILY 31
#define NGFW_IPC_MAX_PAYLOAD 1024

typedef enum {
    NGFW_IPC_CMD_GET_STATS,
    NGFW_IPC_CMD_ADD_RULE,
    NGFW_IPC_CMD_DEL_RULE,
    NGFW_IPC_CMD_FLUSH,
    NGFW_IPC_CMD_GET_RULES,
    NGFW_IPC_CMD_SET_CONFIG,
    NGFW_IPC_CMD_GET_CONFIG,
    NGFW_IPC_CMD_ENABLE,
    NGFW_IPC_CMD_DISABLE,
    NGFW_IPC_CMD_MAX
} ngfw_ipc_cmd_t;

typedef enum {
    NGFW_IPC_TYPE_REQUEST,
    NGFW_IPC_TYPE_RESPONSE,
    NGFW_IPC_TYPE_EVENT,
    NGFW_IPC_TYPE_MAX
} ngfw_ipc_type_t;

typedef struct ngfw_ipc_msg {
    u32 cmd;
    u32 type;
    u32 seq;
    u32 pid;
    u8 data[NGFW_IPC_MAX_PAYLOAD];
    u32 data_len;
} ngfw_ipc_msg_t;

typedef struct ngfw_ipc_stats {
    u64 packets_total;
    u64 packets_accepted;
    u64 packets_dropped;
    u64 bytes_total;
    u64 sessions_active;
    u64 ips_alerts;
} ngfw_ipc_stats_t;

typedef struct ngfw_ipc ngfw_ipc_t;

typedef void (*ngfw_ipc_callback_t)(ngfw_ipc_msg_t *msg, void *context);

ngfw_ipc_t *ngfw_ipc_create(void);
void ngfw_ipc_destroy(ngfw_ipc_t *ipc);

ngfw_ret_t ngfw_ipc_init(ngfw_ipc_t *ipc);
ngfw_ret_t ngfw_ipc_shutdown(ngfw_ipc_t *ipc);

ngfw_ret_t ngfw_ipc_send(ngfw_ipc_t *ipc, ngfw_ipc_msg_t *msg);
ngfw_ret_t ngfw_ipc_recv(ngfw_ipc_t *ipc, ngfw_ipc_msg_t *msg);

ngfw_ret_t ngfw_ipc_register_handler(ngfw_ipc_t *ipc, u32 cmd, ngfw_ipc_callback_t callback, void *context);

ngfw_ret_t ngfw_ipc_get_stats(ngfw_ipc_t *ipc, ngfw_ipc_stats_t *stats);
ngfw_ret_t ngfw_ipc_send_stats(ngfw_ipc_t *ipc, ngfw_ipc_stats_t *stats);

ngfw_ret_t ngfw_ipc_add_rule(ngfw_ipc_t *ipc, const void *rule_data, u32 len);
ngfw_ret_t ngfw_ipc_del_rule(ngfw_ipc_t *ipc, u32 rule_id);
ngfw_ret_t ngfw_ipc_flush(ngfw_ipc_t *ipc);

bool ngfw_ipc_is_connected(ngfw_ipc_t *ipc);

#endif
