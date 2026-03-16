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

#include "ngfw/ipc.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <errno.h>

#define NGFW_IPC_KERNEL_GRP 1

struct ngfw_ipc {
    int sock_fd;
    struct sockaddr_nl local_addr;
    struct sockaddr_nl kernel_addr;
    bool connected;
    pthread_t recv_thread;
    bool running;
    ngfw_ipc_callback_t handlers[NGFW_IPC_CMD_MAX];
    void *handler_contexts[NGFW_IPC_CMD_MAX];
    pthread_mutex_t lock;
};

static int create_netlink_socket(void)
{
    int sock = socket(AF_NETLINK, SOCK_RAW, NGFW_NETLINK_FAMILY);
    if (sock < 0) {
        log_err("Failed to create netlink socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = NGFW_IPC_KERNEL_GRP;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_err("Failed to bind netlink socket: %s", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

ngfw_ipc_t *ngfw_ipc_create(void)
{
    ngfw_ipc_t *ipc = ngfw_malloc(sizeof(ngfw_ipc_t));
    if (!ipc) return NULL;

    memset(ipc, 0, sizeof(ngfw_ipc_t));
    pthread_mutex_init(&ipc->lock, NULL);

    return ipc;
}

void ngfw_ipc_destroy(ngfw_ipc_t *ipc)
{
    if (!ipc) return;

    if (ipc->running) {
        ipc->running = false;
        pthread_join(ipc->recv_thread, NULL);
    }

    if (ipc->sock_fd >= 0) {
        close(ipc->sock_fd);
    }

    pthread_mutex_destroy(&ipc->lock);
    ngfw_free(ipc);
}

static void *recv_loop(void *arg)
{
    ngfw_ipc_t *ipc = (ngfw_ipc_t *)arg;
    char buffer[8192];
    struct iovec iov = { buffer, sizeof(buffer) };
    struct nlmsghdr *nlh;
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    log_info("IPC receive thread started");

    while (ipc->running) {
        ssize_t len = recvmsg(ipc->sock_fd, &msg, 0);
        if (len < 0) {
            if (ipc->running) {
                log_err("IPC recv error: %s", strerror(errno));
            }
            break;
        }

        for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            ngfw_ipc_msg_t ipc_msg = {0};
            ipc_msg.seq = nlh->nlmsg_seq;
            ipc_msg.pid = nlh->nlmsg_pid;
            ipc_msg.data_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(ngfw_ipc_msg_t));

            if (nlh->nlmsg_len >= sizeof(struct nlmsghdr)) {
                memcpy(&ipc_msg, NLMSG_DATA(nlh), sizeof(ngfw_ipc_msg_t));
            }

            if (ipc_msg.cmd < NGFW_IPC_CMD_MAX && ipc->handlers[ipc_msg.cmd]) {
                ipc->handlers[ipc_msg.cmd](&ipc_msg, ipc->handler_contexts[ipc_msg.cmd]);
            }
        }
    }

    log_info("IPC receive thread stopped");
    return NULL;
}

ngfw_ret_t ngfw_ipc_init(ngfw_ipc_t *ipc)
{
    if (!ipc) return NGFW_ERR_INVALID;
    if (ipc->connected) return NGFW_OK;

    ipc->sock_fd = create_netlink_socket();
    if (ipc->sock_fd < 0) {
        return NGFW_ERR;
    }

    memset(&ipc->local_addr, 0, sizeof(ipc->local_addr));
    ipc->local_addr.nl_family = AF_NETLINK;
    ipc->local_addr.nl_pid = getpid();
    ipc->local_addr.nl_groups = NGFW_IPC_KERNEL_GRP;

    memset(&ipc->kernel_addr, 0, sizeof(ipc->kernel_addr));
    ipc->kernel_addr.nl_family = AF_NETLINK;
    ipc->kernel_addr.nl_pid = 0;
    ipc->kernel_addr.nl_groups = NGFW_IPC_KERNEL_GRP;

    ipc->running = true;
    pthread_create(&ipc->recv_thread, NULL, recv_loop, ipc);

    ipc->connected = true;
    log_info("IPC initialized (netlink family: %d, pid: %d)", NGFW_NETLINK_FAMILY, getpid());

    return NGFW_OK;
}

ngfw_ret_t ngfw_ipc_shutdown(ngfw_ipc_t *ipc)
{
    if (!ipc) return NGFW_ERR_INVALID;

    ipc->running = false;

    if (ipc->sock_fd >= 0) {
        close(ipc->sock_fd);
        ipc->sock_fd = -1;
    }

    ipc->connected = false;
    log_info("IPC shutdown");

    return NGFW_OK;
}

ngfw_ret_t ngfw_ipc_send(ngfw_ipc_t *ipc, ngfw_ipc_msg_t *msg)
{
    if (!ipc || !msg || !ipc->connected) return NGFW_ERR_INVALID;

    struct nlmsghdr *nlh;
    struct iovec iov;
    struct msghdr msgh;
    char buffer[8192];

    memset(buffer, 0, sizeof(buffer));
    nlh = (struct nlmsghdr *)buffer;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(ngfw_ipc_msg_t));
    nlh->nlmsg_type = NGFW_IPC_TYPE_REQUEST;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = msg->seq ? msg->seq : 1;
    nlh->nlmsg_pid = getpid();

    memcpy(NLMSG_DATA(nlh), msg, sizeof(ngfw_ipc_msg_t));

    iov.iov_base = nlh;
    iov.iov_len = nlh->nlmsg_len;

    memset(&msgh, 0, sizeof(msgh));
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_name = &ipc->kernel_addr;
    msgh.msg_namelen = sizeof(ipc->kernel_addr);

    ssize_t ret = sendmsg(ipc->sock_fd, &msgh, 0);
    if (ret < 0) {
        log_err("Failed to send IPC message: %s", strerror(errno));
        return NGFW_ERR;
    }

    return NGFW_OK;
}

ngfw_ret_t ngfw_ipc_recv(ngfw_ipc_t *ipc, ngfw_ipc_msg_t *msg)
{
    if (!ipc || !msg) return NGFW_ERR_INVALID;
    if (!ipc->connected) return NGFW_ERR;
    
    char buffer[4096];
    struct sockaddr_nl addr;
    socklen_t addr_len = sizeof(addr);
    
    ssize_t n = recvfrom(ipc->sock_fd, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&addr, &addr_len);
    
    if (n < 0) {
        return NGFW_ERR;
    }
    
    if ((size_t)n > sizeof(ngfw_ipc_msg_t)) {
        n = (ssize_t)sizeof(ngfw_ipc_msg_t);
    }
    
    memcpy(msg, buffer, (size_t)n);
    
    return NGFW_OK;
}

ngfw_ret_t ngfw_ipc_register_handler(ngfw_ipc_t *ipc, u32 cmd, ngfw_ipc_callback_t callback, void *context)
{
    if (!ipc || cmd >= NGFW_IPC_CMD_MAX) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&ipc->lock);
    ipc->handlers[cmd] = callback;
    ipc->handler_contexts[cmd] = context;
    pthread_mutex_unlock(&ipc->lock);

    return NGFW_OK;
}

ngfw_ret_t ngfw_ipc_get_stats(ngfw_ipc_t *ipc, ngfw_ipc_stats_t *stats)
{
    if (!ipc || !stats) return NGFW_ERR_INVALID;

    ngfw_ipc_msg_t msg = {
        .cmd = NGFW_IPC_CMD_GET_STATS,
        .type = NGFW_IPC_TYPE_REQUEST,
        .seq = 1,
    };

    return ngfw_ipc_send(ipc, &msg);
}

ngfw_ret_t ngfw_ipc_send_stats(ngfw_ipc_t *ipc, ngfw_ipc_stats_t *stats)
{
    if (!ipc || !stats) return NGFW_ERR_INVALID;

    ngfw_ipc_msg_t msg = {
        .cmd = NGFW_IPC_CMD_GET_STATS,
        .type = NGFW_IPC_TYPE_RESPONSE,
        .seq = 1,
        .data_len = sizeof(ngfw_ipc_stats_t),
    };

    memcpy(msg.data, stats, sizeof(ngfw_ipc_stats_t));
    return ngfw_ipc_send(ipc, &msg);
}

ngfw_ret_t ngfw_ipc_add_rule(ngfw_ipc_t *ipc, const void *rule_data, u32 len)
{
    if (!ipc || !rule_data || len > NGFW_IPC_MAX_PAYLOAD) return NGFW_ERR_INVALID;

    ngfw_ipc_msg_t msg = {
        .cmd = NGFW_IPC_CMD_ADD_RULE,
        .type = NGFW_IPC_TYPE_REQUEST,
        .seq = 1,
        .data_len = len,
    };

    memcpy(msg.data, rule_data, len);
    return ngfw_ipc_send(ipc, &msg);
}

ngfw_ret_t ngfw_ipc_del_rule(ngfw_ipc_t *ipc, u32 rule_id)
{
    if (!ipc) return NGFW_ERR_INVALID;

    ngfw_ipc_msg_t msg = {
        .cmd = NGFW_IPC_CMD_DEL_RULE,
        .type = NGFW_IPC_TYPE_REQUEST,
        .seq = 1,
        .data_len = sizeof(u32),
    };

    memcpy(msg.data, &rule_id, sizeof(u32));
    return ngfw_ipc_send(ipc, &msg);
}

ngfw_ret_t ngfw_ipc_flush(ngfw_ipc_t *ipc)
{
    if (!ipc) return NGFW_ERR_INVALID;

    ngfw_ipc_msg_t msg = {
        .cmd = NGFW_IPC_CMD_FLUSH,
        .type = NGFW_IPC_TYPE_REQUEST,
        .seq = 1,
    };

    return ngfw_ipc_send(ipc, &msg);
}

bool ngfw_ipc_is_connected(ngfw_ipc_t *ipc)
{
    return ipc && ipc->connected;
}
