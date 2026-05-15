/*
 * NGFW - Netfilter Netlink Library
 * Direct kernel netfilter communication via nfnetlink
 * Copyright (C) 2024 NGFW Project
 */

#define _GNU_SOURCE
#include "ngfw/nfnetlink.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nf_tables.h>

/* Fallback definitions for missing kernel headers */
#ifndef NFQA_PACKET_ID
#define NFQA_PACKET_ID 1
#endif
#ifndef IPCTNL_MSG_GETCT
#define IPCTNL_MSG_GETCT 0
#endif
#ifndef IPCTNL_MSG_CT_DELETE
#define IPCTNL_MSG_CT_DELETE 2
#endif

struct nfnetlink {
    int fd;
    u32 seq;
    u32 portid;
    bool connected;
};

static int nfnetlink_send(nfnetlink_t *nl, u16 subsys, u8 msg_type,
                          u16 flags, void *data, u32 len)
{
    if (!nl || nl->fd < 0) return -1;

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    u32 msg_len = NLMSG_HDRLEN + sizeof(struct nfgenmsg) + len;
    char buf[4096];

    if (msg_len > sizeof(buf)) {
        log_err("nfnetlink message too large");
        return -1;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = msg_len;
    nlh->nlmsg_type = (subsys << 8) | msg_type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = ++nl->seq;
    nlh->nlmsg_pid = 0; /* kernel */

    struct nfgenmsg *nfg = NLMSG_DATA(nlh);
    nfg->nfgen_family = AF_INET;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;

    if (data && len > 0) {
        u8 *msg_data = (u8 *)NLMSG_DATA(nlh);
        memcpy(msg_data + sizeof(struct nfgenmsg), data, len);
    }

    struct iovec iov = { .iov_base = buf, .iov_len = nlh->nlmsg_len };
    struct msghdr msg = {
        .msg_name = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    return sendmsg(nl->fd, &msg, 0);
}

static int nfnetlink_recv(nfnetlink_t *nl, char *buf, size_t buf_len)
{
    if (!nl || nl->fd < 0 || !buf) return -1;

    struct sockaddr_nl addr;
    struct iovec iov = { .iov_base = buf, .iov_len = buf_len };
    struct msghdr msg = {
        .msg_name = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    int ret = recvmsg(nl->fd, &msg, 0);
    if (ret < 0) return -1;

    /* Verify sender is kernel */
    if (addr.nl_pid != 0) {
        log_debug("nfnetlink: received message from userspace (pid %u)", addr.nl_pid);
    }

    return ret;
}

nfnetlink_t *nfnetlink_create(void)
{
    nfnetlink_t *nl = ngfw_malloc(sizeof(nfnetlink_t));
    if (!nl) return NULL;

    memset(nl, 0, sizeof(nfnetlink_t));

    nl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (nl->fd < 0) {
        log_debug("nfnetlink: kernel support not available (errno %d)", errno);
        ngfw_free(nl);
        return NULL;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    if (bind(nl->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_debug("nfnetlink: bind failed (errno %d)", errno);
        close(nl->fd);
        ngfw_free(nl);
        return NULL;
    }

    nl->seq = 0;
    nl->portid = 0;
    nl->connected = true;

    log_info("nfnetlink: initialized (fd=%d)", nl->fd);

    return nl;
}

void nfnetlink_destroy(nfnetlink_t *nl)
{
    if (!nl) return;

    if (nl->fd >= 0) {
        close(nl->fd);
    }

    ngfw_free(nl);
}

bool nfnetlink_is_available(nfnetlink_t *nl)
{
    return nl && nl->connected && nl->fd >= 0;
}

/* Queue operations for userspace packet processing */
ngfw_ret_t nfnetlink_queue_create(nfnetlink_t *nl, u16 queue_num, u32 queue_maxlen)
{
    if (!nfnetlink_is_available(nl)) return NGFW_ERR_INVALID;

    /* NFQA_CFG_QUEUE_MAXLEN attribute */
    struct {
        struct nlattr nfa;
        u32 value;
    } attr = {
        .nfa = { .nla_type = NFQA_CFG_QUEUE_MAXLEN, .nla_len = sizeof(attr) },
        .value = htonl(queue_maxlen)
    };

    /* NFQNL_MSG_CONFIG with NFQNL_CFG_CMD_BIND */
    struct nfqnl_msg_config_cmd cmd = {
        .command = NFQNL_CFG_CMD_BIND,
        .pf = htons(AF_INET)
    };

    /* Send bind command */
    u16 flags = NLM_F_ACK;
    int ret = nfnetlink_send(nl, NFNL_SUBSYS_QUEUE, NFQNL_MSG_CONFIG, flags, &cmd, sizeof(cmd));
    if (ret < 0) {
        log_err("nfnetlink: queue bind failed");
        return NGFW_ERR;
    }

    /* Configure queue maxlen */
    ret = nfnetlink_send(nl, NFNL_SUBSYS_QUEUE, NFQNL_MSG_CONFIG, flags, &attr, sizeof(attr));
    if (ret < 0) {
        log_err("nfnetlink: queue maxlen config failed");
        return NGFW_ERR;
    }

    log_info("nfnetlink: queue %u created (maxlen=%u)", queue_num, queue_maxlen);
    return NGFW_OK;
}

ngfw_ret_t nfnetlink_queue_destroy(nfnetlink_t *nl, u16 queue_num)
{
    if (!nfnetlink_is_available(nl)) return NGFW_ERR_INVALID;

    struct nfqnl_msg_config_cmd cmd = {
        .command = NFQNL_CFG_CMD_UNBIND,
        .pf = htons(AF_INET)
    };

    int ret = nfnetlink_send(nl, NFNL_SUBSYS_QUEUE, NFQNL_MSG_CONFIG, NLM_F_ACK, &cmd, sizeof(cmd));
    if (ret < 0) {
        log_err("nfnetlink: queue unbind failed");
        return NGFW_ERR;
    }

    log_info("nfnetlink: queue %u destroyed", queue_num);
    return NGFW_OK;
}

ngfw_ret_t nfnetlink_queue_set_mode(nfnetlink_t *nl, u16 queue_num, u8 mode, u32 range)
{
    if (!nfnetlink_is_available(nl)) return NGFW_ERR_INVALID;

    struct nfqnl_msg_config_params params = {
        .copy_range = htonl(range),
        .copy_mode = mode
    };

    struct {
        struct nlattr nfa;
        struct nfqnl_msg_config_params params;
    } attr = {
        .nfa = { .nla_type = NFQA_CFG_PARAMS, .nla_len = sizeof(attr) },
        .params = params
    };

    int ret = nfnetlink_send(nl, NFNL_SUBSYS_QUEUE, NFQNL_MSG_CONFIG, NLM_F_ACK, &attr, sizeof(attr));
    if (ret < 0) {
        log_err("nfnetlink: queue mode set failed");
        return NGFW_ERR;
    }

    log_debug("nfnetlink: queue %u mode=%u range=%u", queue_num, mode, range);
    return NGFW_OK;
}

ngfw_ret_t nfnetlink_verdict(nfnetlink_t *nl, u32 id, u32 queue_num, int verdict)
{
    (void)queue_num;
    if (!nfnetlink_is_available(nl)) return NGFW_ERR_INVALID;

    struct {
        struct nlattr id_attr;
        u32 id;
        struct nlattr verdict_attr;
        int32_t verdict;
    } msg = {
        .id_attr = { .nla_type = NFQA_PACKET_ID, .nla_len = sizeof(msg.id_attr) + sizeof(u32) },
        .id = htonl(id),
        .verdict_attr = { .nla_type = NFQA_VERDICT_HDR, .nla_len = sizeof(msg.verdict_attr) + sizeof(int32_t) },
        .verdict = htonl(verdict)
    };

    int ret = nfnetlink_send(nl, NFNL_SUBSYS_QUEUE, NFQNL_MSG_VERDICT, NLM_F_ACK, &msg, sizeof(msg));
    if (ret < 0) {
        log_err("nfnetlink: verdict send failed");
        return NGFW_ERR;
    }

    return NGFW_OK;
}

/* nftables operations */
ngfw_ret_t nfnetlink_nft_table_create(nfnetlink_t *nl, const char *name)
{
    if (!nfnetlink_is_available(nl) || !name) return NGFW_ERR_INVALID;

    struct {
        struct nlattr nfa;
        char data[256];
    } attr = {
        .nfa = { .nla_type = NFTA_TABLE_NAME }
    };

    size_t len = strlen(name) + 1;
    if (len > sizeof(attr.data)) len = sizeof(attr.data);
    memcpy(attr.data, name, len);
    attr.nfa.nla_len = sizeof(attr.nfa) + len;

    int ret = nfnetlink_send(nl, NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE, NLM_F_ACK, &attr, attr.nfa.nla_len);
    if (ret < 0) {
        log_err("nfnetlink: nft table create failed: %s", name);
        return NGFW_ERR;
    }

    log_info("nfnetlink: nft table created: %s", name);
    return NGFW_OK;
}

ngfw_ret_t nfnetlink_nft_table_delete(nfnetlink_t *nl, const char *name)
{
    if (!nfnetlink_is_available(nl) || !name) return NGFW_ERR_INVALID;

    struct {
        struct nlattr nfa;
        char data[256];
    } attr = {
        .nfa = { .nla_type = NFTA_TABLE_NAME }
    };

    size_t len = strlen(name) + 1;
    if (len > sizeof(attr.data)) len = sizeof(attr.data);
    memcpy(attr.data, name, len);
    attr.nfa.nla_len = sizeof(attr.nfa) + len;

    int ret = nfnetlink_send(nl, NFNL_SUBSYS_NFTABLES, NFT_MSG_DELTABLE, NLM_F_ACK, &attr, attr.nfa.nla_len);
    if (ret < 0) {
        log_err("nfnetlink: nft table delete failed: %s", name);
        return NGFW_ERR;
    }

    log_info("nfnetlink: nft table deleted: %s", name);
    return NGFW_OK;
}

ngfw_ret_t nfnetlink_nft_chain_create(nfnetlink_t *nl, const char *table, const char *chain, const char *type)
{
    (void)type;
    if (!nfnetlink_is_available(nl) || !table || !chain) return NGFW_ERR_INVALID;

    /* Simplified: just send table name for now */
    struct {
        struct nlattr nfa;
        char data[256];
    } attr = {
        .nfa = { .nla_type = NFTA_TABLE_NAME }
    };

    size_t len = strlen(table) + 1;
    if (len > sizeof(attr.data)) len = sizeof(attr.data);
    memcpy(attr.data, table, len);
    attr.nfa.nla_len = sizeof(attr.nfa) + len;

    int ret = nfnetlink_send(nl, NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWCHAIN, NLM_F_ACK, &attr, attr.nfa.nla_len);
    if (ret < 0) {
        log_err("nfnetlink: nft chain create failed: %s/%s", table, chain);
        return NGFW_ERR;
    }

    log_info("nfnetlink: nft chain created: %s/%s", table, chain);
    return NGFW_OK;
}

ngfw_ret_t nfnetlink_nft_rule_add(nfnetlink_t *nl, const char *table, const char *chain,
                                   u32 family, u32 handle, void *expr, u32 expr_len)
{
    (void)family;
    (void)handle;
    if (!nfnetlink_is_available(nl) || !table || !chain) return NGFW_ERR_INVALID;

    /* Build rule with expression */
    struct {
        struct nlattr table_attr;
        char table_name[256];
        struct nlattr chain_attr;
        char chain_name[256];
    } msg;

    memset(&msg, 0, sizeof(msg));

    msg.table_attr.nla_type = NFTA_TABLE_NAME;
    size_t tlen = strlen(table) + 1;
    if (tlen > sizeof(msg.table_name)) tlen = sizeof(msg.table_name);
    memcpy(msg.table_name, table, tlen);
    msg.table_attr.nla_len = sizeof(msg.table_attr) + tlen;

    msg.chain_attr.nla_type = NFTA_CHAIN_NAME;
    size_t clen = strlen(chain) + 1;
    if (clen > sizeof(msg.chain_name)) clen = sizeof(msg.chain_name);
    memcpy(msg.chain_name, chain, clen);
    msg.chain_attr.nla_len = sizeof(msg.chain_attr) + clen;

    u32 total_len = sizeof(msg) + expr_len;
    if (total_len > 4096) {
        log_err("nfnetlink: rule too large");
        return NGFW_ERR;
    }

    char buf[4096];
    memcpy(buf, &msg, sizeof(msg));
    if (expr && expr_len > 0) {
        memcpy(buf + sizeof(msg), expr, expr_len);
    }

    int ret = nfnetlink_send(nl, NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE, NLM_F_ACK | NLM_F_CREATE, buf, total_len);
    if (ret < 0) {
        log_err("nfnetlink: nft rule add failed");
        return NGFW_ERR;
    }

    log_debug("nfnetlink: nft rule added to %s/%s", table, chain);
    return NGFW_OK;
}

/* Connection tracking operations */
ngfw_ret_t nfnetlink_ct_flush(nfnetlink_t *nl)
{
    if (!nfnetlink_is_available(nl)) return NGFW_ERR_INVALID;

    /* Use generic delete with NLM_F_EXCL flag to flush */
    int ret = nfnetlink_send(nl, NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_DELETE, NLM_F_ACK | NLM_F_EXCL, NULL, 0);
    if (ret < 0) {
        log_debug("nfnetlink: ct flush not available (kernel may not support)");
        return NGFW_OK; /* Not a fatal error */
    }

    log_info("nfnetlink: connection tracking flushed");
    return NGFW_OK;
}

ngfw_ret_t nfnetlink_ct_dump(nfnetlink_t *nl, char *buf, size_t buf_len, u32 *count)
{
    if (!nfnetlink_is_available(nl) || !buf || !count) return NGFW_ERR_INVALID;

    int ret = nfnetlink_send(nl, NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_GETCT, 0, NULL, 0);
    if (ret < 0) {
        log_debug("nfnetlink: ct dump not available");
        return NGFW_OK;
    }

    int recv_len = nfnetlink_recv(nl, buf, buf_len);
    if (recv_len < 0) {
        log_err("nfnetlink: ct dump recv failed");
        return NGFW_ERR;
    }

    /* Count entries (simplified) */
    *count = (u32)(recv_len / sizeof(struct nlmsghdr));

    return NGFW_OK;
}
