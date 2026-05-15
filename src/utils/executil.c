/*
 * NGFW - Next-Generation Firewall
 * Safe process execution utilities (replaces system() calls)
 * Copyright (C) 2024 NGFW Project
 */

#define _GNU_SOURCE
#include "ngfw/executil.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

/* Safe fork+exec wrapper - no shell injection */
int safe_exec(const char *path, char *const argv[], int timeout_sec)
{
    pid_t pid = fork();
    if (pid == -1) {
        log_err("fork() failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child */
        setsid();
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > 2) close(fd);
        }
        execvp(path, argv);
        _exit(127);
    }

    /* Parent */
    int status;
    pid_t ret;
    u64 deadline = get_ms_time() + (timeout_sec * 1000);

    do {
        ret = waitpid(pid, &status, WNOHANG);
        if (ret == 0) {
            if (get_ms_time() > deadline) {
                kill(pid, SIGTERM);
                usleep(100000);
                kill(pid, SIGKILL);
                waitpid(pid, NULL, 0);
                log_warn("Command timed out: %s", path);
                return -1;
            }
            usleep(10000);
        }
    } while (ret == 0);

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

/* Build argv for iptables command */
static char **build_iptables_argv(const char *table, const char *chain,
                                   const char *rule_str, int *argc_out)
{
    (void)chain;
    int max_args = 32;
    char **argv = ngfw_malloc(sizeof(char *) * max_args);
    if (!argv) return NULL;

    int argc = 0;
    argv[argc++] = "iptables";

    if (table && table[0]) {
        argv[argc++] = "-t";
        argv[argc++] = strdup(table);
    }

    /* Parse rule_str into individual arguments */
    char *copy = strdup(rule_str);
    if (!copy) { ngfw_free(argv); return NULL; }

    char *save;
    char *tok = strtok_r(copy, " ", &save);
    while (tok && argc < max_args - 1) {
        argv[argc++] = strdup(tok);
        tok = strtok_r(NULL, " ", &save);
    }
    ngfw_free(copy);
    argv[argc] = NULL;
    *argc_out = argc;
    return argv;
}

static void free_argv(char **argv, int argc)
{
    if (!argv) return;
    for (int i = 0; i < argc; i++) {
        if (argv[i]) ngfw_free(argv[i]);
    }
    ngfw_free(argv);
}

/* Safe iptables execution via fork/exec - no shell */
int safe_iptables(const char *table, const char *chain, const char *rule_str)
{
    int argc;
    char **argv = build_iptables_argv(table, chain, rule_str, &argc);
    if (!argv) return -1;

    int ret = safe_exec("iptables", argv, 10);
    free_argv(argv, argc);
    return ret;
}

/* Netlink socket for direct kernel netfilter communication */
static int nfnetlink_socket(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) {
        log_debug("NFNETLINK socket not available, falling back to iptables");
    }
    return fd;
}

#if 0
/* Send netlink message to kernel netfilter (future use with proper nf_tables) */
static int nfnetlink_send_request(int nl_fd, int subsys_id, int msg_type,
                                   int msg_flags, void *payload, size_t payload_len)
{
    (void)nl_fd;
    (void)subsys_id;
    (void)msg_type;
    (void)msg_flags;
    (void)payload;
    (void)payload_len;
    return -1;
}
#endif

int nfnetlink_flush_table(const char *table_name)
{
    /* Try netlink first, fall back to iptables */
    int fd = nfnetlink_socket();
    if (fd >= 0) {
        close(fd);
        /* Netlink flush - use iptables fallback for now */
    }

    /* Fallback: safe iptables */
    char rule[16] = "-F";
    return safe_iptables(table_name, NULL, rule);
}

int nfnetlink_add_rule(const char *table, const char *chain,
                        const char *rule_str)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "-A %s %s", chain, rule_str);
    return safe_iptables(table, NULL, buf);
}

int nfnetlink_del_rule(const char *table, const char *chain,
                        const char *rule_str)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "-D %s %s", chain, rule_str);
    return safe_iptables(table, NULL, buf);
}
