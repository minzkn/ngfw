#ifndef NGFW_EXECUTIL_H
#define NGFW_EXECUTIL_H

#include "types.h"

/* Safe fork+exec wrapper - no shell injection */
int safe_exec(const char *path, char *const argv[], int timeout_sec);

/* Safe iptables execution via fork/exec */
int safe_iptables(const char *table, const char *chain, const char *rule_str);

/* Netfilter netlink operations (fall back to iptables if unavailable) */
int nfnetlink_flush_table(const char *table_name);
int nfnetlink_add_rule(const char *table, const char *chain, const char *rule_str);
int nfnetlink_del_rule(const char *table, const char *chain, const char *rule_str);

#endif
