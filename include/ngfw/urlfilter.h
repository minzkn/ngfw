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

#ifndef NGFW_URLFILTER_H
#define NGFW_URLFILTER_H

#include "types.h"

typedef enum {
    URL_CATEGORY_NONE,
    URL_CATEGORY_ADULT,
    URL_CATEGORY_GAMBLING,
    URL_CATEGORY_SOCIAL,
    URL_CATEGORY_STREAMING,
    URL_CATEGORY_SHOPPING,
    URL_CATEGORY_NEWS,
    URL_CATEGORY_ENTERTAINMENT,
    URL_CATEGORY_TECHNOLOGY,
    URL_CATEGORY_BUSINESS,
    URL_CATEGORY_EDUCATION,
    URL_CATEGORY_HEALTH,
    URL_CATEGORY_FINANCE,
    URL_CATEGORY_GOVERNMENT,
    URL_CATEGORY_MALWARE,
    URL_CATEGORY_PHISHING,
    URL_CATEGORY_MAX
} url_category_t;

typedef struct url_rule {
    u32 id;
    char pattern[256];
    url_category_t category;
    bool allow;
    bool enabled;
    u32 priority;
} url_rule_t;

typedef struct dns_rule {
    u32 id;
    char domain[256];
    url_category_t category;
    bool block;
    bool enabled;
} dns_rule_t;

typedef struct url_stats {
    u64 requests_allowed;
    u64 requests_blocked;
    u64 categories[URL_CATEGORY_MAX];
} url_stats_t;

typedef struct urlfilter urlfilter_t;

urlfilter_t *urlfilter_create(void);
void urlfilter_destroy(urlfilter_t *filter);

ngfw_ret_t urlfilter_init(urlfilter_t *filter);
ngfw_ret_t urlfilter_shutdown(urlfilter_t *filter);

ngfw_ret_t urlfilter_add_rule(urlfilter_t *filter, url_rule_t *rule);
ngfw_ret_t urlfilter_del_rule(urlfilter_t *filter, u32 rule_id);
ngfw_ret_t urlfilter_clear_rules(urlfilter_t *filter);

ngfw_ret_t urlfilter_add_dns_rule(urlfilter_t *filter, dns_rule_t *rule);
ngfw_ret_t urlfilter_del_dns_rule(urlfilter_t *filter, u32 rule_id);

ngfw_ret_t urlfilter_check_url(urlfilter_t *filter, const char *url, url_category_t *category);
ngfw_ret_t urlfilter_check_dns(urlfilter_t *filter, const char *domain, url_category_t *category);
ngfw_ret_t urlfilter_check_domain(urlfilter_t *filter, const char *domain, bool *blocked);

url_stats_t *urlfilter_get_stats(urlfilter_t *filter);
void urlfilter_reset_stats(urlfilter_t *filter);

ngfw_ret_t urlfilter_load_blocklist(urlfilter_t *filter, const char *filename);
ngfw_ret_t urlfilter_load_categories(urlfilter_t *filter, const char *filename);
ngfw_ret_t urlfilter_load_db(urlfilter_t *filter, const char *filename);

typedef struct domain_suffix_tree {
    struct domain_suffix_tree *children[128];
    bool is_end;
    url_category_t category;
} domain_suffix_tree_t;

domain_suffix_tree_t *suffix_tree_create(void);
void suffix_tree_destroy(domain_suffix_tree_t *tree);
ngfw_ret_t suffix_tree_add(domain_suffix_tree_t *tree, const char *domain, url_category_t category);
bool suffix_tree_lookup(domain_suffix_tree_t *tree, const char *domain, url_category_t *category);

#endif
