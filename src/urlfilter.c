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

#include "ngfw/urlfilter.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include "ngfw/log.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static const char *category_names[] = {
    "none", "adult", "gambling", "social", "streaming", "shopping",
    "news", "entertainment", "technology", "business", "education",
    "health", "finance", "government", "malware", "phishing"
};

struct urlfilter {
    hash_table_t *url_rules;
    hash_table_t *dns_rules;
    domain_suffix_tree_t *suffix_tree;
    url_stats_t stats;
    bool initialized;
};

static char *to_lowercase(char *str)
{
    for (char *p = str; *p; p++) {
        *p = tolower(*p);
    }
    return str;
}

static char *extract_domain(const char *url, char *domain, size_t len)
{
    if (!url || !domain) return NULL;

    const char *start = strstr(url, "://");
    if (start) {
        start += 3;
    } else {
        start = url;
    }

    const char *end = strchr(start, '/');
    if (end) {
        size_t dlen = end - start;
        if (dlen >= len) dlen = len - 1;
        strncpy(domain, start, dlen);
        domain[dlen] = '\0';
    } else {
        strncpy(domain, start, len - 1);
        domain[len - 1] = '\0';
    }

    const char *colon = strchr(domain, ':');
    if (colon) {
        *colon = '\0';
    }

    return domain;
}

static char *get_domain_suffix(const char *domain)
{
    const char *dot = strrchr(domain, '.');
    if (!dot) return (char *)domain;
    return (char *)(dot + 1);
}

urlfilter_t *urlfilter_create(void)
{
    urlfilter_t *filter = ngfw_malloc(sizeof(urlfilter_t));
    if (!filter) return NULL;

    filter->url_rules = hash_create(1024, NULL, NULL, NULL);
    filter->dns_rules = hash_create(1024, NULL, NULL, NULL);
    filter->suffix_tree = suffix_tree_create();

    if (!filter->url_rules || !filter->dns_rules || !filter->suffix_tree) {
        if (filter->url_rules) hash_destroy(filter->url_rules);
        if (filter->dns_rules) hash_destroy(filter->dns_rules);
        if (filter->suffix_tree) suffix_tree_destroy(filter->suffix_tree);
        ngfw_free(filter);
        return NULL;
    }

    memset(&filter->stats, 0, sizeof(url_stats_t));
    filter->initialized = false;

    return filter;
}

void urlfilter_destroy(urlfilter_t *filter)
{
    if (!filter) return;

    if (filter->initialized) {
        urlfilter_shutdown(filter);
    }

    if (filter->url_rules) hash_destroy(filter->url_rules);
    if (filter->dns_rules) hash_destroy(filter->dns_rules);
    if (filter->suffix_tree) suffix_tree_destroy(filter->suffix_tree);

    ngfw_free(filter);
}

ngfw_ret_t urlfilter_init(urlfilter_t *filter)
{
    if (!filter) return NGFW_ERR_INVALID;

    filter->initialized = true;
    log_info("URL filter initialized");

    return NGFW_OK;
}

ngfw_ret_t urlfilter_shutdown(urlfilter_t *filter)
{
    if (!filter) return NGFW_ERR_INVALID;

    filter->initialized = false;
    log_info("URL filter shutdown");

    return NGFW_OK;
}

ngfw_ret_t urlfilter_add_rule(urlfilter_t *filter, url_rule_t *rule)
{
    if (!filter || !rule) return NGFW_ERR_INVALID;

    return hash_insert(filter->url_rules, (void *)(uintptr_t)rule->id, rule);
}

ngfw_ret_t urlfilter_del_rule(urlfilter_t *filter, u32 rule_id)
{
    if (!filter) return NGFW_ERR_INVALID;

    hash_remove(filter->url_rules, (void *)(uintptr_t)rule_id);
    return NGFW_OK;
}

ngfw_ret_t urlfilter_clear_rules(urlfilter_t *filter)
{
    if (!filter) return NGFW_ERR_INVALID;

    hash_destroy(filter->url_rules);
    filter->url_rules = hash_create(1024, NULL, NULL, NULL);

    return NGFW_OK;
}

ngfw_ret_t urlfilter_add_dns_rule(urlfilter_t *filter, dns_rule_t *rule)
{
    if (!filter || !rule) return NGFW_ERR_INVALID;

    char domain[256];
    strncpy(domain, rule->domain, sizeof(domain) - 1);
    to_lowercase(domain);

    return hash_insert(filter->dns_rules, strdup(domain), rule);
}

ngfw_ret_t urlfilter_del_dns_rule(urlfilter_t *filter, u32 rule_id)
{
    if (!filter) return NGFW_ERR_INVALID;

    (void)rule_id;
    return NGFW_OK;
}

ngfw_ret_t urlfilter_check_url(urlfilter_t *filter, const char *url, url_category_t *category)
{
    if (!filter || !url) return NGFW_ERR_INVALID;

    char domain[256];
    extract_domain(url, domain, sizeof(domain));
    to_lowercase(domain);

    url_category_t cat = URL_CATEGORY_NONE;

    if (suffix_tree_lookup(filter->suffix_tree, domain, &cat)) {
        if (category) *category = cat;
        filter->stats.categories[cat]++;
        return cat == URL_CATEGORY_MALWARE || cat == URL_CATEGORY_PHISHING ? NGFW_ERR : NGFW_OK;
    }

    for (u32 i = 0; i < filter->url_rules->size; i++) {
        struct hash_node *node = filter->url_rules->buckets[i];
        while (node) {
            url_rule_t *rule = (url_rule_t *)node->value;
            if (rule && rule->enabled) {
                if (strstr(domain, rule->pattern)) {
                    if (category) *category = rule->category;
                    filter->stats.categories[rule->category]++;

                    if (rule->allow) {
                        filter->stats.requests_allowed++;
                        return NGFW_OK;
                    } else {
                        filter->stats.requests_blocked++;
                        log_info("URL blocked: %s (category: %s)", url, category_names[rule->category]);
                        return NGFW_ERR;
                    }
                }
            }
            node = node->next;
        }
    }

    if (category) *category = URL_CATEGORY_NONE;
    filter->stats.requests_allowed++;
    return NGFW_OK;
}

ngfw_ret_t urlfilter_check_dns(urlfilter_t *filter, const char *domain, url_category_t *category)
{
    if (!filter || !domain) return NGFW_ERR_INVALID;

    char d[256];
    strncpy(d, domain, sizeof(d) - 1);
    to_lowercase(d);

    dns_rule_t *rule = hash_lookup(filter->dns_rules, d);
    if (rule && rule->enabled && rule->block) {
        if (category) *category = rule->category;
        filter->stats.requests_blocked++;
        log_info("DNS blocked: %s", domain);
        return NGFW_ERR;
    }

    url_category_t cat;
    if (suffix_tree_lookup(filter->suffix_tree, d, &cat)) {
        if (category) *category = cat;
        filter->stats.categories[cat]++;
        return cat == URL_CATEGORY_MALWARE || cat == URL_CATEGORY_PHISHING ? NGFW_ERR : NGFW_OK;
    }

    if (category) *category = URL_CATEGORY_NONE;
    return NGFW_OK;
}

ngfw_ret_t urlfilter_check_domain(urlfilter_t *filter, const char *domain, bool *blocked)
{
    url_category_t category;
    ngfw_ret_t ret = urlfilter_check_dns(filter, domain, &category);

    if (blocked) {
        *blocked = (ret != NGFW_OK);
    }

    return ret;
}

url_stats_t *urlfilter_get_stats(urlfilter_t *filter)
{
    return filter ? &filter->stats : NULL;
}

void urlfilter_reset_stats(urlfilter_t *filter)
{
    if (filter) {
        memset(&filter->stats, 0, sizeof(url_stats_t));
    }
}

ngfw_ret_t urlfilter_load_blocklist(urlfilter_t *filter, const char *filename)
{
    if (!filter || !filename) return NGFW_ERR_INVALID;

    FILE *fp = fopen(filename, "r");
    if (!fp) return NGFW_ERR_INVALID;

    char line[512];
    u32 rule_id = 1;

    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';

        if (line[0] == '#' || line[0] == '\0') continue;

        char domain[256];
        strncpy(domain, line, sizeof(domain) - 1);

        char *domain_start = domain;
        if (strncmp(domain, "0.0.0.0 ", 8) == 0) {
            domain_start = domain + 8;
        }

        to_lowercase(domain_start);

        dns_rule_t *rule = ngfw_malloc(sizeof(dns_rule_t));
        if (rule) {
            rule->id = rule_id++;
            strncpy(rule->domain, domain_start, sizeof(rule->domain) - 1);
            rule->category = URL_CATEGORY_MALWARE;
            rule->block = true;
            rule->enabled = true;

            urlfilter_add_dns_rule(filter, rule);
        }
    }

    fclose(fp);
    log_info("Loaded blocklist from %s", filename);

    return NGFW_OK;
}

ngfw_ret_t urlfilter_load_categories(urlfilter_t *filter, const char *filename)
{
    return urlfilter_load_db(filter, filename);
}

ngfw_ret_t urlfilter_load_db(urlfilter_t *filter, const char *filename)
{
    if (!filter || !filename) return NGFW_ERR_INVALID;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        log_warn("URL filter database not found: %s", filename);
        return NGFW_ERR;
    }

    char line[512];
    int loaded = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        url_rule_t rule = {0};
        int category_id = 0;
        int action = 0;

        if (sscanf(line, "%u|%[^|]|%[^|]|%d", &rule.id, rule.pattern, (char*)&rule.category, &action) >= 3) {
            rule.allow = (action == 0);
            rule.enabled = true;
            rule.priority = rule.id;

            urlfilter_add_rule(filter, &rule);
            loaded++;
        }
    }

    fclose(fp);

    log_info("Loaded %d URL rules from %s", loaded, filename);

    return NGFW_OK;
}

domain_suffix_tree_t *suffix_tree_create(void)
{
    domain_suffix_tree_t *tree = ngfw_malloc(sizeof(domain_suffix_tree_t));
    if (!tree) return NULL;

    memset(tree->children, 0, sizeof(tree->children));
    tree->is_end = false;
    tree->category = URL_CATEGORY_NONE;

    return tree;
}

void suffix_tree_destroy(domain_suffix_tree_t *tree)
{
    if (!tree) return;

    for (int i = 0; i < 128; i++) {
        if (tree->children[i]) {
            suffix_tree_destroy(tree->children[i]);
        }
    }

    ngfw_free(tree);
}

ngfw_ret_t suffix_tree_add(domain_suffix_tree_t *tree, const char *domain, url_category_t category)
{
    if (!tree || !domain) return NGFW_ERR_INVALID;

    domain_suffix_tree_t *node = tree;
    size_t len = strlen(domain);

    for (size_t i = len > 0 ? len - 1 : 0; ; i--) {
        unsigned char c = (unsigned char)domain[i];

        if (c >= 128) continue;

        if (!node->children[c]) {
            node->children[c] = suffix_tree_create();
            if (!node->children[c]) return NGFW_ERR_NO_MEM;
        }

        node = node->children[c];

        if (i == 0) break;
    }

    node->is_end = true;
    node->category = category;

    return NGFW_OK;
}

bool suffix_tree_lookup(domain_suffix_tree_t *tree, const char *domain, url_category_t *category)
{
    if (!tree || !domain) return false;

    char d[256];
    strncpy(d, domain, sizeof(d) - 1);
    to_lowercase(d);

    const char *suffix = get_domain_suffix(d);
    if (!suffix) return false;

    domain_suffix_tree_t *node = tree;
    size_t len = strlen(suffix);

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)suffix[i];
        if (c >= 128 || !node->children[c]) {
            return false;
        }
        node = node->children[c];

        if (node->is_end) {
            if (category) *category = node->category;
            return true;
        }
    }

    return false;
}
