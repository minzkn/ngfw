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
#include "ngfw/types.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

struct urlfilter {
    hash_table_t *rules;
    hash_table_t *dns_rules;
    domain_suffix_tree_t *suffix_tree;
    url_stats_t stats;
    bool initialized;
};

static u32 url_hash(const void *key, u32 size)
{
    const char *str = (const char *)key;
    u32 hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % size;
}

static bool url_match(const void *key1, const void *key2)
{
    return strcmp((const char *)key1, (const char *)key2) == 0;
}

urlfilter_t *urlfilter_create(void)
{
    urlfilter_t *filter = ngfw_malloc(sizeof(urlfilter_t));
    if (!filter) return NULL;
    
    memset(filter, 0, sizeof(urlfilter_t));
    
    filter->rules = hash_create(128, url_hash, url_match, NULL);
    filter->dns_rules = hash_create(128, url_hash, url_match, NULL);
    filter->suffix_tree = suffix_tree_create();
    
    return filter;
}

void urlfilter_destroy(urlfilter_t *filter)
{
    if (!filter) return;
    
    if (filter->rules) hash_destroy(filter->rules);
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
    log_info("URL filter stopped");
    
    return NGFW_OK;
}

ngfw_ret_t urlfilter_add_rule(urlfilter_t *filter, url_rule_t *rule)
{
    if (!filter || !rule) return NGFW_ERR_INVALID;
    
    char key[512];
    snprintf(key, sizeof(key), "%s:%u", rule->pattern, rule->id);
    
    hash_insert(filter->rules, key, rule);
    
    return NGFW_OK;
}

ngfw_ret_t urlfilter_del_rule(urlfilter_t *filter, u32 rule_id)
{
    if (!filter) return NGFW_ERR_INVALID;
    
    void **iter = hash_iterate_start(filter->rules);
    while (hash_iterate_has_next(iter)) {
        url_rule_t *rule = (url_rule_t *)hash_iterate_next(filter->rules, iter);
        if (rule && rule->id == rule_id) {
            hash_remove(filter->rules, rule);
            ngfw_free(rule);
            return NGFW_OK;
        }
    }
    
    return NGFW_ERR;
}

ngfw_ret_t urlfilter_clear_rules(urlfilter_t *filter)
{
    if (!filter) return NGFW_ERR_INVALID;
    
    if (filter->rules) {
        hash_destroy(filter->rules);
        filter->rules = hash_create(128, url_hash, url_match, NULL);
    }
    
    return NGFW_OK;
}

ngfw_ret_t urlfilter_add_dns_rule(urlfilter_t *filter, dns_rule_t *rule)
{
    if (!filter || !rule) return NGFW_ERR_INVALID;
    
    hash_insert(filter->dns_rules, rule->domain, rule);
    
    if (rule->block) {
        suffix_tree_add(filter->suffix_tree, rule->domain, rule->category);
    }
    
    return NGFW_OK;
}

ngfw_ret_t urlfilter_del_dns_rule(urlfilter_t *filter, u32 rule_id)
{
    if (!filter) return NGFW_ERR_INVALID;
    
    void **iter = hash_iterate_start(filter->dns_rules);
    while (hash_iterate_has_next(iter)) {
        dns_rule_t *rule = (dns_rule_t *)hash_iterate_next(filter->dns_rules, iter);
        if (rule && rule->id == rule_id) {
            hash_remove(filter->dns_rules, rule);
            ngfw_free(rule);
            return NGFW_OK;
        }
    }
    
    return NGFW_ERR;
}

ngfw_ret_t urlfilter_check_url(urlfilter_t *filter, const char *url, url_category_t *category)
{
    if (!filter || !url) return NGFW_ERR_INVALID;
    
    if (category) *category = URL_CATEGORY_NONE;
    
    const char *host_start = strstr(url, "://");
    if (!host_start) return NGFW_ERR;
    
    host_start += 3;
    
    const char *path = strchr(host_start, '/');
    size_t host_len;
    if (path) {
        host_len = path - host_start;
    } else {
        host_len = strlen(host_start);
    }
    
    if (host_len == 0) return NGFW_ERR;
    
    char domain[256];
    if (host_len >= sizeof(domain)) {
        host_len = sizeof(domain) - 1;
    }
    
    strncpy(domain, host_start, host_len);
    domain[host_len] = '\0';
    
    char *port_str = strchr(domain, ':');
    if (port_str) {
        *port_str = '\0';
    }
    
    return urlfilter_check_dns(filter, domain, category);
}

ngfw_ret_t urlfilter_check_dns(urlfilter_t *filter, const char *domain, url_category_t *category)
{
    if (!filter || !domain) return NGFW_ERR_INVALID;
    
    url_category_t cat = URL_CATEGORY_NONE;
    bool found = suffix_tree_lookup(filter->suffix_tree, domain, &cat);
    
    if (category) *category = cat;
    
    return found ? NGFW_OK : NGFW_ERR;
}

ngfw_ret_t urlfilter_check_domain(urlfilter_t *filter, const char *domain, bool *blocked)
{
    url_category_t category;
    ngfw_ret_t ret = urlfilter_check_dns(filter, domain, &category);
    
    if (blocked) {
        *blocked = (ret == NGFW_OK && category != URL_CATEGORY_NONE);
    }
    
    return ret;
}

url_stats_t *urlfilter_get_stats(urlfilter_t *filter)
{
    if (!filter) return NULL;
    return &filter->stats;
}

void urlfilter_reset_stats(urlfilter_t *filter)
{
    if (!filter) return;
    memset(&filter->stats, 0, sizeof(url_stats_t));
}

ngfw_ret_t urlfilter_load_blocklist(urlfilter_t *filter, const char *filename)
{
    if (!filter || !filename) return NGFW_ERR_INVALID;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) return NGFW_ERR;
    
    char line[512];
    u32 loaded = 0;
    u32 rule_id = hash_size(filter->rules) + 1;
    
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == 0) continue;
        
        url_rule_t rule = {0};
        rule.id = rule_id++;
        snprintf(rule.pattern, sizeof(rule.pattern), "%s", line);
        rule.category = URL_CATEGORY_MALWARE;
        rule.allow = false;
        rule.enabled = true;
        rule.priority = 50;
        
        urlfilter_add_rule(filter, &rule);
        loaded++;
    }
    
    fclose(fp);
    log_info("Loaded %u blocklist rules", loaded);
    
    return NGFW_OK;
}

ngfw_ret_t urlfilter_load_categories(urlfilter_t *filter, const char *filename)
{
    if (!filter || !filename) return NGFW_ERR_INVALID;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) return NGFW_ERR;
    
    char line[512];
    u32 loaded = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == 0) continue;
        
        url_category_t category = URL_CATEGORY_NONE;
        if (strstr(line, "adult")) category = URL_CATEGORY_ADULT;
        else if (strstr(line, "gambling")) category = URL_CATEGORY_GAMBLING;
        else if (strstr(line, "social")) category = URL_CATEGORY_SOCIAL;
        else if (strstr(line, "phishing")) category = URL_CATEGORY_PHISHING;
        else if (strstr(line, "malware")) category = URL_CATEGORY_MALWARE;
        
        if (category == URL_CATEGORY_NONE) continue;
        
        dns_rule_t rule = {0};
        rule.id = loaded + 1;
        snprintf(rule.domain, sizeof(rule.domain), "%.255s", line);
        rule.category = category;
        rule.block = true;
        rule.enabled = true;
        
        urlfilter_add_dns_rule(filter, &rule);
        loaded++;
    }
    
    fclose(fp);
    log_info("Loaded %u category rules", loaded);
    
    return NGFW_OK;
}

ngfw_ret_t urlfilter_load_db(urlfilter_t *filter, const char *filename)
{
    if (!filter || !filename) return NGFW_ERR_INVALID;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return NGFW_ERR;
    }

    char line[512];
    u32 loaded = 0;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == 0) continue;

        char *category_str = strchr(line, ':');
        if (!category_str) continue;
        *category_str++ = 0;

        url_category_t category = URL_CATEGORY_NONE;
        if (strcmp(category_str, "malware") == 0) category = URL_CATEGORY_MALWARE;
        else if (strcmp(category_str, "phishing") == 0) category = URL_CATEGORY_PHISHING;
        else if (strcmp(category_str, "adult") == 0) category = URL_CATEGORY_ADULT;
        else if (strcmp(category_str, "gambling") == 0) category = URL_CATEGORY_GAMBLING;
        else if (strcmp(category_str, "social") == 0) category = URL_CATEGORY_SOCIAL;

        url_rule_t rule = {0};
        rule.id = loaded + 1;
        snprintf(rule.pattern, sizeof(rule.pattern), "%.255s", line);
        rule.category = category;
        rule.allow = false;
        rule.enabled = true;
        rule.priority = 100;

        urlfilter_add_rule(filter, &rule);
        loaded++;
    }

    fclose(fp);

    return NGFW_OK;
}

int urlfilter_check(urlfilter_t *filter, const char *url)
{
    bool blocked = false;
    urlfilter_check_domain(filter, url, &blocked);
    return blocked ? 1 : 0;
}

domain_suffix_tree_t *suffix_tree_create(void)
{
    domain_suffix_tree_t *tree = ngfw_malloc(sizeof(domain_suffix_tree_t));
    if (!tree) return NULL;
    memset(tree, 0, sizeof(domain_suffix_tree_t));
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
    
    domain_suffix_tree_t *current = tree;
    int len = strlen(domain);
    
    for (int i = len - 1; i >= 0; i--) {
        unsigned char c = domain[i];
        if (!current->children[c]) {
            current->children[c] = suffix_tree_create();
            if (!current->children[c]) return NGFW_ERR;
        }
        current = current->children[c];
    }
    
    current->is_end = true;
    current->category = category;
    
    return NGFW_OK;
}

bool suffix_tree_lookup(domain_suffix_tree_t *tree, const char *domain, url_category_t *category)
{
    if (!tree || !domain) return false;
    
    domain_suffix_tree_t *current = tree;
    int len = strlen(domain);
    url_category_t found_category = URL_CATEGORY_NONE;
    bool found = false;
    
    for (int i = len - 1; i >= 0; i--) {
        unsigned char c = domain[i];
        if (!current->children[c]) {
            return false;
        }
        current = current->children[c];
        
        if (current->is_end) {
            found = true;
            found_category = current->category;
        }
    }
    
    if (category) *category = found_category;
    return found;
}
