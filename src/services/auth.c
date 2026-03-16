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

#include "ngfw/auth.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/hash.h"
#include "ngfw/crypto.h"
#include "ngfw/platform.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>

struct auth_module {
    auth_user_t users[NGFW_AUTH_MAX_USERS];
    u32 user_count;
    
    auth_session_t sessions[NGFW_AUTH_MAX_SESSIONS];
    u32 session_count;
    
    auth_config_t config;
    bool initialized;
    
    pthread_mutex_t lock;
};

static u32 __attribute__((unused)) user_hash(const void *key, u32 size)
{
    const char *username = (const char *)key;
    u32 hash = 0;
    while (*username) {
        hash = ((hash << 5) + hash) + *username++;
    }
    return hash % size;
}

static bool __attribute__((unused)) user_match(const void *key1, const void *key2)
{
    return strcmp((const char *)key1, (const char *)key2) == 0;
}

static char *generate_session_id(void)
{
    static char id[NGFW_AUTH_TOKEN_SIZE];
    u8 random_data[32];
    
    random_bytes(random_data, sizeof(random_data));
    
    for (int i = 0; i < NGFW_AUTH_TOKEN_SIZE - 1; i++) {
        static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        id[i] = charset[random_data[i % sizeof(random_data)] % (sizeof(charset) - 1)];
    }
    id[NGFW_AUTH_TOKEN_SIZE - 1] = '\0';
    
    return id;
}

static void hash_password(const char *password, char *hash, size_t hash_len)
{
    u8 digest[32];
    sha256((const u8 *)password, strlen(password), digest);
    
    for (size_t i = 0; i < 16 && i < hash_len - 1; i++) {
        sprintf(hash + (i * 2), "%02x", digest[i]);
    }
    hash[32] = '\0';
}

auth_module_t *auth_create(void)
{
    auth_module_t *auth = ngfw_malloc(sizeof(auth_module_t));
    if (!auth) return NULL;
    
    memset(auth, 0, sizeof(auth_module_t));
    
    auth->config.max_sessions = NGFW_AUTH_MAX_SESSIONS;
    auth->config.session_timeout = 3600;
    auth->config.max_login_attempts = 5;
    auth->config.lockout_duration = 300;
    auth->config.min_password_length = 8;
    auth->config.require_strong_password = false;
    auth->config.two_factor_enabled = false;
    
    pthread_mutex_init(&auth->lock, NULL);
    
    auth_add_user(auth, "admin", "admin123", AUTH_ROLE_ADMIN);
    auth_add_user(auth, "operator", "operator123", AUTH_ROLE_OPERATOR);
    auth_add_user(auth, "viewer", "viewer123", AUTH_ROLE_VIEWER);
    
    return auth;
}

void auth_destroy(auth_module_t *auth)
{
    if (auth) {
        pthread_mutex_destroy(&auth->lock);
        ngfw_free(auth);
    }
}

ngfw_ret_t auth_init(auth_module_t *auth)
{
    if (!auth) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&auth->lock);
    auth->initialized = true;
    pthread_mutex_unlock(&auth->lock);
    
    log_info("Authentication module initialized");
    return NGFW_OK;
}

ngfw_ret_t auth_shutdown(auth_module_t *auth)
{
    if (!auth) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&auth->lock);
    auth->initialized = false;
    auth->session_count = 0;
    pthread_mutex_unlock(&auth->lock);
    
    log_info("Authentication module shutdown");
    return NGFW_OK;
}

ngfw_ret_t auth_add_user(auth_module_t *auth, const char *username, const char *password, auth_role_t role)
{
    if (!auth || !username || !password) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&auth->lock);
    
    for (u32 i = 0; i < auth->user_count; i++) {
        if (strcmp(auth->users[i].username, username) == 0) {
            pthread_mutex_unlock(&auth->lock);
            return NGFW_ERR;
        }
    }
    
    if (auth->user_count >= NGFW_AUTH_MAX_USERS) {
        pthread_mutex_unlock(&auth->lock);
        return NGFW_ERR_NO_MEM;
    }
    
    auth_user_t *user = &auth->users[auth->user_count++];
    strncpy(user->username, username, sizeof(user->username) - 1);
    hash_password(password, user->password_hash, sizeof(user->password_hash));
    user->role = role;
    user->enabled = true;
    user->login_attempts = 0;
    user->lockout_until = 0;
    
    pthread_mutex_unlock(&auth->lock);
    
    log_info("User added: %s (role: %d)", username, role);
    return NGFW_OK;
}

ngfw_ret_t auth_del_user(auth_module_t *auth, const char *username)
{
    if (!auth || !username) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&auth->lock);
    
    for (u32 i = 0; i < auth->user_count; i++) {
        if (strcmp(auth->users[i].username, username) == 0) {
            for (u32 j = i; j < auth->user_count - 1; j++) {
                auth->users[j] = auth->users[j + 1];
            }
            auth->user_count--;
            pthread_mutex_unlock(&auth->lock);
            return NGFW_OK;
        }
    }
    
    pthread_mutex_unlock(&auth->lock);
    return NGFW_ERR;
}

ngfw_ret_t auth_set_password(auth_module_t *auth, const char *username, const char *old_password, const char *new_password)
{
    if (!auth || !username || !old_password || !new_password) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&auth->lock);
    
    for (u32 i = 0; i < auth->user_count; i++) {
        if (strcmp(auth->users[i].username, username) == 0) {
            char old_hash[128];
            hash_password(old_password, old_hash, sizeof(old_hash));
            
            if (strcmp(auth->users[i].password_hash, old_hash) != 0) {
                pthread_mutex_unlock(&auth->lock);
                return NGFW_ERR;
            }
            
            hash_password(new_password, auth->users[i].password_hash, sizeof(auth->users[i].password_hash));
            pthread_mutex_unlock(&auth->lock);
            return NGFW_OK;
        }
    }
    
    pthread_mutex_unlock(&auth->lock);
    return NGFW_ERR;
}

ngfw_ret_t auth_login(auth_module_t *auth, const char *username, const char *password, const char *ip, char *session_id, size_t session_len)
{
    if (!auth || !username || !password || !session_id) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&auth->lock);
    
    u64 now = get_ms_time();
    auth_user_t *user = NULL;
    
    for (u32 i = 0; i < auth->user_count; i++) {
        if (strcmp(auth->users[i].username, username) == 0) {
            user = &auth->users[i];
            break;
        }
    }
    
    if (!user) {
        pthread_mutex_unlock(&auth->lock);
        log_warn("Login failed: user not found: %s", username);
        return NGFW_ERR;
    }
    
    if (!user->enabled) {
        pthread_mutex_unlock(&auth->lock);
        log_warn("Login failed: user disabled: %s", username);
        return NGFW_ERR;
    }
    
    if (user->lockout_until > now) {
        pthread_mutex_unlock(&auth->lock);
        log_warn("Login failed: user locked until %lu", user->lockout_until);
        return NGFW_ERR;
    }
    
    char password_hash[128];
    hash_password(password, password_hash, sizeof(password_hash));
    
    if (strcmp(user->password_hash, password_hash) != 0) {
        user->login_attempts++;
        if (user->login_attempts >= auth->config.max_login_attempts) {
            user->lockout_until = now + (auth->config.lockout_duration * 1000);
            log_warn("User locked due to too many failed attempts: %s", username);
        }
        pthread_mutex_unlock(&auth->lock);
        log_warn("Login failed: invalid password: %s", username);
        return NGFW_ERR;
    }
    
    user->login_attempts = 0;
    user->last_login = now;
    
    if (auth->session_count >= auth->config.max_sessions) {
        auth->sessions[0].active = false;
        memmove(&auth->sessions[0], &auth->sessions[1], sizeof(auth_session_t) * (NGFW_AUTH_MAX_SESSIONS - 1));
        auth->session_count--;
    }
    
    auth_session_t *session = &auth->sessions[auth->session_count++];
    strcpy(session->session_id, generate_session_id());
    strncpy(session->username, username, sizeof(session->username) - 1);
    session->created = now;
    session->last_activity = now;
    session->expires = now + (auth->config.session_timeout * 1000);
    strncpy(session->ip, ip ? ip : "unknown", sizeof(session->ip) - 1);
    session->active = true;
    
    strncpy(session_id, session->session_id, session_len);
    
    pthread_mutex_unlock(&auth->lock);
    
    log_info("User logged in: %s from %s", username, ip ? ip : "unknown");
    return NGFW_OK;
}

ngfw_ret_t auth_logout(auth_module_t *auth, const char *session_id)
{
    if (!auth || !session_id) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&auth->lock);
    
    for (u32 i = 0; i < auth->session_count; i++) {
        if (auth->sessions[i].active && strcmp(auth->sessions[i].session_id, session_id) == 0) {
            auth->sessions[i].active = false;
            log_info("User logged out: %s", auth->sessions[i].username);
            pthread_mutex_unlock(&auth->lock);
            return NGFW_OK;
        }
    }
    
    pthread_mutex_unlock(&auth->lock);
    return NGFW_ERR;
}

ngfw_ret_t auth_verify_session(auth_module_t *auth, const char *session_id)
{
    if (!auth || !session_id) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&auth->lock);
    
    u64 now = get_ms_time();
    
    for (u32 i = 0; i < auth->session_count; i++) {
        if (auth->sessions[i].active && strcmp(auth->sessions[i].session_id, session_id) == 0) {
            if (auth->sessions[i].expires > now) {
                pthread_mutex_unlock(&auth->lock);
                return NGFW_OK;
            }
            auth->sessions[i].active = false;
            pthread_mutex_unlock(&auth->lock);
            return NGFW_ERR;
        }
    }
    
    pthread_mutex_unlock(&auth->lock);
    return NGFW_ERR;
}

ngfw_ret_t auth_refresh_session(auth_module_t *auth, const char *session_id)
{
    if (!auth || !session_id) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&auth->lock);
    
    u64 now = get_ms_time();
    
    for (u32 i = 0; i < auth->session_count; i++) {
        if (auth->sessions[i].active && strcmp(auth->sessions[i].session_id, session_id) == 0) {
            auth->sessions[i].last_activity = now;
            auth->sessions[i].expires = now + (auth->config.session_timeout * 1000);
            pthread_mutex_unlock(&auth->lock);
            return NGFW_OK;
        }
    }
    
    pthread_mutex_unlock(&auth->lock);
    return NGFW_ERR;
}

bool auth_check_permission(auth_module_t *auth, const char *session_id, auth_role_t required_role)
{
    if (!auth || !session_id) return false;
    
    pthread_mutex_lock(&auth->lock);
    
    for (u32 i = 0; i < auth->session_count; i++) {
        if (auth->sessions[i].active && strcmp(auth->sessions[i].session_id, session_id) == 0) {
            for (u32 j = 0; j < auth->user_count; j++) {
                if (strcmp(auth->sessions[i].username, auth->users[j].username) == 0) {
                    bool has_permission = (auth->users[j].role <= required_role);
                    pthread_mutex_unlock(&auth->lock);
                    return has_permission;
                }
            }
        }
    }
    
    pthread_mutex_unlock(&auth->lock);
    return false;
}

auth_session_t *auth_get_session(auth_module_t *auth, const char *session_id)
{
    if (!auth || !session_id) return NULL;
    
    pthread_mutex_lock(&auth->lock);
    
    for (u32 i = 0; i < auth->session_count; i++) {
        if (auth->sessions[i].active && strcmp(auth->sessions[i].session_id, session_id) == 0) {
            pthread_mutex_unlock(&auth->lock);
            return &auth->sessions[i];
        }
    }
    
    pthread_mutex_unlock(&auth->lock);
    return NULL;
}

auth_user_t *auth_get_user(auth_module_t *auth, const char *username)
{
    if (!auth || !username) return NULL;
    
    pthread_mutex_lock(&auth->lock);
    
    for (u32 i = 0; i < auth->user_count; i++) {
        if (strcmp(auth->users[i].username, username) == 0) {
            pthread_mutex_unlock(&auth->lock);
            return &auth->users[i];
        }
    }
    
    pthread_mutex_unlock(&auth->lock);
    return NULL;
}

ngfw_ret_t auth_load_users(auth_module_t *auth, const char *filename)
{
    if (!auth || !filename) return NGFW_ERR_INVALID;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) return NGFW_ERR;
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        char username[64], password[64], role_str[16];
        if (sscanf(line, "%63s %63s %15s", username, password, role_str) == 3) {
            auth_role_t role = AUTH_ROLE_VIEWER;
            if (strcmp(role_str, "admin") == 0) role = AUTH_ROLE_ADMIN;
            else if (strcmp(role_str, "operator") == 0) role = AUTH_ROLE_OPERATOR;
            
            auth_add_user(auth, username, password, role);
        }
    }
    
    fclose(fp);
    log_info("Loaded users from %s", filename);
    return NGFW_OK;
}

ngfw_ret_t auth_save_users(auth_module_t *auth, const char *filename)
{
    if (!auth || !filename) return NGFW_ERR_INVALID;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) return NGFW_ERR;
    
    fprintf(fp, "# NGFW User Database\n");
    fprintf(fp, "# Format: username password role\n\n");
    
    pthread_mutex_lock(&auth->lock);
    
    for (u32 i = 0; i < auth->user_count; i++) {
        const char *role_str = "viewer";
        if (auth->users[i].role == AUTH_ROLE_ADMIN) role_str = "admin";
        else if (auth->users[i].role == AUTH_ROLE_OPERATOR) role_str = "operator";
        
        fprintf(fp, "%s %s %s\n", auth->users[i].username, auth->users[i].password_hash, role_str);
    }
    
    pthread_mutex_unlock(&auth->lock);
    
    fclose(fp);
    log_info("Saved users to %s", filename);
    return NGFW_OK;
}

ngfw_ret_t auth_set_config(auth_module_t *auth, auth_config_t *config)
{
    if (!auth || !config) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&auth->lock);
    auth->config = *config;
    pthread_mutex_unlock(&auth->lock);
    
    return NGFW_OK;
}

auth_config_t *auth_get_config(auth_module_t *auth)
{
    if (!auth) return NULL;
    return &auth->config;
}