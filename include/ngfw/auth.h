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

#ifndef NGFW_AUTH_H
#define NGFW_AUTH_H

#include "types.h"

#define NGFW_AUTH_MAX_USERS 32
#define NGFW_AUTH_MAX_SESSIONS 64
#define NGFW_AUTH_TOKEN_SIZE 64

typedef enum {
    AUTH_ROLE_ADMIN,
    AUTH_ROLE_OPERATOR,
    AUTH_ROLE_VIEWER,
    AUTH_ROLE_MAX
} auth_role_t;

typedef enum {
    AUTH_METHOD_PASSWORD,
    AUTH_METHOD_TOKEN,
    AUTH_METHOD_CERTIFICATE,
    AUTH_METHOD_MAX
} auth_method_t;

typedef struct auth_user {
    char username[64];
    char password_hash[128];
    auth_role_t role;
    bool enabled;
    u32 login_attempts;
    u64 last_login;
    u64 lockout_until;
} auth_user_t;

typedef struct auth_session {
    char session_id[NGFW_AUTH_TOKEN_SIZE];
    char username[64];
    u64 created;
    u64 last_activity;
    u64 expires;
    char ip[48];
    bool active;
} auth_session_t;

typedef struct auth_config {
    u32 max_sessions;
    u32 session_timeout;
    u32 max_login_attempts;
    u32 lockout_duration;
    bool require_strong_password;
    u32 min_password_length;
    bool two_factor_enabled;
} auth_config_t;

typedef struct auth_module auth_module_t;

auth_module_t *auth_create(void);
void auth_destroy(auth_module_t *auth);

ngfw_ret_t auth_init(auth_module_t *auth);
ngfw_ret_t auth_shutdown(auth_module_t *auth);

ngfw_ret_t auth_add_user(auth_module_t *auth, const char *username, const char *password, auth_role_t role);
ngfw_ret_t auth_del_user(auth_module_t *auth, const char *username);
ngfw_ret_t auth_set_password(auth_module_t *auth, const char *username, const char *old_password, const char *new_password);

ngfw_ret_t auth_login(auth_module_t *auth, const char *username, const char *password, const char *ip, char *session_id, size_t session_len);
ngfw_ret_t auth_logout(auth_module_t *auth, const char *session_id);
ngfw_ret_t auth_verify_session(auth_module_t *auth, const char *session_id);
ngfw_ret_t auth_refresh_session(auth_module_t *auth, const char *session_id);

bool auth_check_permission(auth_module_t *auth, const char *session_id, auth_role_t required_role);

auth_session_t *auth_get_session(auth_module_t *auth, const char *session_id);
auth_user_t *auth_get_user(auth_module_t *auth, const char *username);

ngfw_ret_t auth_load_users(auth_module_t *auth, const char *filename);
ngfw_ret_t auth_save_users(auth_module_t *auth, const char *filename);

ngfw_ret_t auth_set_config(auth_module_t *auth, auth_config_t *config);
auth_config_t *auth_get_config(auth_module_t *auth);

#endif