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

#ifndef NGFW_WEB_H
#define NGFW_WEB_H

#include "types.h"
#include "engine.h"

typedef enum {
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_PATCH
} http_method_t;

typedef enum {
    HTTP_STATUS_OK = 200,
    HTTP_STATUS_CREATED = 201,
    HTTP_STATUS_NO_CONTENT = 204,
    HTTP_STATUS_BAD_REQUEST = 400,
    HTTP_STATUS_UNAUTHORIZED = 401,
    HTTP_STATUS_FORBIDDEN = 403,
    HTTP_STATUS_NOT_FOUND = 404,
    HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
    HTTP_STATUS_INTERNAL_ERROR = 500
} http_status_t;

typedef struct http_request {
    http_method_t method;
    char uri[256];
    char query_string[256];
    char body[8192];
    u32 body_length;
    char headers[32][2][256];
    u32 header_count;
} http_request_t;

typedef struct http_response {
    http_status_t status;
    char body[16384];
    u32 body_length;
    char content_type[64];
} http_response_t;

typedef ngfw_ret_t (*http_handler_t)(const http_request_t *req, http_response_t *res, void *context);

typedef struct http_route {
    char path[128];
    http_method_t method;
    http_handler_t handler;
    void *context;
    struct http_route *next;
} http_route_t;

typedef struct web_server {
    int socket_fd;
    char bind_address[48];
    u16 port;
    bool running;
    http_route_t *routes;
    void *ssl_ctx;
    void *context;
} web_server_t;

web_server_t *web_server_create(void);
void web_server_destroy(web_server_t *server);

ngfw_ret_t web_server_set_address(web_server_t *server, const char *address, u16 port);
ngfw_ret_t web_server_register_route(web_server_t *server, const char *path, http_method_t method,
                                     http_handler_t handler, void *context);

ngfw_ret_t web_server_start(web_server_t *server);
ngfw_ret_t web_server_stop(web_server_t *server);

typedef struct web_context {
    ngfw_engine_t *engine;
    char username[64];
    bool authenticated;
} web_context_t;

ngfw_ret_t web_api_get_stats(const http_request_t *req, http_response_t *res, void *context);
ngfw_ret_t web_api_get_sessions(const http_request_t *req, http_response_t *res, void *context);
ngfw_ret_t web_api_get_config(const http_request_t *req, http_response_t *res, void *context);
ngfw_ret_t web_api_set_config(const http_request_t *req, http_response_t *res, void *context);
ngfw_ret_t web_api_get_filter_rules(const http_request_t *req, http_response_t *res, void *context);
ngfw_ret_t web_api_add_filter_rule(const http_request_t *req, http_response_t *res, void *context);
ngfw_ret_t web_api_get_ips_signatures(const http_request_t *req, http_response_t *res, void *context);
ngfw_ret_t web_api_get_vpn_tunnels(const http_request_t *req, http_response_t *res, void *context);

ngfw_ret_t web_serve_static_file(web_server_t *server, const char *path, http_response_t *res);

#endif
