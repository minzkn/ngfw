#include "ngfw/web.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/engine.h"
#include "ngfw/prometheus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>

#define HTTP_BUFFER_SIZE 16384

static const char *http_status_text[] = {
    [HTTP_STATUS_OK] = "OK",
    [HTTP_STATUS_CREATED] = "Created",
    [HTTP_STATUS_NO_CONTENT] = "No Content",
    [HTTP_STATUS_BAD_REQUEST] = "Bad Request",
    [HTTP_STATUS_UNAUTHORIZED] = "Unauthorized",
    [HTTP_STATUS_FORBIDDEN] = "Forbidden",
    [HTTP_STATUS_NOT_FOUND] = "Not Found",
    [HTTP_STATUS_METHOD_NOT_ALLOWED] = "Method Not Allowed",
    [HTTP_STATUS_INTERNAL_ERROR] = "Internal Server Error"
};

static const char *default_html = "<!DOCTYPE html><html><head><title>NGFW Manager</title></head><body><h1>NGFW Management Interface</h1></body></html>";

web_server_t *web_server_create(void)
{
    web_server_t *server = ngfw_malloc(sizeof(web_server_t));
    if (!server) return NULL;

    memset(server, 0, sizeof(web_server_t));
    server->socket_fd = -1;
    strcpy(server->bind_address, "0.0.0.0");
    server->port = 8443;

    return server;
}

void web_server_destroy(web_server_t *server)
{
    if (!server) return;

    if (server->running) {
        web_server_stop(server);
    }

    http_route_t *route = server->routes;
    while (route) {
        http_route_t *next = route->next;
        ngfw_free(route);
        route = next;
    }

    ngfw_free(server);
}

ngfw_ret_t web_server_set_address(web_server_t *server, const char *address, u16 port)
{
    if (!server) return NGFW_ERR_INVALID;

    if (address) {
        strncpy(server->bind_address, address, sizeof(server->bind_address) - 1);
    }
    server->port = port;

    return NGFW_OK;
}

ngfw_ret_t web_server_register_route(web_server_t *server, const char *path, http_method_t method,
                                     http_handler_t handler, void *context)
{
    if (!server || !path || !handler) return NGFW_ERR_INVALID;

    http_route_t *route = ngfw_malloc(sizeof(http_route_t));
    if (!route) return NGFW_ERR_NO_MEM;

    strncpy(route->path, path, sizeof(route->path) - 1);
    route->method = method;
    route->handler = handler;
    route->context = context;
    route->next = server->routes;
    server->routes = route;

    return NGFW_OK;
}

static http_route_t * __attribute__((unused)) find_route(web_server_t *server, const char *path, http_method_t method)
{
    http_route_t *route = server->routes;
    while (route) {
        if (strcmp(route->path, path) == 0 && route->method == method) {
            return route;
        }
        route = route->next;
    }
    return NULL;
}

static void parse_request(const char *buffer, http_request_t *req)
{
    memset(req, 0, sizeof(http_request_t));

    char method[16], uri[256], version[16];
    sscanf(buffer, "%s %s %s", method, uri, version);

    if (strcmp(method, "GET") == 0) req->method = HTTP_METHOD_GET;
    else if (strcmp(method, "POST") == 0) req->method = HTTP_METHOD_POST;
    else if (strcmp(method, "PUT") == 0) req->method = HTTP_METHOD_PUT;
    else if (strcmp(method, "DELETE") == 0) req->method = HTTP_METHOD_DELETE;

    char *path = uri;
    char *query = strchr(uri, '?');
    if (query) {
        *query = '\0';
        strncpy(req->query_string, query + 1, sizeof(req->query_string) - 1);
    }
    strncpy(req->uri, path, sizeof(req->uri) - 1);

    const char *body = strstr(buffer, "\r\n\r\n");
    if (body) {
        body += 4;
        strncpy(req->body, body, sizeof(req->body) - 1);
        req->body_length = strlen(req->body);
    }
}

static void build_response(http_response_t *res, char *buffer, size_t size)
{
    const char *status_text = http_status_text[res->status] ? http_status_text[res->status] : "Unknown";

    snprintf(buffer, size,
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "\r\n",
             res->status, status_text,
             res->content_type[0] ? res->content_type : "application/json",
             res->body_length);

    size_t len = strlen(buffer);
    if (res->body_length > 0 && len < size) {
        strncat(buffer, res->body, size - len - 1);
    }
}

static void *client_thread(void *arg)
{
    int client_fd = *(int *)arg;
    ngfw_free(arg);

    web_server_t *server = arg ? NULL : NULL;

    char buffer[HTTP_BUFFER_SIZE];
    ssize_t len = read(client_fd, buffer, sizeof(buffer) - 1);

    if (len > 0) {
        buffer[len] = '\0';

        http_request_t req;
        parse_request(buffer, &req);

        http_response_t res;
        memset(&res, 0, sizeof(res));
        res.status = HTTP_STATUS_OK;
        strcpy(res.content_type, "application/json");

        if (strcmp(req.uri, "/") == 0 || strcmp(req.uri, "/index.html") == 0) {
            res.status = HTTP_STATUS_OK;
            res.body_length = strlen(default_html);
            strncpy(res.body, default_html, sizeof(res.body) - 1);
            strcpy(res.content_type, "text/html");
        } else if (strcmp(req.uri, "/metrics") == 0) {
            prometheus_t *prom = NULL;
            if (server && server->context) {
                web_context_t *ctx = (web_context_t *)server->context;
                prom = ngfw_engine_get_prometheus(ctx->engine);
            }
            if (prom) {
                char metrics[8192];
                prometheus_export(prom, metrics, sizeof(metrics));
                res.body_length = strlen(metrics);
                strncpy(res.body, metrics, sizeof(res.body) - 1);
            } else {
                res.status = HTTP_STATUS_NOT_FOUND;
                strcpy(res.body, "{}");
                res.body_length = 2;
            }
        } else if (strcmp(req.uri, "/api/stats") == 0) {
            web_context_t *ctx = NULL;
            ngfw_stats_t stats = {0};
            if (server && server->context) {
                ctx = (web_context_t *)server->context;
                if (ctx->engine) {
                    stats = *ngfw_engine_get_stats(ctx->engine);
                }
            }

            snprintf(res.body, sizeof(res.body),
                     "{"
                     "\"packets_processed\":%lu,"
                     "\"packets_dropped\":%lu,"
                     "\"packets_forwarded\":%lu,"
                     "\"bytes_processed\":%lu,"
                     "\"sessions_active\":%lu,"
                     "\"sessions_created\":%lu,"
                     "\"sessions_expired\":%lu,"
                     "\"ips_threats_detected\":%lu,"
                     "\"ips_threats_blocked\":%lu,"
                     "\"nat_translations\":%lu,"
                     "\"ddos_blocked\":%lu,"
                     "\"antivirus_blocked\":%lu,"
                     "\"uptime\":%lu"
                     "}",
                     stats.packets_processed,
                     stats.packets_dropped,
                     stats.packets_forwarded,
                     stats.bytes_processed,
                     stats.sessions_active,
                     stats.sessions_created,
                     stats.sessions_expired,
                     stats.ips_threats_detected,
                     stats.ips_threats_blocked,
                     stats.nat_translations,
                     stats.ddos_blocked,
                     stats.antivirus_blocked,
                     stats.uptime / 1000);
            res.body_length = strlen(res.body);
        } else if (strcmp(req.uri, "/api/sessions") == 0) {
            strcpy(res.body, "[]");
            res.body_length = 2;
        } else if (strcmp(req.uri, "/api/ips") == 0) {
            strcpy(res.body, "{\"enabled\":true,\"signatures\":500}");
            res.body_length = strlen(res.body);
        } else if (strcmp(req.uri, "/api/nat") == 0) {
            strcpy(res.body, "{\"enabled\":true,\"translations\":0}");
            res.body_length = strlen(res.body);
        } else if (strcmp(req.uri, "/api/ddos") == 0) {
            strcpy(res.body, "{\"enabled\":true,\"blocked_ips\":0}");
            res.body_length = strlen(res.body);
        } else if (strcmp(req.uri, "/api/config") == 0) {
            strcpy(res.body, "{\"filter_enabled\":true,\"ips_enabled\":true,\"nat_enabled\":true,\"ddos_enabled\":true}");
            res.body_length = strlen(res.body);
        } else {
            res.status = HTTP_STATUS_NOT_FOUND;
            strcpy(res.body, "{\"error\":\"Not found\"}");
            res.body_length = strlen(res.body);
        }

        char response[32768];
        build_response(&res, response, sizeof(response));
        ssize_t written = write(client_fd, response, strlen(response));
        (void)written;
    }

    close(client_fd);
    return NULL;
}

ngfw_ret_t web_server_start(web_server_t *server)
{
    if (!server) return NGFW_ERR_INVALID;
    if (server->running) return NGFW_OK;

    server->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->socket_fd < 0) {
        return NGFW_ERR;
    }

    int opt = 1;
    setsockopt(server->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(server->bind_address);
    addr.sin_port = htons(server->port);

    if (bind(server->socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(server->socket_fd);
        return NGFW_ERR;
    }

    if (listen(server->socket_fd, 10) < 0) {
        close(server->socket_fd);
        return NGFW_ERR;
    }

    server->running = true;
    log_info("Web server started on %s:%d", server->bind_address, server->port);

    while (server->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server->socket_fd, (struct sockaddr *)&client_addr, &client_len);

        if (client_fd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        int *fd_ptr = ngfw_malloc(sizeof(int));
        *fd_ptr = client_fd;
        pthread_t thread;
        pthread_create(&thread, NULL, client_thread, fd_ptr);
        pthread_detach(thread);
    }

    return NGFW_OK;
}

ngfw_ret_t web_server_stop(web_server_t *server)
{
    if (!server) return NGFW_ERR_INVALID;

    server->running = false;

    if (server->socket_fd >= 0) {
        close(server->socket_fd);
        server->socket_fd = -1;
    }

    return NGFW_OK;
}

ngfw_ret_t web_api_get_stats(const http_request_t *req, http_response_t *res, void *context)
{
    (void)req;

    web_context_t *ctx = (web_context_t *)context;
    if (!ctx || !ctx->engine) {
        res->status = HTTP_STATUS_INTERNAL_ERROR;
        return NGFW_ERR;
    }

    ngfw_stats_t *stats = ngfw_engine_get_stats(ctx->engine);

    snprintf(res->body, sizeof(res->body),
             "{"
             "\"packets_processed\":%lu,"
             "\"packets_dropped\":%lu,"
             "\"packets_forwarded\":%lu,"
             "\"bytes_processed\":%lu,"
             "\"sessions_active\":%lu,"
             "\"sessions_created\":%lu,"
             "\"sessions_expired\":%lu,"
             "\"ips_threats_detected\":%lu,"
             "\"ips_threats_blocked\":%lu,"
             "\"nat_translations\":%lu,"
             "\"ddos_blocked\":%lu,"
             "\"uptime\":%lu"
             "}",
             stats->packets_processed,
             stats->packets_dropped,
             stats->packets_forwarded,
             stats->bytes_processed,
             stats->sessions_active,
             stats->sessions_created,
             stats->sessions_expired,
             stats->ips_threats_detected,
             stats->ips_threats_blocked,
             stats->nat_translations,
             stats->ddos_blocked,
             stats->uptime / 1000);

    res->body_length = strlen(res->body);
    res->status = HTTP_STATUS_OK;

    return NGFW_OK;
}

ngfw_ret_t web_api_get_sessions(const http_request_t *req, http_response_t *res, void *context)
{
    (void)req;
    (void)context;

    res->status = HTTP_STATUS_OK;
    strcpy(res->body, "[]");
    res->body_length = 2;

    return NGFW_OK;
}

ngfw_ret_t web_api_get_config(const http_request_t *req, http_response_t *res, void *context)
{
    (void)req;
    (void)context;

    res->status = HTTP_STATUS_OK;
    strcpy(res->body, "{\"filter_enabled\":true,\"ips_enabled\":true,\"nat_enabled\":true,\"ddos_enabled\":true}");
    res->body_length = strlen(res->body);

    return NGFW_OK;
}

ngfw_ret_t web_api_set_config(const http_request_t *req, http_response_t *res, void *context)
{
    (void)req;
    (void)context;

    res->status = HTTP_STATUS_OK;
    strcpy(res->body, "{\"status\":\"ok\"}");
    res->body_length = strlen(res->body);

    return NGFW_OK;
}

ngfw_ret_t web_api_get_filter_rules(const http_request_t *req, http_response_t *res, void *context)
{
    (void)req;
    (void)context;

    res->status = HTTP_STATUS_OK;
    strcpy(res->body, "[]");
    res->body_length = 2;

    return NGFW_OK;
}

ngfw_ret_t web_api_add_filter_rule(const http_request_t *req, http_response_t *res, void *context)
{
    (void)req;
    (void)context;

    res->status = HTTP_STATUS_CREATED;
    strcpy(res->body, "{\"id\":1}");
    res->body_length = strlen(res->body);

    return NGFW_OK;
}

ngfw_ret_t web_api_get_ips_signatures(const http_request_t *req, http_response_t *res, void *context)
{
    (void)req;
    (void)context;

    res->status = HTTP_STATUS_OK;
    strcpy(res->body, "{\"enabled\":true,\"count\":500}");
    res->body_length = strlen(res->body);

    return NGFW_OK;
}

ngfw_ret_t web_api_get_vpn_tunnels(const http_request_t *req, http_response_t *res, void *context)
{
    (void)req;
    (void)context;

    res->status = HTTP_STATUS_OK;
    strcpy(res->body, "[]");
    res->body_length = 2;

    return NGFW_OK;
}

ngfw_ret_t web_serve_static_file(web_server_t *server, const char *path, http_response_t *res)
{
    (void)server;
    (void)path;

    res->status = HTTP_STATUS_OK;
    res->body_length = strlen(default_html);
    strncpy(res->body, default_html, sizeof(res->body) - 1);
    strcpy(res->content_type, "text/html");

    return NGFW_OK;
}
