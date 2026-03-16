#ifndef NGFW_CONNPOOL_H
#define NGFW_CONNPOOL_H

#include "ngfw/types.h"
#include <stddef.h>
#include <stdbool.h>

typedef struct connection connection_t;
typedef struct connpool connpool_t;

typedef void (*conn_destructor_t)(void *);

connpool_t *connpool_create(u32 max_connections);
void connpool_destroy(connpool_t *pool);
connection_t *connpool_acquire(connpool_t *pool);
void connpool_release(connpool_t *pool, connection_t *conn);
void connpool_release_direct(connpool_t *pool, void *conn);
u32 connpool_available(connpool_t *pool);
u32 connpool_used(connpool_t *pool);
u32 connpool_max(connpool_t *pool);
bool connpool_set_max(connpool_t *pool, u32 max);

connection_t *connection_create(int fd);
void connection_destroy(connection_t *conn);
int connection_get_fd(connection_t *conn);
void *connection_get_data(connection_t *conn);
void connection_set_data(connection_t *conn, void *data);
u64 connection_get_created(connection_t *conn);
void connection_set_destructor(connection_t *conn, conn_destructor_t destructor);

#endif
