#include "ngfw/connpool.h"
#include "ngfw/memory.h"
#include "ngfw/platform.h"
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

struct connection {
    int fd;
    void *data;
    u64 created;
    conn_destructor_t destructor;
    bool in_use;
};

struct connpool {
    connection_t **connections;
    u32 max_connections;
    u32 used;
    pthread_mutex_t lock;
};

connpool_t *connpool_create(u32 max_connections)
{
    if (max_connections == 0) return NULL;
    
    connpool_t *pool = ngfw_malloc(sizeof(connpool_t));
    if (!pool) return NULL;
    
    pool->connections = ngfw_calloc(max_connections, sizeof(connection_t *));
    if (!pool->connections) {
        ngfw_free(pool);
        return NULL;
    }
    
    pool->max_connections = max_connections;
    pool->used = 0;
    pthread_mutex_init(&pool->lock, NULL);
    
    return pool;
}

void connpool_destroy(connpool_t *pool)
{
    if (!pool) return;
    
    pthread_mutex_lock(&pool->lock);
    for (u32 i = 0; i < pool->max_connections; i++) {
        if (pool->connections[i]) {
            connection_destroy(pool->connections[i]);
        }
    }
    pthread_mutex_unlock(&pool->lock);
    
    ngfw_free(pool->connections);
    pthread_mutex_destroy(&pool->lock);
    ngfw_free(pool);
}

connection_t *connpool_acquire(connpool_t *pool)
{
    if (!pool) return NULL;
    
    pthread_mutex_lock(&pool->lock);
    
    for (u32 i = 0; i < pool->max_connections; i++) {
        if (pool->connections[i] && !pool->connections[i]->in_use) {
            pool->connections[i]->in_use = true;
            pool->used++;
            pthread_mutex_unlock(&pool->lock);
            return pool->connections[i];
        }
    }
    
    if (pool->used < pool->max_connections) {
        for (u32 i = 0; i < pool->max_connections; i++) {
            if (!pool->connections[i]) {
                connection_t *conn = connection_create(-1);
                if (!conn) {
                    pthread_mutex_unlock(&pool->lock);
                    return NULL;
                }
                conn->in_use = true;
                pool->connections[i] = conn;
                pool->used++;
                pthread_mutex_unlock(&pool->lock);
                return conn;
            }
        }
    }
    
    pthread_mutex_unlock(&pool->lock);
    return NULL;
}

void connpool_release(connpool_t *pool, connection_t *conn)
{
    if (!pool || !conn) return;
    
    pthread_mutex_lock(&pool->lock);
    if (conn->in_use) {
        conn->in_use = false;
        if (pool->used > 0) pool->used--;
    }
    pthread_mutex_unlock(&pool->lock);
}

void connpool_release_direct(connpool_t *pool, void *conn)
{
    connpool_release(pool, (connection_t *)conn);
}

u32 connpool_available(connpool_t *pool)
{
    if (!pool) return 0;
    u32 avail;
    pthread_mutex_lock(&pool->lock);
    avail = pool->max_connections - pool->used;
    pthread_mutex_unlock(&pool->lock);
    return avail;
}

u32 connpool_used(connpool_t *pool)
{
    if (!pool) return 0;
    u32 used;
    pthread_mutex_lock(&pool->lock);
    used = pool->used;
    pthread_mutex_unlock(&pool->lock);
    return used;
}

u32 connpool_max(connpool_t *pool)
{
    return pool ? pool->max_connections : 0;
}

bool connpool_set_max(connpool_t *pool, u32 max)
{
    if (!pool || max == 0) return false;
    
    pthread_mutex_lock(&pool->lock);
    
    if (max < pool->used) {
        pthread_mutex_unlock(&pool->lock);
        return false;
    }
    
    connection_t **new_conns = ngfw_realloc(pool->connections, max * sizeof(connection_t *));
    if (!new_conns) {
        pthread_mutex_unlock(&pool->lock);
        return false;
    }
    
    for (u32 i = pool->max_connections; i < max; i++) {
        new_conns[i] = NULL;
    }
    
    pool->connections = new_conns;
    pool->max_connections = max;
    
    pthread_mutex_unlock(&pool->lock);
    return true;
}

connection_t *connection_create(int fd)
{
    connection_t *conn = ngfw_malloc(sizeof(connection_t));
    if (!conn) return NULL;
    
    conn->fd = fd;
    conn->data = NULL;
    conn->created = get_us_time();
    conn->destructor = NULL;
    conn->in_use = false;
    
    return conn;
}

void connection_destroy(connection_t *conn)
{
    if (!conn) return;
    
    if (conn->destructor && conn->data) {
        conn->destructor(conn->data);
    }
    
    if (conn->fd >= 0) {
        close(conn->fd);
    }
    
    ngfw_free(conn);
}

int connection_get_fd(connection_t *conn)
{
    return conn ? conn->fd : -1;
}

void *connection_get_data(connection_t *conn)
{
    return conn ? conn->data : NULL;
}

void connection_set_data(connection_t *conn, void *data)
{
    if (!conn) return;
    conn->data = data;
}

u64 connection_get_created(connection_t *conn)
{
    return conn ? conn->created : 0;
}

void connection_set_destructor(connection_t *conn, conn_destructor_t destructor)
{
    if (!conn) return;
    conn->destructor = destructor;
}
