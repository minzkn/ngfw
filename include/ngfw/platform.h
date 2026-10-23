/*
 * ngfw - platform abstraction layer (L0).
 *
 * This subsystem is the only place where OS specifics are allowed to appear
 * in the public interface (R05; designs/15-portability.md section 1). Every
 * other subsystem must go through the npx_* API. libc differences and
 * optional OS facilities are resolved by autoconf feature detection.
 */
#ifndef NGFW_PLATFORM_H
#define NGFW_PLATFORM_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* --- Memory ------------------------------------------------------------- */

/* Allocation wrappers centralize the failure policy (P-C fail-fast at the
 * caller). A zero-length request returns a distinct non-NULL pointer. */
void *npx_malloc (size_t size);
void *npx_calloc (size_t nmemb, size_t size);
void *npx_realloc (void *ptr, size_t size);
void npx_free (void *ptr);

/* Duplicates text into a fresh allocation; NULL when text is NULL or when
 * the allocation fails. */
char *npx_strdup (const char *text);

/* --- Time --------------------------------------------------------------- */

/* Nanoseconds since an unspecified boot-relative origin; never goes
 * backwards. Returns -1 when the clock is unavailable. */
int64_t npx_monotonic_ns (void);

/* Nanoseconds since the UNIX epoch. Returns -1 when the clock is
 * unavailable. */
int64_t npx_realtime_ns (void);

/* --- Error text --------------------------------------------------------- */

/* Thread-safe errno-to-text rendering. Never returns NULL; unknown values
 * render as "unknown error". */
const char *npx_strerror (int errnum);

/* --- Mutex -------------------------------------------------------------- */

struct npx_mutex;

int npx_mutex_init (struct npx_mutex **out_mutex);
void npx_mutex_lock (struct npx_mutex *mutex);
void npx_mutex_unlock (struct npx_mutex *mutex);
void npx_mutex_fini (struct npx_mutex *mutex);

/* --- Event poll --------------------------------------------------------- */

/* Readiness notification over a poll instance. Event bits below are kept
 * identical to the nfc_evloop contract in <ngfw/evloop.h>. */
#define NPX_EV_NONE 0u
#define NPX_EV_IN 1u
#define NPX_EV_OUT 2u
#define NPX_EV_ERR 4u

struct npx_poll_event
{
  int fd;
  uint32_t events;
};

struct npx_poll;

/* Creates a poll instance; returns 0 and sets *out_poll on success. */
int npx_poll_create (struct npx_poll **out_poll);

/* Registers (or re-arms) fd interest in events (NPX_EV_* bitmask). */
int npx_poll_add (struct npx_poll *poll, int fd, uint32_t events);
int npx_poll_mod (struct npx_poll *poll, int fd, uint32_t events);
int npx_poll_del (struct npx_poll *poll, int fd);

/* Waits up to timeout_ms (-1 = forever). Returns the number of ready events
 * filled into events[], 0 on timeout, -1 on error. At most 64 events are
 * reported per wait. */
int npx_poll_wait (struct npx_poll *poll, struct npx_poll_event *events,
       int max_events, int timeout_ms);

void npx_poll_close (struct npx_poll *poll);

/* --- Pipe --------------------------------------------------------------- */

/* Creates a non-blocking, close-on-exec pipe. Returns 0 on success. */
int npx_pipe (int fds[2]);

/* --- Descriptor I/O ----------------------------------------------------- */

/* Single-shot wrappers around read(2)/write(2); return the transferred byte
 * count, or -1 on error (including EAGAIN/EINTR - callers retry). */
int npx_fd_read (int fd, void *buffer, size_t length);
int npx_fd_write (int fd, const void *data, size_t length);

/* Closes fd; returns 0 on success. */
int npx_fd_close (int fd);

#ifdef __cplusplus
}
#endif

#endif /* NGFW_PLATFORM_H */
