/*
 * ngfw - single-threaded event loop contract (L1 core).
 *
 * One thread owns an evloop instance (single-writer principle,
 * designs/02-architecture.md section 4). Handlers may add or remove other
 * descriptors but MUST NOT run another evloop in the same thread.
 */
#ifndef NGFW_EVLOOP_H
#define NGFW_EVLOOP_H 1

#include <stdint.h>

#include <ngfw/platform.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct nfc_evloop;

/* Events bits are the platform poll bits (NPX_EV_*). */
typedef void (*nfc_evcb_t) (void *user_data, int fd, uint32_t events);

/* Creates a loop; returns 0 on success. */
int nfc_evloop_create (struct nfc_evloop **out_evloop);

/* Registers fd with an event mask and callback. Re-adding an already
 * registered fd replaces its registration. Returns 0 on success. */
int nfc_evloop_add (struct nfc_evloop *evloop, int fd, uint32_t events,
        nfc_evcb_t callback, void *user_data);

/* Removes fd; unknown fds are ignored (returns 0). */
int nfc_evloop_del (struct nfc_evloop *evloop, int fd);

/* Dispatches ready events once, waiting up to timeout_ms (-1 = forever).
 * Returns the number of dispatched callbacks, or -1 on error. */
int nfc_evloop_run (struct nfc_evloop *evloop, int timeout_ms);

void nfc_evloop_destroy (struct nfc_evloop *evloop);

#ifdef __cplusplus
}
#endif

#endif /* NGFW_EVLOOP_H */
