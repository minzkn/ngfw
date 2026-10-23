/* ngfw - single-threaded event loop (L1 core). */
#include <stdlib.h>
#include <string.h>

#include <ngfw/evloop.h>
#include <ngfw/platform.h>

#define NFC_EVLOOP_MAX_DISPATCH 64

struct nfc_evhandler
{
  nfc_evcb_t callback;
  void *user_data;
};

struct nfc_evloop
{
  struct npx_poll *poll;
  struct nfc_evhandler *handlers; /* indexed by descriptor */
  int capacity;                   /* allocated handler slots */
  struct npx_poll_event *events;  /* dispatch scratch (fixed size) */
};

static int
ensure_capacity (struct nfc_evloop *evloop, int fd)
{
  int new_capacity;
  struct nfc_evhandler *grown;

  if (evloop == NULL || fd < 0)
  {
    return -1;
  }
  if (fd < evloop->capacity)
  {
    return 0;
  }
  new_capacity = (evloop->capacity == 0) ? 64 : evloop->capacity;
  while (new_capacity <= fd)
  {
    if (new_capacity > 1048576)
    {
      return -1;
    }
    new_capacity *= 2;
  }
  grown = (struct nfc_evhandler *) npx_realloc (evloop->handlers,
                        sizeof (*grown)
                        * (size_t) new_capacity);
  if (grown == NULL)
  {
    return -1;
  }
  memset (grown + evloop->capacity, 0,
      sizeof (*grown) * (size_t) (new_capacity - evloop->capacity));
  evloop->handlers = grown;
  evloop->capacity = new_capacity;
  return 0;
}

int
nfc_evloop_create (struct nfc_evloop **out_evloop)
{
  struct nfc_evloop *evloop;

  if (out_evloop == NULL)
  {
    return -1;
  }
  *out_evloop = NULL;
  evloop = (struct nfc_evloop *) npx_calloc (1, sizeof (*evloop));
  if (evloop == NULL)
  {
    return -1;
  }
  if (npx_poll_create (&evloop->poll) != 0)
  {
    npx_free (evloop);
    return -1;
  }
  evloop->events = (struct npx_poll_event *) npx_calloc (
    NFC_EVLOOP_MAX_DISPATCH, sizeof (*evloop->events));
  if (evloop->events == NULL)
  {
    npx_poll_close (evloop->poll);
    npx_free (evloop);
    return -1;
  }
  *out_evloop = evloop;
  return 0;
}

int
nfc_evloop_add (struct nfc_evloop *evloop, int fd, uint32_t events,
        nfc_evcb_t callback, void *user_data)
{
  if (evloop == NULL || callback == NULL)
  {
    return -1;
  }
  if (ensure_capacity (evloop, fd) != 0)
  {
    return -1;
  }
  if (npx_poll_add (evloop->poll, fd, events) != 0)
  {
    return -1;
  }
  evloop->handlers[fd].callback = callback;
  evloop->handlers[fd].user_data = user_data;
  return 0;
}

int
nfc_evloop_del (struct nfc_evloop *evloop, int fd)
{
  if (evloop == NULL)
  {
    return -1;
  }
  if (npx_poll_del (evloop->poll, fd) != 0)
  {
    return -1;
  }
  if (fd >= 0 && fd < evloop->capacity)
  {
    memset (&evloop->handlers[fd], 0, sizeof (evloop->handlers[fd]));
  }
  return 0;
}

int
nfc_evloop_run (struct nfc_evloop *evloop, int timeout_ms)
{
  int ready;
  int dispatched;
  int index;

  if (evloop == NULL)
  {
    return -1;
  }
  ready = npx_poll_wait (evloop->poll, evloop->events,
             NFC_EVLOOP_MAX_DISPATCH, timeout_ms);
  if (ready < 0)
  {
    return -1;
  }
  dispatched = 0;
  for (index = 0; index < ready; index++)
  {
    int fd = evloop->events[index].fd;
    uint32_t events = evloop->events[index].events;

    if (fd < 0 || fd >= evloop->capacity)
    {
      continue;
    }
    if (evloop->handlers[fd].callback == NULL)
    {
      continue;
    }
    evloop->handlers[fd].callback (evloop->handlers[fd].user_data, fd,
                   events);
    dispatched++;
  }
  return dispatched;
}

void
nfc_evloop_destroy (struct nfc_evloop *evloop)
{
  if (evloop != NULL)
  {
    npx_poll_close (evloop->poll);
    npx_free (evloop->handlers);
    npx_free (evloop->events);
    npx_free (evloop);
  }
}
