/* ngfw - platform event poll wrapper (L0, epoll backed).
 *
 * config.h MUST come first: it carries the feature test macros that decide
 * which OS facilities are visible. */
#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/epoll.h>

#include <ngfw/platform.h>

#if !defined(HAVE_SYS_EPOLL_H)
#error "ngfw requires epoll; a poll(2) fallback is planned for later milestones"
#endif

/* Bounded scratch space avoids dynamic allocation in the wait path. */
#define NPX_POLL_SCRATCH 64

struct npx_poll
{
  int epfd;
  struct epoll_event *scratch;
};

static uint32_t
events_to_epoll (uint32_t events)
{
  uint32_t mask = 0u;

  if ((events & NPX_EV_IN) != 0u)
    {
      mask |= (uint32_t) EPOLLIN;
    }
  if ((events & NPX_EV_OUT) != 0u)
    {
      mask |= (uint32_t) EPOLLOUT;
    }
  if ((events & NPX_EV_ERR) != 0u)
    {
      mask |= (uint32_t) (EPOLLERR | EPOLLHUP);
    }
  return mask;
}

static uint32_t
events_from_epoll (uint32_t mask)
{
  uint32_t events = NPX_EV_NONE;

  if ((mask & (uint32_t) EPOLLIN) != 0u)
    {
      events |= NPX_EV_IN;
    }
  if ((mask & (uint32_t) EPOLLOUT) != 0u)
    {
      events |= NPX_EV_OUT;
    }
  if ((mask & (uint32_t) (EPOLLERR | EPOLLHUP)) != 0u)
    {
      events |= NPX_EV_ERR;
    }
  return events;
}

int
npx_poll_create (struct npx_poll **out_poll)
{
  struct npx_poll *poll;

  if (out_poll == NULL)
    {
      return -1;
    }
  *out_poll = NULL;
  poll = (struct npx_poll *) calloc (1, sizeof (*poll));
  if (poll == NULL)
    {
      return -1;
    }
#if defined(HAVE_EPOLL_CREATE1)
  poll->epfd = epoll_create1 (EPOLL_CLOEXEC);
#else
  poll->epfd = epoll_create (NPX_POLL_SCRATCH);
#endif
  if (poll->epfd < 0)
    {
      free (poll);
      return -1;
    }
  poll->scratch =
    (struct epoll_event *) calloc (NPX_POLL_SCRATCH, sizeof (*poll->scratch));
  if (poll->scratch == NULL)
    {
      (void) close (poll->epfd);
      free (poll);
      return -1;
    }
  *out_poll = poll;
  return 0;
}

int
npx_poll_add (struct npx_poll *poll, int fd, uint32_t events)
{
  struct epoll_event ev;

  if (poll == NULL || fd < 0)
    {
      return -1;
    }
  memset (&ev, 0, sizeof (ev));
  ev.events = events_to_epoll (events);
  ev.data.fd = fd;
  return (epoll_ctl (poll->epfd, EPOLL_CTL_ADD, fd, &ev) == 0) ? 0 : -1;
}

int
npx_poll_mod (struct npx_poll *poll, int fd, uint32_t events)
{
  struct epoll_event ev;

  if (poll == NULL || fd < 0)
    {
      return -1;
    }
  memset (&ev, 0, sizeof (ev));
  ev.events = events_to_epoll (events);
  ev.data.fd = fd;
  return (epoll_ctl (poll->epfd, EPOLL_CTL_MOD, fd, &ev) == 0) ? 0 : -1;
}

int
npx_poll_del (struct npx_poll *poll, int fd)
{
  if (poll == NULL || fd < 0)
    {
      return -1;
    }
  /* Removing an already-removed fd is not an error for callers. */
  if (epoll_ctl (poll->epfd, EPOLL_CTL_DEL, fd, NULL) != 0 && errno != ENOENT)
    {
      return -1;
    }
  return 0;
}

int
npx_poll_wait (struct npx_poll *poll, struct npx_poll_event *events,
         int max_events, int timeout_ms)
{
  int capacity;
  int ready;
  int index;

  if (poll == NULL || events == NULL || max_events <= 0)
    {
      return -1;
    }
  capacity = (max_events < NPX_POLL_SCRATCH) ? max_events : NPX_POLL_SCRATCH;
  ready = epoll_wait (poll->epfd, poll->scratch, capacity, timeout_ms);
  if (ready < 0)
    {
      return (errno == EINTR) ? 0 : -1;
    }
  for (index = 0; index < ready; index++)
    {
      events[index].fd = poll->scratch[index].data.fd;
      events[index].events = events_from_epoll (poll->scratch[index].events);
    }
  return ready;
}

void
npx_poll_close (struct npx_poll *poll)
{
  if (poll != NULL)
    {
      if (poll->epfd >= 0)
  {
    (void) close (poll->epfd);
  }
      free (poll->scratch);
      free (poll);
    }
}
