/* ngfw - platform pipe helper (L0).
 *
 * config.h MUST come first: it carries the feature test macros that decide
 * which OS facilities are visible. */
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <ngfw/platform.h>

#if defined(HAVE_PIPE2)

int
npx_pipe (int fds[2])
{
  if (fds == NULL)
    {
      return -1;
    }
  return (pipe2 (fds, O_NONBLOCK | O_CLOEXEC) == 0) ? 0 : -1;
}

#else

int
npx_pipe (int fds[2])
{
  int flags;

  if (fds == NULL)
    {
      return -1;
    }
  if (pipe (fds) != 0)
    {
      return -1;
    }
  flags = fcntl (fds[0], F_GETFL, 0);
  if (flags >= 0)
    {
      (void) fcntl (fds[0], F_SETFL, flags | O_NONBLOCK);
    }
  flags = fcntl (fds[1], F_GETFL, 0);
  if (flags >= 0)
    {
      (void) fcntl (fds[1], F_SETFL, flags | O_NONBLOCK);
    }
  (void) fcntl (fds[0], F_SETFD, FD_CLOEXEC);
  (void) fcntl (fds[1], F_SETFD, FD_CLOEXEC);
  return 0;
}

#endif
