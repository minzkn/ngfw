/* ngfw - platform clock wrappers (L0).
 *
 * config.h MUST come first: it carries the feature test macros that decide
 * which libc declarations are visible. */
#include "config.h"

#include <stdint.h>
#include <time.h>

#if !defined(HAVE_CLOCK_GETTIME)
#include <sys/time.h>
#endif

#include <ngfw/platform.h>

int64_t
npx_monotonic_ns (void)
{
#if defined(HAVE_CLOCK_GETTIME)
  struct timespec ts;

  if (clock_gettime (CLOCK_MONOTONIC, &ts) != 0)
    {
      return -1;
    }
  return (int64_t) ts.tv_sec * 1000000000LL + (int64_t) ts.tv_nsec;
#else
  /* Fallback is wall-clock based and not strictly monotonic; real
   * deployments always provide CLOCK_MONOTONIC. */
  struct timeval tv;

  if (gettimeofday (&tv, NULL) != 0)
    {
      return -1;
    }
  return (int64_t) tv.tv_sec * 1000000000LL + (int64_t) tv.tv_usec * 1000LL;
#endif
}

int64_t
npx_realtime_ns (void)
{
#if defined(HAVE_CLOCK_GETTIME)
  struct timespec ts;

  if (clock_gettime (CLOCK_REALTIME, &ts) != 0)
    {
      return -1;
    }
  return (int64_t) ts.tv_sec * 1000000000LL + (int64_t) ts.tv_nsec;
#else
  struct timeval tv;

  if (gettimeofday (&tv, NULL) != 0)
    {
      return -1;
    }
  return (int64_t) tv.tv_sec * 1000000000LL + (int64_t) tv.tv_usec * 1000LL;
#endif
}
