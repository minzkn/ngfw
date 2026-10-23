/* ngfw - platform error rendering (L0).
 *
 * config.h MUST come first: it carries the feature test macros that decide
 * which libc declarations are visible. */
#include "config.h"

#include <string.h>

#include <ngfw/platform.h>

/* One buffer per thread keeps npx_strerror() thread-safe without dynamic
 * allocation in error paths. */
static _Thread_local char s_errbuf[128];

const char *
npx_strerror (int errnum)
{
#if defined(STRERROR_R_CHAR_P)
  char *text;

  text = strerror_r (errnum, s_errbuf, sizeof (s_errbuf));
  return (text != NULL) ? text : "unknown error";
#else
  if (strerror_r (errnum, s_errbuf, sizeof (s_errbuf)) != 0)
    {
      return "unknown error";
    }
  return s_errbuf;
#endif
}
