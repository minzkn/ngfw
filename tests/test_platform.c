/* Unit runner for the platform suite (`make check`). The cases themselves
 * live in src/lib/selftest/nst_platform.c so that the runtime `ngfw selftest
 * platform` command runs exactly the same checks (R07). */
#include <ngfw/selftest.h>

int
main (void)
{
  return nst_run (&nst_platform_suite, 1);
}
