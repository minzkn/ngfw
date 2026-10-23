/* Unit runner for the core suite (`make check`). The cases themselves live
 * in src/lib/selftest/nst_core.c so that the runtime `ngfw selftest core`
 * command runs exactly the same checks (R07). */
#include <ngfw/selftest.h>

int
main (void)
{
  return nst_run (&nst_core_suite, 1);
}
