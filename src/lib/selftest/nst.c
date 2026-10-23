/* ngfw - selftest framework implementation (F15). */
#include <stdio.h>

#include <ngfw/selftest.h>

int
nst_run (const struct nst_suite *suite, int verbose)
{
  size_t index;
  size_t passed = 0;
  int failed = 0;

  if (suite == NULL || suite->cases == NULL)
  {
    fprintf (stderr, "FAIL: invalid selftest suite\n");
    return 1;
  }
  (void) fprintf (stdout, "[%s] %zu case(s)\n", suite->name,
          suite->case_count);
  for (index = 0; index < suite->case_count; index++)
  {
    const struct nst_case *test = &suite->cases[index];
    int rc = (test->fn != NULL) ? test->fn () : -1;

    if (rc != 0)
    {
      failed++;
      (void) fprintf (stdout, "  FAIL: %s\n", test->name);
    }
    else
    {
      passed++;
      if (verbose)
      {
        (void) fprintf (stdout, "  ok: %s\n", test->name);
      }
    }
  }
  (void) fprintf (stdout, "[%s] %zu/%zu passed\n", suite->name, passed,
          suite->case_count);
  return failed;
}
