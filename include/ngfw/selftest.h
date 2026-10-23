/*
 * ngfw - minimal selftest framework (F15).
 *
 * One header + one implementation back both `make check` unit tests and the
 * runtime `ngfw selftest` command; each suite is defined exactly once in the
 * library (designs/17-testing-selftest.md section 2). A case returns 0 on
 * success and -1 on the first failed assertion.
 */
#ifndef NGFW_SELFTEST_H
#define NGFW_SELFTEST_H 1

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct nst_case
{
  const char *name;
  int (*fn) (void);
};

struct nst_suite
{
  const char *name;
  const struct nst_case *cases;
  size_t case_count;
};

/* Built-in suites shipped with libngfw (defined in lib/selftest/nst_*.c). */
extern const struct nst_suite nst_platform_suite;
extern const struct nst_suite nst_core_suite;

#define NST_CASE(casename, fnptr) { (casename), (fnptr) }
#define NST_SUITE(suitename, cases_array) \
  { (suitename), (cases_array), \
    sizeof (cases_array) / sizeof ((cases_array)[0]) }

/* Assertion macros: report the failing location and abort the case. */
#define NST_CHECK(cond) \
  do \
    { \
      if (! (cond)) \
  { \
    fprintf (stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    return -1; \
  } \
    } \
  while (0)

#define NST_CHECK_EQ_INT(actual, expected) \
  do \
    { \
      long nst_a_ = (long) (actual); \
      long nst_b_ = (long) (expected); \
      if (nst_a_ != nst_b_) \
  { \
    fprintf (stderr, "  FAIL %s:%d: %s == %s (%ld != %ld)\n", \
       __FILE__, __LINE__, #actual, #expected, nst_a_, nst_b_); \
    return -1; \
  } \
    } \
  while (0)

#define NST_FAIL(message) \
  do \
    { \
      fprintf (stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, (message)); \
      return -1; \
    } \
  while (0)

/* Runs every case in suite. verbose!=0 prints passing cases too.
 * Returns the number of failed cases (0 = all passed). */
int nst_run (const struct nst_suite *suite, int verbose);

#ifdef __cplusplus
}
#endif

#endif /* NGFW_SELFTEST_H */
