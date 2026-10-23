/* ngfw - management CLI (L4). M0 exposes the selftest and version commands;
 * the full command tree arrives with designs/11-management.md milestones. */
#include <stdio.h>
#include <string.h>

#include <ngfw/selftest.h>
#include <ngfw/version.h>

static int
case_version_format (void)
{
  const char *version = NGFW_VERSION;
  size_t index = 0;
  int components = 0;

  NST_CHECK (version != NULL && version[0] != '\0');
  while (components < 3)
  {
    if (version[index] < '0' || version[index] > '9')
    {
      NST_FAIL ("version component must start with a digit");
    }
    while (version[index] >= '0' && version[index] <= '9')
    {
      index++;
    }
    components++;
    if (components == 3)
    {
      break;
    }
    if (version[index] != '.')
    {
      NST_FAIL ("version components must be dot separated");
    }
    index++;
  }
  /* Everything after MAJOR.MINOR.PATCH must be a SemVer prerelease ('-')
   * or build metadata ('+') suffix (docs/standards/semver-notes.md). */
  NST_CHECK (version[index] == '\0' || version[index] == '-'
       || version[index] == '+');
  return 0;
}

static const struct nst_case s_version_cases[] = {
  NST_CASE ("version-format", case_version_format),
};

static const struct nst_suite s_version_suite =
  NST_SUITE ("version", s_version_cases);

struct module_entry
{
  const char *name;
  const struct nst_suite *suite;
};

static const struct module_entry s_modules[] = {
  { "platform", &nst_platform_suite },
  { "core", &nst_core_suite },
  { "version", &s_version_suite },
};

#define NGFW_MODULE_COUNT (sizeof (s_modules) / sizeof (s_modules[0]))

static int
module_index (const char *name)
{
  size_t index;

  for (index = 0; index < NGFW_MODULE_COUNT; index++)
  {
    if (strcmp (s_modules[index].name, name) == 0)
    {
      return (int) index;
    }
  }
  return -1;
}

static int
run_selftest (int argc, char **argv)
{
  int verbose = 0;
  int run_all = 0;
  int explicit_count = 0;
  int failed = 0;
  size_t index;
  int argument;

  for (argument = 0; argument < argc; argument++)
  {
    const char *arg = argv[argument];

    if (strcmp (arg, "-v") == 0 || strcmp (arg, "--verbose") == 0)
    {
      verbose = 1;
      continue;
    }
    if (strcmp (arg, "all") == 0)
    {
      run_all = 1;
      explicit_count++;
      continue;
    }
    if (module_index (arg) < 0)
    {
      (void) fprintf (stderr, "ngfw: unknown selftest module '%s'\n", arg);
      return 2;
    }
    explicit_count++;
  }
  if (run_all || explicit_count == 0)
  {
    for (index = 0; index < NGFW_MODULE_COUNT; index++)
    {
      failed += nst_run (s_modules[index].suite, verbose);
    }
  }
  else
  {
    for (argument = 0; argument < argc; argument++)
    {
      int module = module_index (argv[argument]);

      if (module >= 0)
      {
        failed += nst_run (s_modules[module].suite, verbose);
      }
    }
  }
  (void) fprintf (stdout, "selftest: %s\n",
          (failed == 0) ? "all passed" : "FAILURES");
  return (failed == 0) ? 0 : 1;
}

static int
cmd_version (void)
{
  (void) fprintf (stdout, "%s %s\n", NGFW_PRODUCT, NGFW_VERSION);
  return 0;
}

int
main (int argc, char **argv)
{
  if (argc >= 2 && strcmp (argv[1], "selftest") == 0)
  {
    return run_selftest (argc - 2, argv + 2);
  }
  if (argc == 2
    && (strcmp (argv[1], "--version") == 0 || strcmp (argv[1], "version") == 0))
  {
    return cmd_version ();
  }
  (void) fprintf (stderr,
          "usage: ngfw selftest [-v] [platform|core|version|all]\n"
          "       ngfw --version\n");
  return 2;
}
