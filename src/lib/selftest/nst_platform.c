/* ngfw - platform selftest suite (F15). Exercises the L0 contract surface. */
#include <errno.h>
#include <string.h>

#include <ngfw/platform.h>
#include <ngfw/selftest.h>

static int
case_mem_alloc (void)
{
  void *ptr = npx_malloc (100);

  NST_CHECK (ptr != NULL);
  memset (ptr, 0xAB, 100);
  npx_free (ptr);
  return 0;
}

static int
case_calloc_zero (void)
{
  unsigned char *ptr = (unsigned char *) npx_calloc (4, 8);
  int index;

  NST_CHECK (ptr != NULL);
  for (index = 0; index < 32; index++)
  {
    NST_CHECK_EQ_INT (ptr[index], 0);
  }
  npx_free (ptr);
  return 0;
}

static int
case_realloc_grow (void)
{
  char *ptr = (char *) npx_malloc (4);

  NST_CHECK (ptr != NULL);
  memcpy (ptr, "abcd", 4);
  ptr = (char *) npx_realloc (ptr, 8);
  NST_CHECK (ptr != NULL);
  NST_CHECK (memcmp (ptr, "abcd", 4) == 0);
  npx_free (ptr);
  return 0;
}

static int
case_strdup_copy (void)
{
  char *copy = npx_strdup ("ngfw");

  NST_CHECK (copy != NULL);
  NST_CHECK (copy != (char *) "ngfw");
  NST_CHECK (strcmp (copy, "ngfw") == 0);
  npx_free (copy);
  NST_CHECK (npx_strdup (NULL) == NULL);
  return 0;
}

static int
case_time_order (void)
{
  int64_t monotonic_first = npx_monotonic_ns ();
  int64_t monotonic_second = npx_monotonic_ns ();
  int64_t realtime = npx_realtime_ns ();

  NST_CHECK (monotonic_first >= 0);
  NST_CHECK (monotonic_second >= monotonic_first);
  /* 1000000000000000 ns corresponds to 2001-09; sane lower bound. */
  NST_CHECK (realtime > 1000000000000000LL);
  return 0;
}

static int
case_strerror_text (void)
{
  const char *unknown = npx_strerror (9999999);
  const char *invalid = npx_strerror (EINVAL);

  NST_CHECK (unknown != NULL);
  NST_CHECK (invalid != NULL);
  NST_CHECK (invalid[0] != '\0');
  return 0;
}

static int
case_mutex_lock (void)
{
  struct npx_mutex *mutex = NULL;

  NST_CHECK (npx_mutex_init (&mutex) == 0);
  npx_mutex_lock (mutex);
  npx_mutex_unlock (mutex);
  npx_mutex_fini (mutex);
  return 0;
}

static int
case_poll_signal (void)
{
  struct npx_poll *poll = NULL;
  int fds[2] = { -1, -1 };
  struct npx_poll_event events[4];

  NST_CHECK (npx_poll_create (&poll) == 0);
  NST_CHECK (npx_pipe (fds) == 0);
  NST_CHECK (npx_poll_add (poll, fds[0], NPX_EV_IN) == 0);
  NST_CHECK_EQ_INT (npx_fd_write (fds[1], "x", 1), 1);
  NST_CHECK_EQ_INT (npx_poll_wait (poll, events, 4, 100), 1);
  NST_CHECK_EQ_INT (events[0].fd, fds[0]);
  NST_CHECK ((events[0].events & NPX_EV_IN) != 0u);
  NST_CHECK (npx_poll_del (poll, fds[0]) == 0);
  NST_CHECK (npx_fd_close (fds[0]) == 0);
  NST_CHECK (npx_fd_close (fds[1]) == 0);
  npx_poll_close (poll);
  return 0;
}

static int
case_poll_timeout (void)
{
  struct npx_poll *poll = NULL;
  int fds[2] = { -1, -1 };
  struct npx_poll_event events[4];

  NST_CHECK (npx_poll_create (&poll) == 0);
  NST_CHECK (npx_pipe (fds) == 0);
  NST_CHECK (npx_poll_add (poll, fds[0], NPX_EV_IN) == 0);
  NST_CHECK_EQ_INT (npx_poll_wait (poll, events, 4, 20), 0);
  NST_CHECK (npx_fd_close (fds[0]) == 0);
  NST_CHECK (npx_fd_close (fds[1]) == 0);
  npx_poll_close (poll);
  return 0;
}

static const struct nst_case s_cases[] = {
  NST_CASE ("mem-alloc", case_mem_alloc),
  NST_CASE ("calloc-zero", case_calloc_zero),
  NST_CASE ("realloc-grow", case_realloc_grow),
  NST_CASE ("strdup-copy", case_strdup_copy),
  NST_CASE ("time-order", case_time_order),
  NST_CASE ("strerror-text", case_strerror_text),
  NST_CASE ("mutex-lock", case_mutex_lock),
  NST_CASE ("poll-signal", case_poll_signal),
  NST_CASE ("poll-timeout", case_poll_timeout),
};

const struct nst_suite nst_platform_suite = NST_SUITE ("platform", s_cases);
