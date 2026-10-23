/* ngfw - core selftest suite (F15). Exercises log, evloop and config tree. */
#include <string.h>

#include <ngfw/config.h>
#include <ngfw/evloop.h>
#include <ngfw/log.h>
#include <ngfw/platform.h>
#include <ngfw/selftest.h>

struct evpipe_context
{
  int hit;
};

static void
on_pipe_ready (void *user_data, int fd, uint32_t events)
{
  struct evpipe_context *context = (struct evpipe_context *) user_data;
  char byte;

  /* Consume the pending byte: epoll readiness is level-triggered, so the
   * descriptor stays readable until the data is drained. */
  if (npx_fd_read (fd, &byte, 1) != 1)
  {
    context->hit = 0;
    return;
  }
  context->hit = ((events & NPX_EV_IN) != 0u) ? 1 : 0;
}

static int
case_log_write (void)
{
  NST_CHECK (nfc_log_init (NFC_LOG_ERROR) == 0);
  nfc_log_write (NFC_LOG_INFO, "selftest", "suppressed %d", 1);
  nfc_log_write (NFC_LOG_ERROR, "selftest", "emitted %d", 1);
  nfc_log_flush ();
  return 0;
}

static int
case_evloop_pipe (void)
{
  struct nfc_evloop *evloop = NULL;
  struct evpipe_context context = { 0 };
  int fds[2] = { -1, -1 };

  NST_CHECK (nfc_evloop_create (&evloop) == 0);
  NST_CHECK (npx_pipe (fds) == 0);
  NST_CHECK (nfc_evloop_add (evloop, fds[0], NPX_EV_IN, on_pipe_ready,
               &context) == 0);
  NST_CHECK_EQ_INT (npx_fd_write (fds[1], "y", 1), 1);
  NST_CHECK_EQ_INT (nfc_evloop_run (evloop, 200), 1);
  NST_CHECK_EQ_INT (context.hit, 1);
  /* No new data: the next pass must time out without dispatching. */
  NST_CHECK_EQ_INT (nfc_evloop_run (evloop, 20), 0);
  NST_CHECK (nfc_evloop_del (evloop, fds[0]) == 0);
  NST_CHECK (npx_fd_close (fds[0]) == 0);
  NST_CHECK (npx_fd_close (fds[1]) == 0);
  nfc_evloop_destroy (evloop);
  return 0;
}

static int
case_config_basic (void)
{
  static const char document[] =
  "{\"a\":1,\"b\":[true,null,\"x\"],\"c\":{\"d\":2.5}}";
  struct nfc_cfg *root = NULL;
  struct nfc_cfg *node = NULL;
  int64_t int_value = 0;
  int bool_value = 0;
  double real_value = 0.0;
  const char *text_value = NULL;

  NST_CHECK (nfc_cfg_parse (document, sizeof (document) - 1, &root) == 0);
  NST_CHECK (nfc_cfg_lookup (root, "a", &node) == 0);
  NST_CHECK (nfc_cfg_get_int64 (node, &int_value) == 0);
  NST_CHECK_EQ_INT (int_value, 1);
  NST_CHECK (nfc_cfg_lookup (root, "b[0]", &node) == 0);
  NST_CHECK (nfc_cfg_get_bool (node, &bool_value) == 0);
  NST_CHECK_EQ_INT (bool_value, 1);
  NST_CHECK (nfc_cfg_lookup (root, "b[1]", &node) == 0);
  NST_CHECK (strcmp (nfc_cfg_type_name (nfc_cfg_type (node)), "null") == 0);
  NST_CHECK (nfc_cfg_lookup (root, "b[2]", &node) == 0);
  NST_CHECK (nfc_cfg_get_string (node, &text_value) == 0);
  NST_CHECK (strcmp (text_value, "x") == 0);
  NST_CHECK_EQ_INT ((int) nfc_cfg_array_count (root), 0); /* root is object */
  NST_CHECK (nfc_cfg_lookup (root, "b", &node) == 0);
  NST_CHECK_EQ_INT ((int) nfc_cfg_array_count (node), 3);
  NST_CHECK (nfc_cfg_lookup (root, "c.d", &node) == 0);
  NST_CHECK (nfc_cfg_get_real (node, &real_value) == 0);
  NST_CHECK (real_value == 2.5);
  NST_CHECK (nfc_cfg_lookup (root, "missing", &node) != 0);
  nfc_cfg_free (root);
  return 0;
}

static int
case_config_escapes (void)
{
  static const char document[] = "{\"s\":\"a\\u00e9\\t\\\"q\\\"\"}";
  static const char expected[] = { 'a', (char) 0xC3, (char) 0xA9, '\t',
                   '"', 'q', '"' };
  struct nfc_cfg *root = NULL;
  struct nfc_cfg *node = NULL;
  const char *text_value = NULL;

  NST_CHECK (nfc_cfg_parse (document, sizeof (document) - 1, &root) == 0);
  NST_CHECK (nfc_cfg_lookup (root, "s", &node) == 0);
  NST_CHECK (nfc_cfg_get_string (node, &text_value) == 0);
  NST_CHECK_EQ_INT ((int) strlen (text_value), (int) sizeof (expected));
  NST_CHECK (memcmp (text_value, expected, sizeof (expected)) == 0);
  nfc_cfg_free (root);
  return 0;
}

static int
rejects (const char *document)
{
  struct nfc_cfg *root = NULL;

  return (nfc_cfg_parse (document, strlen (document), &root) != 0
      && root == NULL) ? 0 : -1;
}

static int
case_config_rejects (void)
{
  char *deep;
  int index;

  NST_CHECK_EQ_INT (rejects ("{"), 0);
  NST_CHECK_EQ_INT (rejects ("[1,]"), 0);
  NST_CHECK_EQ_INT (rejects ("\"abc"), 0);
  NST_CHECK_EQ_INT (rejects ("{\"a\":01}"), 0);
  NST_CHECK_EQ_INT (rejects ("{\"a\":1} trailing"), 0);
  NST_CHECK_EQ_INT (rejects ("{\"a\"}"), 0);
  NST_CHECK_EQ_INT (rejects ("[\"\\uD800\"]"), 0);   /* lone high surrogate */
  NST_CHECK_EQ_INT (rejects ("[\"\\u0000\"]"), 0);   /* embedded NUL */
  NST_CHECK_EQ_INT (rejects ("[1 2]"), 0);          /* missing comma */
  NST_CHECK_EQ_INT (rejects ("tru"), 0);
  NST_CHECK_EQ_INT (rejects ("nul"), 0);
  NST_CHECK_EQ_INT (rejects ("+1"), 0);
  /* Nesting beyond the depth limit must fail without crashing. */
  deep = (char *) npx_malloc (2 * 100 + 1);
  NST_CHECK (deep != NULL);
  for (index = 0; index < 100; index++)
  {
    deep[index] = '[';
    deep[200 - index] = ']';
  }
  deep[100] = '\0';
  NST_CHECK_EQ_INT (rejects (deep), 0);
  npx_free (deep);
  return 0;
}

static int
case_config_lookup_empty (void)
{
  static const char document[] = "{}";
  struct nfc_cfg *root = NULL;
  struct nfc_cfg *node = NULL;

  NST_CHECK (nfc_cfg_parse (document, sizeof (document) - 1, &root) == 0);
  /* An empty path resolves to the root. */
  NST_CHECK (nfc_cfg_lookup (root, "", &node) == 0);
  NST_CHECK (node == root);
  nfc_cfg_free (root);
  return 0;
}

static const struct nst_case s_cases[] = {
  NST_CASE ("log-write", case_log_write),
  NST_CASE ("evloop-pipe", case_evloop_pipe),
  NST_CASE ("config-basic", case_config_basic),
  NST_CASE ("config-escapes", case_config_escapes),
  NST_CASE ("config-rejects", case_config_rejects),
  NST_CASE ("config-lookup-empty", case_config_lookup_empty),
};

const struct nst_suite nst_core_suite = NST_SUITE ("core", s_cases);
