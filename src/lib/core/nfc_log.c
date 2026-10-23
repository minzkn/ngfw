/* ngfw - structured logging (L1 core). M0 writes to stderr; the event bus
 * wiring in designs/12-observability.md replaces the transport later without
 * changing this contract. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <ngfw/log.h>
#include <ngfw/platform.h>

static struct npx_mutex *s_lock;
static enum nfc_log_level s_min_level = NFC_LOG_INFO;

static const char *
level_name (enum nfc_log_level level)
{
  switch (level)
  {
  case NFC_LOG_DEBUG:
    return "DEBUG";
  case NFC_LOG_INFO:
    return "INFO";
  case NFC_LOG_WARN:
    return "WARN";
  case NFC_LOG_ERROR:
    return "ERROR";
  default:
    break;
  }
  return "LEVEL?";
}

int
nfc_log_init (enum nfc_log_level min_level)
{
  if (s_lock == NULL && npx_mutex_init (&s_lock) != 0)
  {
    return -1;
  }
  s_min_level = min_level;
  return 0;
}

void
nfc_log_write (enum nfc_log_level level, const char *module,
         const char *format, ...)
{
  int64_t now_ns;
  char stamp[32];
  va_list args;
  int locked;

  if (level < s_min_level || module == NULL || format == NULL)
  {
    return;
  }
  now_ns = npx_realtime_ns ();
  if (now_ns < 0)
  {
    stamp[0] = '\0';
  }
  else
  {
    (void) snprintf (stamp, sizeof (stamp), "%lld.%03lld",
             (long long) (now_ns / 1000000000LL),
             (long long) ((now_ns / 1000000LL) % 1000LL));
  }

  locked = (s_lock != NULL);
  if (locked)
  {
    npx_mutex_lock (s_lock);
  }
  (void) fprintf (stderr, "%s %-5s [%s] ", stamp, level_name (level), module);
  va_start (args, format);
  (void) vfprintf (stderr, format, args);
  va_end (args);
  (void) fputc ('\n', stderr);
  if (locked)
  {
    npx_mutex_unlock (s_lock);
  }
}

void
nfc_log_flush (void)
{
  if (s_lock != NULL)
  {
    npx_mutex_lock (s_lock);
  }
  (void) fflush (stderr);
  if (s_lock != NULL)
  {
    npx_mutex_unlock (s_lock);
  }
}
