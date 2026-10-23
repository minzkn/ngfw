/*
 * ngfw - structured logging contract (L1 core).
 *
 * Sinks are extensible in later milestones (designs/12-observability.md);
 * M0 writes to stderr. Callers never format timestamps or levels themselves.
 */
#ifndef NGFW_LOG_H
#define NGFW_LOG_H 1

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum nfc_log_level
{
  NFC_LOG_DEBUG = 0,
  NFC_LOG_INFO = 1,
  NFC_LOG_WARN = 2,
  NFC_LOG_ERROR = 3
};

/* Installs the minimum level and prepares the sink. Idempotent; returns 0 on
 * success. Writes below the minimum level are dropped. */
int nfc_log_init (enum nfc_log_level min_level);

/* Emits one line: "<epoch-seconds.millis> LEVEL [module] message".
 * module and format must not be NULL. Safe to call before init (defaults to
 * INFO minimum). */
void nfc_log_write (enum nfc_log_level level, const char *module,
        const char *format, ...);

/* Flushes the sink (no-op sinks return immediately). */
void nfc_log_flush (void);

#ifdef __cplusplus
}
#endif

#endif /* NGFW_LOG_H */
