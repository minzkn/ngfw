/*
 * ngfw - configuration tree contract (L1 core).
 *
 * The configuration document format is JSON (RFC 8259) per ADR-006 in
 * designs/00-principles.md. The parser is strict: trailing garbage, leading
 * zeros in numbers, control characters in strings and lone surrogate escapes
 * are rejected. Input text must be valid UTF-8; the tree stores it verbatim.
 */
#ifndef NGFW_CONFIG_H
#define NGFW_CONFIG_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum nfc_cfg_type
{
  NFC_CFG_NULL = 0,
  NFC_CFG_BOOL,
  NFC_CFG_INT,
  NFC_CFG_REAL,
  NFC_CFG_STRING,
  NFC_CFG_ARRAY,
  NFC_CFG_OBJECT
};

struct nfc_cfg;

/* Parses text[0..length) into a tree. Returns 0 and sets *out_root on
 * success; returns -1 on any syntax error (the caller owns *out_root). */
int nfc_cfg_parse (const char *text, size_t length, struct nfc_cfg **out_root);

void nfc_cfg_free (struct nfc_cfg *root);

/* Path lookup: dot-separated object keys with array indexing in brackets,
 * for example "policy.rules[2].action". "" returns the root. Returns 0 and
 * sets *out_node when the path resolves. */
int nfc_cfg_lookup (const struct nfc_cfg *root, const char *path,
        struct nfc_cfg **out_node);

/* Typed accessors return 0 on success and -1 on a type or range mismatch. */
int nfc_cfg_get_bool (const struct nfc_cfg *node, int *out_value);
int nfc_cfg_get_int64 (const struct nfc_cfg *node, int64_t *out_value);
int nfc_cfg_get_real (const struct nfc_cfg *node, double *out_value);
int nfc_cfg_get_string (const struct nfc_cfg *node, const char **out_text);

/* The returned pointer stays valid until the owning tree is freed.
 * A NULL node reports NFC_CFG_NULL. */
const char *nfc_cfg_type_name (enum nfc_cfg_type type);

/* Type query for an opaque node. */
enum nfc_cfg_type nfc_cfg_type (const struct nfc_cfg *node);

/* Array accessors. Indexing out of range returns -1. */
size_t nfc_cfg_array_count (const struct nfc_cfg *node);
int nfc_cfg_array_get (const struct nfc_cfg *node, size_t index,
           struct nfc_cfg **out_item);

/* Object accessors. Duplicate keys are legal in the input; the first
 * occurrence wins for lookup. */
size_t nfc_cfg_object_count (const struct nfc_cfg *node);
int nfc_cfg_object_get (const struct nfc_cfg *node, const char *key,
      struct nfc_cfg **out_item);

#ifdef __cplusplus
}
#endif

#endif /* NGFW_CONFIG_H */
