#ifndef NGFW_PATMATCH_H
#define NGFW_PATMATCH_H

#include "types.h"

/* Pattern matching engine types */
#define PATMATCH_EXACT  0   /* Exact substring match (Boyer-Moore-Horspool) */
#define PATMATCH_WILDCARD 1 /* Wildcard: '*' = any sequence, '?' = single char */
#define PATMATCH_REGEX  2   /* Simple regex (placeholder for future PCRE) */

/* Pattern matching context for fast searching */
typedef struct patmatch_ctx {
    const u8 *pattern;      /* Owned copy of the pattern */
    u32 pattern_len;
    u32 type;
    u32 shift_table[256];   /* BMH bad-character shift table */
    bool ignore_case;
} patmatch_ctx_t;

/* Precompile a pattern for fast matching. Returns NULL on failure. */
patmatch_ctx_t *patmatch_compile(const u8 *pattern, u32 len, u32 type, bool ignore_case);

/* Free a compiled pattern context */
void patmatch_destroy(patmatch_ctx_t *ctx);

/* Search for the pattern in 'data' of length 'data_len'.
 * Returns the offset of the first match, or -1 if not found.
 * Uses BMH for exact patterns and fallback for wildcards. */
int patmatch_find(patmatch_ctx_t *ctx, const u8 *data, u32 data_len);

/* Check if the entire 'data' matches the pattern (anchored match).
 * Returns true if data starts and ends within pattern. */
bool patmatch_match(patmatch_ctx_t *ctx, const u8 *data, u32 data_len);

#endif
