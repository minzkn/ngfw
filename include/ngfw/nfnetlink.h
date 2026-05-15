#ifndef NGFW_NFNETLINK_H
#define NGFW_NFNETLINK_H

#include "types.h"

/* Opaque nfnetlink context */
typedef struct nfnetlink nfnetlink_t;

/* Create/destroy nfnetlink context */
nfnetlink_t *nfnetlink_create(void);
void nfnetlink_destroy(nfnetlink_t *nl);
bool nfnetlink_is_available(nfnetlink_t *nl);

/* Queue operations (userspace packet processing) */
ngfw_ret_t nfnetlink_queue_create(nfnetlink_t *nl, u16 queue_num, u32 queue_maxlen);
ngfw_ret_t nfnetlink_queue_destroy(nfnetlink_t *nl, u16 queue_num);
ngfw_ret_t nfnetlink_queue_set_mode(nfnetlink_t *nl, u16 queue_num, u8 mode, u32 range);
ngfw_ret_t nfnetlink_verdict(nfnetlink_t *nl, u32 id, u32 queue_num, int verdict);

/* nftables operations */
ngfw_ret_t nfnetlink_nft_table_create(nfnetlink_t *nl, const char *name);
ngfw_ret_t nfnetlink_nft_table_delete(nfnetlink_t *nl, const char *name);
ngfw_ret_t nfnetlink_nft_chain_create(nfnetlink_t *nl, const char *table, const char *chain, const char *type);
ngfw_ret_t nfnetlink_nft_rule_add(nfnetlink_t *nl, const char *table, const char *chain,
                                   u32 family, u32 handle, void *expr, u32 expr_len);

/* Connection tracking operations */
ngfw_ret_t nfnetlink_ct_flush(nfnetlink_t *nl);
ngfw_ret_t nfnetlink_ct_dump(nfnetlink_t *nl, char *buf, size_t buf_len, u32 *count);

#endif
