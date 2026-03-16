#ifndef NGFW_HWACCEL_H
#define NGFW_HWACCEL_H

#include "types.h"

#define HWACCEL_MAX_DEVICES 32
#define HWACCEL_MAX_QUEUES 16

typedef enum {
    HWACCEL_TYPE_NONE,
    HWACCEL_TYPE_INTEL_AES_NI,
    HWACCEL_TYPE_ARM_CE,
    HWACCEL_TYPE_NIAGARA,
    HWACCEL_TYPE_CRYPTO,
    HWACCEL_TYPE_RSS,
    HWACCEL_TYPE_FLOW_DIRECTOR,
    HWACCEL_TYPE_TSO,
    HWACCEL_TYPE_GSO,
    HWACCEL_TYPE_CSUM,
    HWACCEL_TYPE_VXLAN,
    HWACCEL_TYPE_GRE
} hwaccel_type_t;

typedef enum {
    OFFLOAD_NONE,
    OFFLOAD_RX,
    OFFLOAD_TX,
    OFFLOAD_BOTH
} offload_direction_t;

typedef struct hwaccel_capability {
    hwaccel_type_t type;
    char name[64];
    char vendor[64];
    bool supported;
    bool enabled;
    u32 flags;
} hwaccel_capability_t;

typedef struct hwaccel_device {
    char name[32];
    char driver[32];
    hwaccel_capability_t capabilities[16];
    u16 num_capabilities;
    u16 num_queues;
    bool is_default;
} hwaccel_device_t;

typedef struct hwaccel hwaccel_t;

typedef void (*hwaccel_crypto_callback_t)(void *result, void *user_data);

hwaccel_t *hwaccel_create(void);
void hwaccel_destroy(hwaccel_t *hw);

ngfw_ret_t hwaccel_init(hwaccel_t *hw);
ngfw_ret_t hwaccel_shutdown(hwaccel_t *hw);

int hwaccel_get_device_count(hwaccel_t *hw);
hwaccel_device_t *hwaccel_get_device(hwaccel_t *hw, int index);

bool hwaccel_crypto_available(hwaccel_t *hw);
bool hwaccel_crypto_aes_available(hwaccel_t *hw);
bool hwaccel_crypto_sha_available(hwaccel_t *hw);

ngfw_ret_t hwaccel_crypto_aes_encrypt(hwaccel_t *hw, const u8 *key, const u8 *iv,
                                       const u8 *src, u8 *dst, u32 len);
ngfw_ret_t hwaccel_crypto_aes_decrypt(hwaccel_t *hw, const u8 *key, const u8 *iv,
                                       const u8 *src, u8 *dst, u32 len);

bool hwaccel_offload_available(hwaccel_t *hw, hwaccel_type_t type);

ngfw_ret_t hwaccel_set_offload(hwaccel_t *hw, const char *iface, hwaccel_type_t type, bool enable);

ngfw_ret_t hwaccel_enable_rss(hwaccel_t *hw, const char *iface, u16 num_queues);
ngfw_ret_t hwaccel_disable_rss(hwaccel_t *hw, const char *iface);

ngfw_ret_t hwaccel_configure_flow_director(hwaccel_t *hw, const char *iface,
                                            u32 src_ip, u32 dst_ip,
                                            u16 src_port, u16 dst_port,
                                            u8 proto, u16 queue);

ngfw_ret_t hwaccel_get_stats(hwaccel_t *hw, const char *iface,
                              u64 *packets_processed, u64 *bytes_processed);

typedef struct {
    hwaccel_type_t type;
    char name[64];
    bool available;
    u32 features;
} hwaccel_info_t;

int hwaccel_detect(hwaccel_info_t *info, int max_info);

#endif
