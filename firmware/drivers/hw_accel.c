/*
 * NGFW Hardware Acceleration Driver
 * Intel AES-NI, ARM CE, Crypto API support
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/cryptohw.h>
#include <linux/hw_random.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>

#define HWACCEL_NAME "ngfw-hw"
#define HWACCEL_VERSION "2.0.0"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NGFW Team");
MODULE_DESCRIPTION("Hardware Acceleration for NGFW");
MODULE_VERSION(HWACCEL_VERSION);

struct hw_accel_dev {
    struct device *dev;
    bool aesni_present;
    bool avx_present;
    bool armv8_crypto_present;
    bool rdrand_present;
    bool padlock_present;
    
    u32 capabilities;
    u64 stats.aes_ops;
    u64 stats.sha_ops;
    u64 stats.rng_bytes;
    spinlock_t lock;
};

static struct hw_accel_dev *hw_dev;

static int __init hw_accel_init(void)
{
    struct device *dev;
    int ret;

    pr_info("NGFW HW Accel: Initializing hardware acceleration\n");

    hw_dev = kzalloc(sizeof(struct hw_accel_dev), GFP_KERNEL);
    if (!hw_dev)
        return -ENOMEM;

    spin_lock_init(&hw_dev->lock);

#ifdef CONFIG_CRYPTO_AES_ARM64_CE
    hw_dev->armv8_crypto_present = true;
    hw_dev->capabilities |= HW_CAP_AES | HW_CAP_GCM | HW_CAP_CCM;
    pr_info("NGFW HW Accel: ARMv8 crypto detected\n");
#endif

#ifdef CONFIG_CRYPTO_AES_NI
    hw_dev->aesni_present = true;
    hw_dev->capabilities |= HW_CAP_AES | HW_CAP_AES_XTS;
    pr_info("NGFW HW Accel: Intel AES-NI detected\n");
#endif

#ifdef CONFIG_RANDOM_INTEL
    hw_dev->rdrand_present = true;
    hw_dev->capabilities |= HW_CAP_RNG;
    pr_info("NGFW HW Accel: Intel RDRAND detected\n");
#endif

#ifdef CONFIG_CRYPTO_DEV_PADLOCK
    hw_dev->padlock_present = true;
    hw_dev->capabilities |= HW_CAP_AES | HW_CAP_SHA;
    pr_info("NGFW HW Accel: VIA Padlock detected\n");
#endif

    ret = crypto_register_alg(&hw_aes_alg);
    if (ret) {
        pr_err("NGFW HW Accel: failed to register AES: %d\n", ret);
        goto err_aes;
    }

    ret = crypto_register_alg(&hw_sha_alg);
    if (ret) {
        pr_err("NGFW HW Accel: failed to register SHA: %d\n", ret);
        goto err_sha;
    }

    ret = hw_rng_register(dev);
    if (ret) {
        pr_warn("NGFW HW Accel: RNG registration failed: %d\n", ret);
    }

    pr_info("NGFW HW Accel: Hardware acceleration initialized\n");
    return 0;

err_aes:
    crypto_unregister_alg(&hw_aes_alg);
err_sha:
    crypto_unregister_alg(&hw_sha_alg);
    kfree(hw_dev);
    return ret;
}

static void __exit hw_accel_exit(void)
{
    crypto_unregister_alg(&hw_aes_alg);
    crypto_unregister_alg(&hw_sha_alg);
    hw_rng_unregister();
    kfree(hw_dev);
    pr_info("NGFW HW Accel: Module unloaded\n");
}

static int hw_aes_setkey(struct crypto_ablkcipher *tfm, const u8 *key, unsigned int keylen)
{
    struct hw_ctx *ctx = crypto_ablkcipher_ctx(tfm);
    memcpy(ctx->key, key, keylen);
    ctx->keylen = keylen;
    return 0;
}

static int hw_aes_encrypt(struct ablkcipher_request *req)
{
    struct hw_ctx *ctx = crypto_ablkcipher_ctx(req->base.tfm);
    
    if (hw_dev->capabilities & HW_CAP_AES) {
        if (hw_dev->armv8_crypto_present) {
            return armv8_crypto_encrypt(req, ctx->key, ctx->keylen);
        } else if (hw_dev->aesni_present) {
            return aesni_encrypt(req, ctx->key, ctx->keylen);
        }
    }
    
    return -ENOSYS;
}

module_init(hw_accel_init);
module_exit(hw_accel_exit);