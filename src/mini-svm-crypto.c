#include "mini-svm-crypto.h"
#include "mini-svm.h"

#include <crypto/aes.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/internal/skcipher.h>

#define INVALID_KEY_ID ((uint16_t)-1)

struct mini_svm_crypto_tfm_ctx {
	unsigned int key_length;
	uint16_t key_id;
};

static int mini_svm_skcipher_init(struct crypto_skcipher *tfm) {
	struct mini_svm_crypto_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	ctx->key_id = INVALID_KEY_ID;
	return 0;
}

static void mini_svm_skcipher_exit(struct crypto_skcipher *tfm) {
	struct mini_svm_crypto_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	MiniSvmReturnResult ret;
	if (ctx->key_id != INVALID_KEY_ID) {
		ret = removeContext(ctx->key_id);
		BUG_ON(ret != MiniSvmReturnResult_Ok);
	}
}

static int mini_svm_skcipher_setkey(struct crypto_skcipher *tfm,
	const uint8_t *key,
	unsigned int keylen) {
	MiniSvmReturnResult ret;
	uint16_t context_id;
	struct mini_svm_crypto_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);

	printk("%x %x %x %x\n", key[0], key[1], key[2], key[3]);

	ret = registerContext(slow_virt_to_phys(key), keylen, NULL, 0, &context_id);
	if (ret != MiniSvmReturnResult_Ok) {
		printk("Failed to register key\n");
		return -ENOMEM;
	}

	ctx->key_id = context_id;
	ctx->key_length = keylen;

	return 0;
}

static inline void mini_svm_get_next_sg_entry(struct scatterlist **sg, dma_addr_t *next_addr, unsigned int *remaining_length, int *current_index, int sg_nents, unsigned int data_size) {
	unsigned int rem = *remaining_length - data_size;
	*remaining_length = rem;
	if (rem == 0 && *current_index + 1 < sg_nents) {
		struct scatterlist *sg_tmp = sg_next(*sg);
		*sg = sg_tmp;
		*next_addr = sg_phys(sg_tmp);
		*remaining_length = sg_tmp->length;
		*current_index += 1;
	}
}

static int mini_svm_skcipher_perform_operation(struct skcipher_request *req, bool is_encrypt, MiniSvmCipher cipher_type) {
	struct crypto_skcipher *atfm = crypto_skcipher_reqtfm(req);
	struct mini_svm_crypto_tfm_ctx *ctx = crypto_skcipher_ctx(atfm);
	struct scatterlist *sg_src, *sg_dst;
	int src_i, dst_i;
	uint16_t key_length = ctx->key_length;
	const int src_nents = sg_nents(req->src);
	const int dst_nents = sg_nents(req->dst);
	unsigned int src_remaining_length = 0;
	unsigned int dst_remaining_length = 0;
	dma_addr_t src_phys_addr = 0;
	dma_addr_t dst_phys_addr = 0;
	unsigned int data_size;
	MiniSvmReturnResult ret;
	MiniSvmSgList sgList;
	clearSgList(&sgList);

	if (src_nents && dst_nents) {
		sg_src = req->src;
		sg_dst = req->dst;
		src_i = 0;
		dst_i = 0;
		src_phys_addr = sg_phys(sg_src);
		dst_phys_addr = sg_phys(sg_dst);
		src_remaining_length = sg_src->length;
		dst_remaining_length = sg_dst->length;
		do {
			data_size = min(src_remaining_length, dst_remaining_length);
			if (data_size % key_length != 0) {
				printk("%u %u\n", data_size, key_length);
				BUG();
			}

			if (!addSgListEntry(&sgList, src_phys_addr, dst_phys_addr, data_size)) {
				return -EFAULT;
			}

			if (isSgListFull(&sgList)) {
				if (is_encrypt) {
					ret = encryptData(ctx->key_id, cipher_type, &sgList);
				} else {
					ret = decryptData(ctx->key_id, cipher_type, &sgList);
				}
				if (ret != MiniSvmReturnResult_Ok) {
					return -EFAULT;
				}
				clearSgList(&sgList);
			}

			mini_svm_get_next_sg_entry(&sg_src, &src_phys_addr, &src_remaining_length, &src_i, src_nents, data_size);

			mini_svm_get_next_sg_entry(&sg_dst, &dst_phys_addr, &dst_remaining_length, &dst_i, dst_nents, data_size);

			if ((src_i + 1 == src_nents && dst_i + 1 == dst_nents) &&
				(src_remaining_length == 0 && dst_remaining_length == 0)) {
				break;
			}
		} while (1);

		// Handle remaining.
		if (!isSgListEmpty(&sgList)) {
			if (is_encrypt) {
				ret = encryptData(ctx->key_id, cipher_type, &sgList);
			} else {
				ret = decryptData(ctx->key_id, cipher_type, &sgList);
			}
			if (ret != MiniSvmReturnResult_Ok) {
				return -EFAULT;
			}
		}
	}

	return 0;
}

static int mini_svm_skcipher_decrypt_aes_ecb(struct skcipher_request *req) {
	return mini_svm_skcipher_perform_operation(req, false, MiniSvmCipher_AesEcb);
}

static int mini_svm_skcipher_encrypt_aes_ecb(struct skcipher_request *req) {
	return mini_svm_skcipher_perform_operation(req, true, MiniSvmCipher_AesEcb);
}

static struct skcipher_alg supported_algo = 
{ 
    .base.cra_name      = "ecb(aes)",
    .base.cra_driver_name  = "sevault_ecb_aes",
    .base.cra_priority  = 1450,
    .base.cra_flags     = CRYPTO_ALG_ASYNC,
    .base.cra_blocksize = AES_BLOCK_SIZE,
    .base.cra_ctxsize   = sizeof(struct mini_svm_crypto_tfm_ctx),
    .base.cra_module    = THIS_MODULE,
    .init           = mini_svm_skcipher_init,
    .exit           = mini_svm_skcipher_exit,
    .setkey         = mini_svm_skcipher_setkey,
    .decrypt        = mini_svm_skcipher_decrypt_aes_ecb,
    .encrypt        = mini_svm_skcipher_encrypt_aes_ecb,
    .min_keysize    = AES_MIN_KEY_SIZE,
    .max_keysize    = AES_MAX_KEY_SIZE,
    .ivsize         = AES_BLOCK_SIZE,
};

int mini_svm_register_cipher(void) {
	int ret;

	ret = crypto_register_skcipher(&supported_algo);
	if (ret) {
		return ret;
	}

	return 0;
}

void mini_svm_deregister_cipher(void) {
	crypto_unregister_skcipher(&supported_algo);
}
