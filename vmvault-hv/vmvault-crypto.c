// Copyright (C) 2021 Martin Radev
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "vmvault-crypto.h"
#include "vmvault.h"
#include "vmvault-debug.h"

#include <crypto/aes.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/internal/skcipher.h>

#define INVALID_KEY_ID ((uint16_t)-1)

struct vmvault_crypto_tfm_ctx {
	unsigned int key_length;
	uint16_t key_id;
};

static int vmvault_skcipher_init(struct crypto_skcipher *tfm) {
	struct vmvault_crypto_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	ctx->key_id = INVALID_KEY_ID;
	return 0;
}

static void vmvault_skcipher_exit(struct crypto_skcipher *tfm) {
	struct vmvault_crypto_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	VmVaultReturnResult ret;
	if (ctx->key_id != INVALID_KEY_ID) {
		ret = removeContext(ctx->key_id);
		if (ret != VmVaultReturnResult_Ok) {
			printk("vmvault: Return value was unexpected: %x\n", ret);
		}
	}
}

static int vmvault_skcipher_setkey(struct crypto_skcipher *tfm,
	const uint8_t *key,
	unsigned int keylen) {
	VmVaultReturnResult ret;
	uint16_t context_id;
	struct vmvault_crypto_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);

	ret = registerContext(slow_virt_to_phys((void *)key), keylen, 0, 0, &context_id);
	if (ret != VmVaultReturnResult_Ok) {
		vmvault_log_msg("Failed to register key\n");
		return -ENOMEM;
	}

	ctx->key_id = context_id;
	ctx->key_length = keylen;

	return 0;
}

static inline void vmvault_get_next_sg_entry(struct scatterlist **sg, dma_addr_t *next_addr, unsigned int *remaining_length, int *current_index, int sg_nents, unsigned int data_size) {
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

static int vmvault_skcipher_perform_operation(struct skcipher_request *req, bool is_encrypt, VmVaultCipher cipher_type) {
	struct crypto_skcipher *atfm = crypto_skcipher_reqtfm(req);
	struct vmvault_crypto_tfm_ctx *ctx = crypto_skcipher_ctx(atfm);
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
	unsigned int ivlen = crypto_skcipher_ivsize(atfm);
	u64 iv;
	VmVaultReturnResult ret;
	VmVaultSgList sgList;
	clearSgList(&sgList);

	iv = (ivlen != 0) ? slow_virt_to_phys(req->iv) : 0;

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
				vmvault_log_msg("Incompatible size and key length: %u %u\n", data_size, key_length);
				BUG();
			}

			if (!addSgListEntry(&sgList, src_phys_addr, dst_phys_addr, data_size)) {
				return -EFAULT;
			}

			if (isSgListFull(&sgList)) {
				if (is_encrypt) {
					ret = encryptDataWithIv(ctx->key_id, cipher_type, &sgList, iv, ivlen);
				} else {
					ret = decryptDataWithIv(ctx->key_id, cipher_type, &sgList, iv, ivlen);
				}
				if (ret != VmVaultReturnResult_Ok) {
					return -EFAULT;
				}
				clearSgList(&sgList);

				// Only the first request needs to set the iv.
				iv = 0;
				ivlen = 0;
			}

			vmvault_get_next_sg_entry(&sg_src, &src_phys_addr, &src_remaining_length, &src_i, src_nents, data_size);

			vmvault_get_next_sg_entry(&sg_dst, &dst_phys_addr, &dst_remaining_length, &dst_i, dst_nents, data_size);

			if ((src_i + 1 == src_nents && dst_i + 1 == dst_nents) &&
				(src_remaining_length == 0 && dst_remaining_length == 0)) {
				break;
			}
		} while (1);

		// Handle remaining.
		if (!isSgListEmpty(&sgList)) {
			if (is_encrypt) {
				ret = encryptDataWithIv(ctx->key_id, cipher_type, &sgList, iv, ivlen);
			} else {
				ret = decryptDataWithIv(ctx->key_id, cipher_type, &sgList, iv, ivlen);
			}
			if (ret != VmVaultReturnResult_Ok) {
				return -EFAULT;
			}
		}
	}

	return 0;
}

static int vmvault_skcipher_decrypt_aes_ecb(struct skcipher_request *req) {
	return vmvault_skcipher_perform_operation(req, false, VmVaultCipher_AesEcb);
}

static int vmvault_skcipher_encrypt_aes_ecb(struct skcipher_request *req) {
	return vmvault_skcipher_perform_operation(req, true, VmVaultCipher_AesEcb);
}

static int vmvault_skcipher_decrypt_aes_cbc(struct skcipher_request *req) {
	return vmvault_skcipher_perform_operation(req, false, VmVaultCipher_AesCbc);
}

static int vmvault_skcipher_encrypt_aes_cbc(struct skcipher_request *req) {
	return vmvault_skcipher_perform_operation(req, true, VmVaultCipher_AesCbc);
}

static struct skcipher_alg supported_algos[] =
{
	{
		.base.cra_name      = "ecb(aes)",
		.base.cra_driver_name  = "vmvault_ecb_aes",
		.base.cra_priority  = 1450,
		.base.cra_flags     = CRYPTO_ALG_ASYNC,
		.base.cra_blocksize = AES_BLOCK_SIZE,
		.base.cra_ctxsize   = sizeof(struct vmvault_crypto_tfm_ctx),
		.base.cra_module    = THIS_MODULE,
		.init           = vmvault_skcipher_init,
		.exit           = vmvault_skcipher_exit,
		.setkey         = vmvault_skcipher_setkey,
		.decrypt        = vmvault_skcipher_decrypt_aes_ecb,
		.encrypt        = vmvault_skcipher_encrypt_aes_ecb,
		.min_keysize    = AES_MIN_KEY_SIZE,
		.max_keysize    = 16,
		.ivsize         = AES_BLOCK_SIZE,
	},
	{
		.base.cra_name      = "cbc(aes)",
		.base.cra_driver_name  = "vmvault_cbc_aes",
		.base.cra_priority  = 1450,
		.base.cra_flags     = CRYPTO_ALG_ASYNC,
		.base.cra_blocksize = AES_BLOCK_SIZE,
		.base.cra_ctxsize   = sizeof(struct vmvault_crypto_tfm_ctx),
		.base.cra_module    = THIS_MODULE,
		.init           = vmvault_skcipher_init,
		.exit           = vmvault_skcipher_exit,
		.setkey         = vmvault_skcipher_setkey,
		.decrypt        = vmvault_skcipher_decrypt_aes_cbc,
		.encrypt        = vmvault_skcipher_encrypt_aes_cbc,
		.min_keysize    = AES_MIN_KEY_SIZE,
		.max_keysize    = 16,
		.ivsize         = AES_BLOCK_SIZE,
	},
};


int vmvault_register_cipher(void) {
	int ret;
	size_t cipher_i;

	for (cipher_i = 0; cipher_i < sizeof(supported_algos) / sizeof(supported_algos[0]); ++cipher_i) {
		ret = crypto_register_skcipher(&supported_algos[cipher_i]);
		if (ret) {
			return ret;
		}
	}

	return 0;
}

void vmvault_deregister_cipher(void) {
	size_t cipher_i;

	for (cipher_i = 0; cipher_i < sizeof(supported_algos) / sizeof(supported_algos[0]); ++cipher_i) {
		crypto_unregister_skcipher(&supported_algos[cipher_i]);
	}
}
