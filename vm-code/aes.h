#ifndef AES_H
#define AES_H

#include "util.h"

extern "C" {
#include "tiny-aes/tiny-aes.h"
}

static void _encAesEcb(const u8 *input, u8 *output, size_t inputSize, const u8 *key, u16 keyLen) {
	const size_t keyLenAsSizeT { static_cast<size_t>(keyLen) };
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);
	memcpy(output, input, inputSize);
	for (size_t i = 0; i < inputSize; i += keyLenAsSizeT) {
		AES_ECB_encrypt(&ctx, &output[i]);
	}
}

#endif
